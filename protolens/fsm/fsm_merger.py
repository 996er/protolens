from __future__ import annotations

from typing import Any

from protolens.fsm.fsm_model import Divergence, ProtocolFSM
from protolens.fsm.llm_support import (
    EVIDENCE_SCHEMA,
    FSM_SCHEMA,
    LLMConversationRecorder,
    LLMValidationError,
    fsm_from_llm,
    normalize_fsm_protocol,
    validate_divergences,
    validate_json_schema,
)
from protolens.utils.llm_client import LLMClient


DIVERGENCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["id", "kind", "spec_element", "impl_element", "severity", "rationale", "evidence"],
    "properties": {
        "id": {"type": "string"},
        "kind": {
            "type": "string",
            "enum": [
                "missing_transition", "extra_transition", "guard_mismatch", "state_mismatch",
                "action_mismatch", "error_handling_mismatch",
            ],
        },
        "spec_element": {"type": ["string", "null"]},
        "impl_element": {"type": ["string", "null"]},
        "severity": {"type": "string", "enum": ["P0", "P1", "P2"]},
        "rationale": {"type": "string", "minLength": 1},
        "evidence": {"type": "array", "items": EVIDENCE_SCHEMA, "minItems": 1, "maxItems": 20},
    },
}

TRANSITION_SOURCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["unified_transition_id", "spec_transition_ids", "impl_transition_ids"],
    "properties": {
        "unified_transition_id": {"type": "string", "minLength": 1},
        "spec_transition_ids": {"type": "array", "items": {"type": "string"}},
        "impl_transition_ids": {"type": "array", "items": {"type": "string"}},
    },
}

MERGE_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["unified_fsm", "divergences", "transition_sources", "merge_rationale", "uncertainties"],
    "properties": {
        "unified_fsm": FSM_SCHEMA,
        "divergences": {"type": "array", "items": DIVERGENCE_SCHEMA, "maxItems": 1000},
        "transition_sources": {
            "type": "array",
            "items": TRANSITION_SOURCE_SCHEMA,
            "minItems": 1,
            "maxItems": 1000,
        },
        "merge_rationale": {"type": "string", "minLength": 1},
        "uncertainties": {"type": "array", "items": {"type": "string"}, "maxItems": 100},
    },
}


class FSMMerger:
    """Compare and merge specification/implementation FSMs through the LLM."""

    CACHE_VERSION = "fsm-semantic-merge-v1"

    def __init__(self, llm_client: LLMClient) -> None:
        self.recorder = LLMConversationRecorder("fsm_merge", llm_client)

    def merge(self, spec_fsm: ProtocolFSM, impl_fsm: ProtocolFSM) -> tuple[ProtocolFSM, list[Divergence]]:
        if self.recorder.llm_client.is_offline:
            raise RuntimeError("FSM comparison and merge require an online LLM")
        # Match the model-facing output schema instead of teaching the model
        # the name-indexed state representation used by persisted artifacts.
        spec_payload = spec_fsm.to_dict()
        impl_payload = impl_fsm.to_dict()
        spec_payload["states"] = list(spec_payload["states"].values())
        impl_payload["states"] = list(impl_payload["states"].values())
        payload = {
            "protocol": spec_fsm.protocol,
            "task": "Compare SpecificationFSM and ImplementationFSM, report conflicts, and produce UnifiedFSM.",
            "requirements": [
                "Reason semantically about state aliases, guards, side effects, and error behavior.",
                "Preserve both normative and implementation-only behavior with evidence.",
                "Report every material conflict as a typed divergence with security-aware priority.",
                "Do not silently drop any input transition.",
                "Map every input transition id in transition_sources to its unified transition.",
                "Every transition_sources entry must include spec_transition_ids and impl_transition_ids arrays; use [] only for a side with no supporting input transition.",
                "Never cite evidence absent from the two input FSMs.",
                "Return unified_fsm.states as an array of state objects, each with name, description, evidence and confidence.",
                "Every transition source and target must exactly match a name in unified_fsm.states.",
                "When renaming or merging states, update all transition endpoints and initial/terminal/error state references.",
            ],
            "specification_fsm": spec_payload,
            "implementation_fsm": impl_payload,
        }
        result: tuple[ProtocolFSM, list[Divergence]] | None = None

        def validate_result(data: dict[str, Any]) -> None:
            nonlocal result
            result = self._parse_merge_result(data, spec_fsm, impl_fsm)

        self.recorder.call_chat(
            system=(
                "You are ProtoLens FSM conflict analyst and merger. Compare the two evidence-backed models. "
                "The specification is normative; implementation behavior remains in the unified graph so later "
                "security reasoning can target divergences. Return a complete, auditable merge."
            ),
            payload=payload,
            schema=MERGE_RESULT_SCHEMA,
            schema_name="protolens_fsm_merge",
            validator=validate_result,
            result_normalizer=lambda data: self._repair_transition_source_fields(data, spec_fsm, impl_fsm),
        )
        assert result is not None
        return result

    def _repair_transition_source_fields(
        self, data: dict[str, Any], spec_fsm: ProtocolFSM, impl_fsm: ProtocolFSM,
    ) -> list[dict[str, Any]]:
        mappings = data.get("transition_sources")
        if not isinstance(mappings, list):
            return []
        fields = ("spec_transition_ids", "impl_transition_ids")
        missing = {index: [field for field in fields if field not in mapping]
                   for index, mapping in enumerate(mappings) if isinstance(mapping, dict)
                   and any(field not in mapping for field in fields)}
        if not missing:
            return []
        validate_json_schema(data, MERGE_RESULT_SCHEMA, allow_missing=True)
        if any("unified_transition_id" not in mappings[index] for index in missing):
            return []  # No unambiguous target; let the ordinary schema retry handle it.
        source_schema = {
            "type": "object", "additionalProperties": False,
            "required": ["mapping_index", *fields],
            "properties": {
                "mapping_index": {"type": "integer", "enum": list(missing)},
                "spec_transition_ids": {"type": "array", "items": {
                    "type": "string", "enum": [transition.id for transition in spec_fsm.transitions]}},
                "impl_transition_ids": {"type": "array", "items": {
                    "type": "string", "enum": [transition.id for transition in impl_fsm.transitions]}},
            },
        }
        schema = {
            "type": "object", "additionalProperties": False, "required": ["repairs"],
            "properties": {"repairs": {"type": "array", "items": source_schema,
                                       "minItems": len(missing), "maxItems": len(missing)}},
        }

        def patched(result: dict[str, Any]) -> list[dict[str, Any]]:
            indices = [repair["mapping_index"] for repair in result["repairs"]]
            if len(set(indices)) != len(indices) or set(indices) != set(missing):
                raise ValueError("source mapping repair must cover each incomplete entry exactly once")
            candidate = [dict(mapping) for mapping in mappings]
            for repair in result["repairs"]:
                index = repair["mapping_index"]
                for field in fields:
                    if field not in missing[index] and candidate[index][field] != repair[field]:
                        raise ValueError(f"source mapping repair changed existing transition_sources[{index}].{field}")
                    candidate[index][field] = repair[field]
            return candidate

        def validate_repair(result: dict[str, Any]) -> None:
            self._parse_merge_result({**data, "transition_sources": patched(result)}, spec_fsm, impl_fsm)

        try:
            result = self.recorder.call_chat(
                system="Complete missing source mappings for a fixed merged FSM using only the supplied input transitions.",
                payload={
                    "protocol": spec_fsm.protocol,
                    "missing_fields": [{"mapping_index": index, "fields": fields} for index, fields in missing.items()],
                    "transition_sources": mappings,
                    "unified_fsm": data.get("unified_fsm"),
                    "spec_transitions": spec_fsm.to_dict()["transitions"],
                    "impl_transitions": impl_fsm.to_dict()["transitions"],
                    "requirements": [
                        "Match source transitions using behavior and evidence, never ID spelling alone.",
                        "Fill only missing lists; copy existing lists unchanged. Do not modify the FSM.",
                        "Use [] only when that side has no supporting transition; every merged transition needs a source.",
                        "Across all mappings, preserve coverage of every specification and implementation input transition.",
                    ],
                },
                schema=schema, schema_name="protolens_merge_source_mapping_repair",
                validator=validate_repair,
            )
        except LLMValidationError as exc:
            raise RuntimeError(f"FSM merge source mapping repair failed: {exc}") from exc
        repaired = patched(result)
        changes = [{"path": f"$.transition_sources[{index}].{field}", "value": repaired[index][field],
                    "reason": "missing_transition_sources_repaired"}
                   for index, fields in missing.items() for field in fields]
        data["transition_sources"] = repaired
        return changes

    def _parse_merge_result(
        self, data: dict[str, Any], spec_fsm: ProtocolFSM, impl_fsm: ProtocolFSM
    ) -> tuple[ProtocolFSM, list[Divergence]]:
        unified = fsm_from_llm(
            data.get("unified_fsm"),
            builder="LLMFSMMerger",
            metadata={
                "merge_rationale": data.get("merge_rationale", ""),
                "uncertainties": data.get("uncertainties", []),
                "transition_sources": data.get("transition_sources", []),
                "comparison": "llm_only",
            },
        )
        normalize_fsm_protocol(unified, spec_fsm.protocol, component="UnifiedFSM")
        self._validate_transition_coverage(spec_fsm, impl_fsm, unified, data.get("transition_sources"))
        divergences = validate_divergences(data.get("divergences"))
        divergences.sort(key=lambda item: {"P0": 0, "P1": 1, "P2": 2}[item.severity])
        return unified, divergences

    def drain_conversations(self) -> list[dict[str, Any]]:
        return self.recorder.drain_conversations()

    def _validate_transition_coverage(
        self,
        spec_fsm: ProtocolFSM,
        impl_fsm: ProtocolFSM,
        unified_fsm: ProtocolFSM,
        mappings: Any,
    ) -> None:
        if not isinstance(mappings, list):
            raise ValueError("transition_sources must be an array")
        expected_spec = {item.id for item in spec_fsm.transitions}
        expected_impl = {item.id for item in impl_fsm.transitions}
        unified_ids = {item.id for item in unified_fsm.transitions}
        seen_spec: set[str] = set()
        seen_impl: set[str] = set()
        seen_unified: set[str] = set()
        for mapping in mappings:
            if not isinstance(mapping, dict):
                raise ValueError("transition_sources entries must be objects")
            unified_id = str(mapping.get("unified_transition_id", ""))
            if unified_id not in unified_ids:
                raise ValueError(f"transition_sources references unknown unified id: {unified_id!r}")
            spec_ids = {str(item) for item in mapping.get("spec_transition_ids", [])}
            impl_ids = {str(item) for item in mapping.get("impl_transition_ids", [])}
            if not spec_ids and not impl_ids:
                raise ValueError(f"transition_sources entry for {unified_id!r} has no input sources")
            if not spec_ids <= expected_spec:
                raise ValueError(f"transition_sources contains unknown spec ids: {sorted(spec_ids - expected_spec)}")
            if not impl_ids <= expected_impl:
                raise ValueError(f"transition_sources contains unknown impl ids: {sorted(impl_ids - expected_impl)}")
            seen_spec.update(spec_ids)
            seen_impl.update(impl_ids)
            seen_unified.add(unified_id)
        if seen_unified != unified_ids:
            raise ValueError(f"transition_sources omitted unified transitions: {sorted(unified_ids - seen_unified)}")
        if seen_spec != expected_spec or seen_impl != expected_impl:
            raise ValueError(
                "LLM merge omitted input transitions: "
                f"spec={sorted(expected_spec - seen_spec)}, impl={sorted(expected_impl - seen_impl)}"
            )
