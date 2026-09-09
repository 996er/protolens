from __future__ import annotations

from typing import Any

from protolens.fsm.fsm_model import Divergence, ProtocolFSM
from protolens.fsm.llm_support import (
    EVIDENCE_SCHEMA,
    FSM_SCHEMA,
    LLMConversationRecorder,
    fsm_from_llm,
    normalize_fsm_protocol,
    validate_divergences,
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
        payload = {
            "task": "Compare SpecificationFSM and ImplementationFSM, report conflicts, and produce UnifiedFSM.",
            "requirements": [
                "Reason semantically about state aliases, guards, side effects, and error behavior.",
                "Preserve both normative and implementation-only behavior with evidence.",
                "Report every material conflict as a typed divergence with security-aware priority.",
                "Do not silently drop any input transition.",
                "Map every input transition id in transition_sources to its unified transition.",
                "Never cite evidence absent from the two input FSMs.",
            ],
            "specification_fsm": spec_fsm.to_dict(),
            "implementation_fsm": impl_fsm.to_dict(),
        }
        data = self.recorder.call_chat(
            system=(
                "You are ProtoLens FSM conflict analyst and merger. Compare the two evidence-backed models. "
                "The specification is normative; implementation behavior remains in the unified graph so later "
                "security reasoning can target divergences. Return a complete, auditable merge."
            ),
            payload=payload,
            schema=MERGE_RESULT_SCHEMA,
            schema_name="protolens_fsm_merge",
        )
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
        for mapping in mappings:
            if not isinstance(mapping, dict):
                raise ValueError("transition_sources entries must be objects")
            unified_id = str(mapping.get("unified_transition_id", ""))
            if unified_id not in unified_ids:
                raise ValueError(f"transition_sources references unknown unified id: {unified_id!r}")
            spec_ids = {str(item) for item in mapping.get("spec_transition_ids", [])}
            impl_ids = {str(item) for item in mapping.get("impl_transition_ids", [])}
            if not spec_ids <= expected_spec:
                raise ValueError(f"transition_sources contains unknown spec ids: {sorted(spec_ids - expected_spec)}")
            if not impl_ids <= expected_impl:
                raise ValueError(f"transition_sources contains unknown impl ids: {sorted(impl_ids - expected_impl)}")
            seen_spec.update(spec_ids)
            seen_impl.update(impl_ids)
        if seen_spec != expected_spec or seen_impl != expected_impl:
            raise ValueError(
                "LLM merge omitted input transitions: "
                f"spec={sorted(expected_spec - seen_spec)}, impl={sorted(expected_impl - seen_impl)}"
            )
