from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse
import json
import math
import re

from protolens.fsm.fsm_model import Divergence, ProtocolFSM
from protolens.utils.llm_client import IncompleteLLMResponse, LLMClient, LLMResponse
from protolens.utils.json_output import load_json_object


EVIDENCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["source_type", "location", "excerpt", "confidence"],
    "properties": {
        "source_type": {"type": "string", "minLength": 1},
        "location": {"type": "string", "minLength": 1},
        "excerpt": {"type": "string", "minLength": 1},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
}

STATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["name", "description", "evidence", "confidence"],
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "evidence": {"type": "array", "items": EVIDENCE_SCHEMA, "maxItems": 12},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
}

TRANSITION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "id", "source", "target", "trigger", "message_type", "guard", "action",
        "error_handling", "evidence", "confidence",
    ],
    "properties": {
        "id": {"type": "string", "minLength": 1},
        "source": {"type": "string", "minLength": 1},
        "target": {"type": "string", "minLength": 1},
        "trigger": {"type": "string", "minLength": 1},
        "message_type": {"type": ["string", "null"]},
        "guard": {"type": ["string", "null"]},
        "action": {"type": ["string", "null"]},
        "error_handling": {"type": ["string", "null"]},
        "evidence": {
            "type": "array",
            "items": EVIDENCE_SCHEMA,
            "minItems": 1,
            "maxItems": 12,
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
}

FSM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "protocol", "version", "states", "transitions", "initial_state",
        "terminal_states", "error_states",
    ],
    "properties": {
        "protocol": {"type": "string", "minLength": 1},
        "version": {"type": ["string", "null"]},
        "states": {"type": "array", "items": STATE_SCHEMA, "minItems": 1, "maxItems": 500},
        "transitions": {
            "type": "array",
            "items": TRANSITION_SCHEMA,
            "minItems": 1,
            "maxItems": 1000,
        },
        "initial_state": {"type": "string", "minLength": 1},
        "terminal_states": {"type": "array", "items": {"type": "string"}, "maxItems": 100},
        "error_states": {"type": "array", "items": {"type": "string"}, "maxItems": 100},
    },
}


class LLMValidationError(ValueError):
    """A model result exhausted its structural/semantic validation budget."""


@dataclass
class LLMConversationRecorder:
    name: str
    llm_client: LLMClient

    def __post_init__(self) -> None:
        self._conversations: list[dict[str, Any]] = []

    def call_chat(
        self,
        *,
        system: str,
        payload: dict[str, Any],
        schema: dict[str, Any],
        schema_name: str,
        validator: Callable[[dict[str, Any]], None] | None = None,
        validation_retries: int | None = None,
        result_normalizer: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
    ) -> dict[str, Any]:
        return self._call(
            system=system,
            payload=payload,
            schema=schema,
            schema_name=schema_name,
            web_search=False,
            allowed_domains=None,
            validator=validator,
            validation_retries=validation_retries,
            result_normalizer=result_normalizer,
        )

    def call_web(
        self,
        *,
        system: str,
        payload: dict[str, Any],
        schema: dict[str, Any],
        schema_name: str,
        allowed_domains: list[str],
        max_tool_calls: int,
        validator: Callable[[dict[str, Any]], None] | None = None,
        response_validator: Callable[[dict[str, Any], LLMResponse], None] | None = None,
        schema_repairer: Callable[[dict[str, Any], LLMResponse, ValueError], dict[str, Any]] | None = None,
    ) -> tuple[dict[str, Any], LLMResponse]:
        data, response = self._call_with_response(
            system=system,
            payload=payload,
            schema=schema,
            schema_name=schema_name,
            web_search=True,
            allowed_domains=allowed_domains,
            max_tool_calls=max_tool_calls,
            validator=validator,
            response_validator=response_validator,
            schema_repairer=schema_repairer,
        )
        return data, response

    def drain_conversations(self) -> list[dict[str, Any]]:
        records = list(self._conversations)
        self._conversations.clear()
        return records

    def mark_last_rejected(self, error: Exception) -> None:
        if not self._conversations:
            return
        record = self._conversations[-1]
        record["final_status"] = "rejected"
        record["validation_error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }

    def response_raws(self) -> list[dict[str, Any]]:
        raws: list[dict[str, Any]] = []
        for record in self._conversations:
            response = record.get("response")
            raw = response.get("raw") if isinstance(response, dict) else None
            if isinstance(raw, dict):
                raws.append(raw)
        return raws

    def _call(
        self,
        *,
        system: str,
        payload: dict[str, Any],
        schema: dict[str, Any],
        schema_name: str,
        web_search: bool,
        allowed_domains: list[str] | None,
        max_tool_calls: int | None = None,
        validator: Callable[[dict[str, Any]], None] | None = None,
        validation_retries: int | None = None,
        result_normalizer: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
    ) -> dict[str, Any]:
        data, _ = self._call_with_response(
            system=system,
            payload=payload,
            schema=schema,
            schema_name=schema_name,
            web_search=web_search,
            allowed_domains=allowed_domains,
            max_tool_calls=max_tool_calls,
            validator=validator,
            validation_retries=validation_retries,
            result_normalizer=result_normalizer,
        )
        return data

    def _call_with_response(
        self,
        *,
        system: str,
        payload: dict[str, Any],
        schema: dict[str, Any],
        schema_name: str,
        web_search: bool,
        allowed_domains: list[str] | None,
        max_tool_calls: int | None = None,
        validator: Callable[[dict[str, Any]], None] | None = None,
        response_validator: Callable[[dict[str, Any], LLMResponse], None] | None = None,
        schema_repairer: Callable[[dict[str, Any], LLMResponse, ValueError], dict[str, Any]] | None = None,
        validation_retries: int | None = None,
        result_normalizer: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
    ) -> tuple[dict[str, Any], LLMResponse]:
        base_user = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        last_error: Exception | None = None
        retries = self.llm_client.retries if validation_retries is None else validation_retries
        for attempt in range(retries + 1):
            user = base_user
            if last_error is not None:
                user += (
                    "\n\nThe previous response was rejected by ProtoLens: "
                    f"{type(last_error).__name__}: {last_error}. Regenerate the complete JSON object."
                )
            record: dict[str, Any] = {
                "started_at": datetime.now(timezone.utc).isoformat(),
                "component": self.name,
                "provider": self.llm_client.provider,
                "model": self.llm_client.model,
                "attempt": attempt + 1,
                "system": system,
                "user": user,
                "schema_name": schema_name,
                "json_schema": schema,
                "web_search": web_search,
            }
            received_response = False
            try:
                response = self.llm_client.responses_json(
                    system=system,
                    user=user,
                    response_schema=schema,
                    schema_name=schema_name,
                    web_search=web_search,
                    allowed_domains=allowed_domains,
                    max_tool_calls=max_tool_calls,
                )
                received_response = True
                record["response"] = {
                    "text": response.text,
                    "provider": response.provider,
                    "model": response.model,
                    "raw": response.raw,
                }
                data = load_json_object(response.text)
                normalizations = _normalize_fsm_metadata(
                    data, schema, protocol=payload.get("protocol"),
                    repair_response=schema_name.endswith("_repair"),
                )
                if result_normalizer is not None:
                    normalizations.extend(result_normalizer(data))
                if normalizations:
                    record["normalizations"] = normalizations
                try:
                    validate_json_schema(data, schema)
                except ValueError as schema_error:
                    if schema_repairer is None:
                        raise
                    record["schema_error_before_repair"] = str(schema_error)
                    data = schema_repairer(data, response, schema_error)
                    validate_json_schema(data, schema)
                if validator is not None:
                    validator(data)
                if response_validator is not None:
                    response_validator(data, response)
                record["final_status"] = "success"
                self._conversations.append(record)
                return data, response
            except Exception as exc:
                last_error = exc
                raw = getattr(exc, "raw", None)
                if isinstance(raw, dict):
                    record["response"] = {
                        "text": getattr(exc, "text", ""),
                        "provider": self.llm_client.provider,
                        "model": self.llm_client.model,
                        "raw": raw,
                    }
                record["error"] = {"type": type(exc).__name__, "message": str(exc)}
                # Transport/output-budget retries belong to LLMClient. Retrying them
                # here multiplies request counts and worsens upstream rate limits.
                retryable = received_response and isinstance(exc, ValueError)
                record["final_status"] = "retrying" if retryable and attempt < retries else "failed"
                self._conversations.append(record)
                if not retryable:
                    if isinstance(exc, IncompleteLLMResponse):
                        raise IncompleteLLMResponse(exc.raw, context=f"{self.name}/{schema_name}") from exc
                    raise RuntimeError(f"{self.name}/{schema_name} request failed: {exc}") from exc
        assert last_error is not None
        raise LLMValidationError(
            f"{self.name}/{schema_name}: invalid LLM result after {retries + 1} attempt(s): {last_error}"
        ) from last_error


def _normalize_fsm_metadata(
    value: Any, schema: dict[str, Any], path: str = "$", *, protocol: str | None = None,
    repair_response: bool = False,
) -> list[dict[str, Any]]:
    """Normalize FSM aliases and separate extensions before strict validation.

    Apply known aliases before moving undeclared fields to the audit. Required
    fields, supplied values and graph semantics still undergo strict validation;
    extensions cannot substitute for evidence or missing graph fields. Schemas
    that permit additional properties retain them. The raw response is preserved.
    """
    changes: list[dict[str, Any]] = []
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if ({"spec_transition_ids", "impl_transition_ids"} <= properties.keys()
                and ("unified_transition_id" in properties or "mapping_index" in properties)):
            for canonical, aliases in (
                ("spec_transition_ids", ("spec_transition_id", "spec_ids", "specification_transition_ids")),
                ("impl_transition_ids", ("impl_transition_id", "impl_ids", "implementation_transition_ids")),
            ):
                for field in (canonical, *aliases):
                    if isinstance(value.get(field), str):
                        original = value[field]
                        value[field] = [original]
                        changes.append({"path": f"{path}.{field}", "original_value": original,
                                        "value": [original], "reason": "single_transition_source_id"})
                for alias in aliases:
                    if alias not in value or alias in properties:
                        continue
                    if canonical in value and value[canonical] != value[alias]:
                        raise ValueError(f"{path} contains conflicting source mappings: {canonical}, {alias}")
                    value[canonical] = value.pop(alias)
                    changes.append({"path": f"{path}.{canonical}", "original_path": f"{path}.{alias}",
                                    "value": value[canonical], "reason": "transition_source_alias"})
        states_schema = properties.get("states", {})
        state_schema = states_schema.get("items", {})
        if (states_schema.get("type") == "array" and state_schema.get("type") == "object"
                and {"name", "description", "evidence", "confidence"}
                <= state_schema.get("properties", {}).keys()
                and isinstance(value.get("states"), dict)):
            # ProtocolFSM's persisted representation indexes states by name;
            # providers may copy it even when the output schema uses an array.
            # Convert the container without dropping annotations or silently
            # choosing between conflicting identities.
            states = []
            for name, state in value["states"].items():
                if not isinstance(state, dict):
                    raise ValueError(f"{path}.states[{name!r}] must be a state object")
                if "name" in state and state["name"] != name:
                    raise ValueError(
                        f"{path}.states contains conflicting state names: "
                        f"dictionary key={name!r}, name={state['name']!r}"
                    )
                states.append({**state, "name": name})
            changes.append({"path": f"{path}.states", "state_names": list(value["states"]),
                            "reason": "state_mapping_to_array"})
            value["states"] = states
        if (properties.get("confidence", {}).get("type") == "number"
                and isinstance(value.get("confidence"), str)):
            original = value["confidence"]
            numeric_text = original.strip()
            percentage = numeric_text.endswith("%")
            if percentage:
                numeric_text = numeric_text[:-1].strip()
            # Normalize explicit numbers only. Labels such as "high" have no
            # defined numeric meaning; bare 95 must not silently become 0.95.
            if not re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", numeric_text):
                raise ValueError(
                    f"{path}.confidence must be numeric or an explicit percentage, got {original!r}"
                )
            confidence = float(numeric_text)
            if percentage:
                confidence /= 100
            if not math.isfinite(confidence):
                raise ValueError(f"{path}.confidence must be finite, got {original!r}")
            value["confidence"] = confidence
            changes.append({"path": f"{path}.confidence", "original_value": original,
                            "value": confidence, "reason": "numeric_confidence_string"})
            # The original schema still checks the permitted range below.
        if {"source_type", "location", "excerpt", "confidence"} <= properties.keys():
            # Normalize citation aliases before the extension filter can move
            # the only supplied quotation or URL out of the evidence object.
            for alias, canonical in (
                ("quote", "excerpt"), ("quotation", "excerpt"),
                ("source_url", "location"), ("url", "location"),
                ("type", "source_type"),
            ):
                if alias not in value or alias in properties:
                    continue
                if (canonical == "location" and isinstance(value.get(canonical), str)
                        and value[canonical].strip() and not canonical_source_url(value[canonical])
                        and isinstance(value[alias], str)
                        and re.fullmatch(r"https?://\S+", value[alias].strip())
                        and urlparse(value[alias].strip()).hostname):
                    # A section title and a document URL are complementary.
                    # Keep the title verbatim; do not invent a fragment whose
                    # spelling may differ between RFC publishers/formats.
                    location = value[canonical]
                    source_url = value[alias].strip()
                    source_id = canonical_source_url(source_url)
                    named_rfcs = {f"rfc:{int(number)}" for number in re.findall(
                        r"\bRFC\s*0*(\d+)\b", location, re.IGNORECASE,
                    )}
                    if not named_rfcs or named_rfcs == {source_id}:
                        original_url = value.pop(alias)
                        value[canonical] = f"{source_url} {location}"
                        changes.append({
                            "path": f"{path}.{canonical}", "value": value[canonical],
                            "original_value": location, "original_path": f"{path}.{alias}",
                            "original_url": original_url, "reason": "evidence_url_and_section_combined",
                        })
                        continue
                if (canonical == "location" and isinstance(value.get(canonical), str)
                        and isinstance(value[alias], str) and canonical_source_url(value[canonical])
                        and canonical_source_url(value[canonical]) == canonical_source_url(value[alias])):
                    # Keep the canonical location's section when an additional
                    # source URL names the same RFC without its fragment.
                    changes.append({"path": f"{path}.{alias}", "value": value.pop(alias),
                                    "reason": "redundant_evidence_source_url"})
                    continue
                if canonical in value and value[canonical] != value[alias]:
                    raise ValueError(
                        f"{path} contains conflicting citation fields: "
                        f"{canonical}={value[canonical]!r}, {alias}={value[alias]!r}"
                    )
                value[canonical] = value.pop(alias)
                changes.append({"path": f"{path}.{canonical}", "value": value[canonical],
                                "original_path": f"{path}.{alias}", "reason": "evidence_field_alias"})
        # Repair rationales are audit commentary, not the values being patched.
        # Keep strict output schemas for providers, but do not retry a valid
        # repair solely because this commentary was omitted or structured.
        # This policy does not apply to merge/latestness rationales or evidence.
        is_repair_note = path == "$" or re.search(r"\.repairs\[[0-9]+\]$", path) is not None
        if (repair_response and is_repair_note
                and properties.get("rationale", {}).get("type") == "string"):
            rationale = value.get("rationale")
            rendered = None
            if rationale is None or (isinstance(rationale, str) and not rationale.strip()):
                rendered = "[ProtoLens audit] Model supplied no repair rationale; no justification was inferred."
            elif isinstance(rationale, (dict, list)):
                rendered = json.dumps(rationale, ensure_ascii=False, sort_keys=True)
            if rendered is not None:
                changes.append({"path": f"{path}.rationale", "original_value": rationale,
                                "was_missing": "rationale" not in value, "value": rendered,
                                "reason": "repair_rationale_annotation_normalized"})
                value["rationale"] = rendered
        uncertainties_schema = properties.get("uncertainties", {})
        if (uncertainties_schema.get("type") == "array"
                and uncertainties_schema.get("items", {}).get("type") == "string"
                and isinstance(value.get("uncertainties"), list)):
            for index, uncertainty in enumerate(value["uncertainties"]):
                if isinstance(uncertainty, (dict, list)):
                    # Preserve every detail of structured commentary, including
                    # nested citations, instead of selecting one text field.
                    # This conversion must not apply to state names or evidence.
                    rendered = json.dumps(uncertainty, ensure_ascii=False, sort_keys=True)
                    value["uncertainties"][index] = rendered
                    changes.append({"path": f"{path}.uncertainties[{index}]",
                                    "original_value": uncertainty, "value": rendered,
                                    "reason": "structured_uncertainty_to_string"})
        evidence_schema = properties.get("evidence", {})
        if (evidence_schema.get("type") == "array"
                and evidence_schema.get("items", {}).get("type") == "object"
                and isinstance(value.get("evidence"), dict)):
            # Accept a single citation wherever an evidence array is expected.
            # Preserve the supplied object and validate it recursively below;
            # empty or malformed citations must not become valid evidence.
            value["evidence"] = [value["evidence"]]
            changes.append({"path": f"{path}.evidence", "original_type": "object",
                            "reason": "single_evidence_object_to_array"})
        if {"id", "source", "target", "trigger", "evidence"} <= properties.keys():
            # Accept common endpoint aliases only on transition objects. The
            # canonical endpoint values still undergo type and state checks.
            for alias, canonical in (("from", "source"), ("to", "target")):
                if alias not in value or alias in properties:
                    continue
                if canonical in value and value[canonical] != value[alias]:
                    raise ValueError(
                        f"{path} contains conflicting endpoint fields: "
                        f"{canonical}={value[canonical]!r}, {alias}={value[alias]!r}. "
                        f"Use only {canonical} with the evidence-backed state name."
                    )
                endpoint = value.pop(alias)
                value[canonical] = endpoint
                changes.append({"path": f"{path}.{canonical}", "value": endpoint,
                                "original_path": f"{path}.{alias}",
                                "reason": "transition_endpoint_alias"})
        is_fsm = {"protocol", "states", "transitions", "version"} <= properties.keys()
        if is_fsm and "protocol" not in value and isinstance(protocol, str) and protocol.strip():
            value["protocol"] = protocol
            changes.append({"path": f"{path}.protocol", "value": protocol,
                            "reason": "protocol_from_request_context"})
        version_types = properties.get("version", {}).get("type", [])
        if (is_fsm
                and isinstance(version_types, list) and "null" in version_types
                and "version" not in value):
            value["version"] = None
            changes.append({"path": f"{path}.version", "value": None,
                            "reason": "omitted_nullable_fsm_version"})
        # State annotations are optional in the in-memory model. An empty
        # description or citation list records their absence, not a new fact.
        # Never apply this to transition evidence (which requires minItems=1).
        if {"name", "description", "confidence"} <= properties.keys():
            defaults: dict[str, Any] = {"description": ""}
            evidence_schema = properties.get("evidence", {})
            if evidence_schema.get("type") == "array" and evidence_schema.get("minItems", 0) == 0:
                defaults["evidence"] = []
            for key, default in defaults.items():
                if key not in value:
                    value[key] = default
                    changes.append({"path": f"{path}.{key}", "value": default,
                                    "reason": "omitted_state_annotation"})
            # Entry/exit annotations can describe actions or conditions; they
            # do not reliably identify initial or terminal states. Preserve
            # their content in the supported description field and the audit,
            # without inferring graph roles or changing transition actions.
            for key in ("entry", "exit"):
                if key not in value or key in properties:
                    continue
                annotation = value.pop(key)
                changes.append({"path": f"{path}.{key}", "value": annotation,
                                "reason": "state_annotation_preserved_in_description_and_audit"})
                if isinstance(value.get("description"), str):
                    description = value["description"]
                    separator = "\n" if description else ""
                    rendered = json.dumps(annotation, ensure_ascii=False)
                    value["description"] = f"{description}{separator}{key}: {rendered}"
        # Provider outputs often include descriptive extensions such as FSM
        # name/specification or transition notes. Handle all undeclared keys
        # consistently at every schema level, instead of maintaining a growing
        # allowlist. Never copy an unknown field into a semantic field or relax
        # the schema validator: required fields and known values remain checked.
        if schema.get("additionalProperties") is False:
            for key in sorted(set(value) - set(properties)):
                extension = value.pop(key)
                changes.append({"path": f"{path}.{key}", "value": extension,
                                "reason": "unexpected_field_preserved_in_audit"})
        for key, item in value.items():
            if isinstance(properties.get(key), dict):
                changes.extend(_normalize_fsm_metadata(
                    item, properties[key], f"{path}.{key}", protocol=protocol,
                    repair_response=repair_response,
                ))
    elif isinstance(value, list) and isinstance(schema.get("items"), dict):
        item_schema = schema["items"]
        is_state = (
            item_schema.get("type") == "object"
            and {"name", "description", "evidence", "confidence"}
            <= item_schema.get("properties", {}).keys()
        )
        for index, item in enumerate(value):
            if is_state and isinstance(item, str):
                # A bare string explicitly declares a state name, but supplies
                # no annotations or supporting evidence. Do not invent either
                # or inherit the in-memory model's default full confidence.
                # Keep the name unchanged so empty/duplicate names and endpoint
                # mismatches still fail the normal schema/graph validation.
                original = item
                item = {"name": original, "description": "", "evidence": [], "confidence": 0.0}
                value[index] = item
                changes.append({"path": f"{path}[{index}]", "original_value": original,
                                "value": dict(item), "reason": "state_name_string_to_object"})
            changes.extend(_normalize_fsm_metadata(
                item, item_schema, f"{path}[{index}]", protocol=protocol,
                repair_response=repair_response,
            ))
    return changes


def fsm_from_llm(data: Any, *, builder: str, metadata: dict[str, Any] | None = None) -> ProtocolFSM:
    validate_json_schema(data, FSM_SCHEMA)
    if not isinstance(data, dict):
        raise ValueError("LLM FSM must be an object")
    states = data.get("states")
    if not isinstance(states, list):
        raise ValueError("LLM FSM states must be an array")
    names = [item["name"] for item in states]
    if len(set(names)) != len(names):
        positions: dict[str, list[int]] = {}
        for index, name in enumerate(names):
            positions.setdefault(name, []).append(index)
        duplicates = {name: indices for name, indices in positions.items() if len(indices) > 1}
        raise ValueError(
            "LLM FSM contains duplicate state names; every state name must be unique: "
            f"{json.dumps(duplicates, ensure_ascii=False)} (zero-based states[] positions). "
            "Consolidate declarations of the same state without losing evidence; "
            "if they represent distinct states, give them distinct names and update their references."
        )
    if any(name != name.strip() for name in names):
        raise ValueError("LLM FSM state names must not have leading or trailing whitespace")
    normalized = dict(data)
    normalized["states"] = {
        str(item.get("name", "")): item
        for item in states
        if isinstance(item, dict) and str(item.get("name", "")).strip()
    }
    normalized["metadata"] = {"builder": builder, **(metadata or {})}
    fsm = ProtocolFSM.from_dict(normalized)
    validate_fsm(fsm)
    return fsm


def validate_fsm(fsm: ProtocolFSM) -> None:
    if not fsm.states:
        raise ValueError("LLM FSM contains no states")
    if not fsm.transitions:
        raise ValueError("LLM FSM contains no transitions")
    if fsm.initial_state not in fsm.states:
        raise ValueError(
            f"initial state {fsm.initial_state!r} is absent from states; "
            f"declared states={sorted(fsm.states)!r}. "
            "Use an exact declared state name, or declare the evidence-backed entry state."
        )
    unknown_terminal = fsm.terminal_states - set(fsm.states)
    unknown_error = fsm.error_states - set(fsm.states)
    if unknown_terminal or unknown_error:
        raise ValueError(
            "terminal_states/error_states contain unknown state names: "
            f"unknown terminal_states={sorted(unknown_terminal)!r}, "
            f"unknown error_states={sorted(unknown_error)!r}; "
            f"declared states={sorted(fsm.states)!r}. "
            "Use exact declared names for aliases, declare omitted evidence-backed states, "
            "or remove classifications unsupported by the evidence."
        )
    transition_ids: set[str] = set()
    for transition in fsm.transitions:
        if transition.source not in fsm.states or transition.target not in fsm.states:
            missing = sorted({transition.source, transition.target} - set(fsm.states))
            raise ValueError(
                f"transition {transition.id!r} references an unknown state: "
                f"source={transition.source!r}, target={transition.target!r}, missing={missing!r}; "
                f"declared states={sorted(fsm.states)!r}. "
                "Each endpoint must exactly match a declared states[].name; "
                "correct the endpoint or declare the evidence-backed state."
            )
        if transition.id in transition_ids:
            raise ValueError(f"duplicate transition id: {transition.id}")
        transition_ids.add(transition.id)
        if not transition.evidence:
            raise ValueError(f"transition {transition.id!r} has no evidence")
        if not 0 <= transition.confidence <= 1:
            raise ValueError(f"transition {transition.id!r} has invalid confidence")


def protocol_label_matches(expected: str, actual: str) -> bool:
    expected_key = _protocol_key(expected)
    actual_text = actual.strip()
    if not expected_key or not actual_text:
        return False
    if _protocol_key(actual_text) == expected_key:
        return True

    candidates: list[str] = []
    leading = re.split(r"\s*(?:\(|\[|:|\s[-\u2013\u2014]\s)", actual_text, maxsplit=1)[0]
    candidates.append(leading)
    candidates.extend(re.findall(r"[\(\[]\s*([^\)\]]+)\s*[\)\]]", actual_text))
    first_token = re.match(r"^([A-Za-z0-9][A-Za-z0-9.+/_-]*)", actual_text)
    if first_token:
        candidates.append(first_token.group(1))
    if any(_protocol_key(candidate) == expected_key for candidate in candidates):
        return True

    words = re.findall(r"[A-Za-z0-9]+", actual_text)
    acronym = "".join(word[0] for word in words if word)
    return len(words) >= 2 and _protocol_key(acronym) == expected_key


def normalize_fsm_protocol(fsm: ProtocolFSM, expected: str, *, component: str) -> None:
    model_label = fsm.protocol
    if not protocol_label_matches(expected, model_label):
        raise ValueError(f"{component} protocol mismatch: expected {expected!r}, got {model_label!r}")
    if model_label != expected:
        fsm.metadata["model_protocol_label"] = model_label
    fsm.protocol = expected


def _protocol_key(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def validate_divergences(items: Any) -> list[Divergence]:
    if not isinstance(items, list):
        raise ValueError("LLM divergences must be an array")
    allowed_kinds = {
        "missing_transition", "extra_transition", "guard_mismatch", "state_mismatch",
        "action_mismatch", "error_handling_mismatch",
    }
    result: list[Divergence] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("each divergence must be an object")
        if item.get("kind") not in allowed_kinds:
            raise ValueError(f"unsupported divergence kind: {item.get('kind')!r}")
        if item.get("severity") not in {"P0", "P1", "P2"}:
            raise ValueError(f"unsupported divergence severity: {item.get('severity')!r}")
        result.append(Divergence.from_dict(item))
    return result


def validate_json_schema(
    value: Any, schema: dict[str, Any], path: str = "$", *, allow_missing: bool = False,
) -> None:
    expected_type = schema.get("type")
    if expected_type is not None and not _matches_json_type(value, expected_type):
        raise ValueError(f"{path} must have JSON type {expected_type!r}, got {type(value).__name__}")

    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} must be one of {schema['enum']!r}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing and not allow_missing:
            raise ValueError(f"{path} is missing required keys: {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extras = sorted(set(value) - set(properties))
            if extras:
                raise ValueError(f"{path} contains unexpected keys: {extras}")
        for key, item in value.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                validate_json_schema(item, child_schema, f"{path}.{key}", allow_missing=allow_missing)

    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            raise ValueError(f"{path} must contain at least {schema['minItems']} items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise ValueError(f"{path} must contain at most {schema['maxItems']} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_json_schema(item, item_schema, f"{path}[{index}]", allow_missing=allow_missing)

    if isinstance(value, str) and "minLength" in schema and len(value.strip()) < int(schema["minLength"]):
        raise ValueError(f"{path} must contain at least {schema['minLength']} characters")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(f"{path} must be a finite number")
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path} must be >= {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{path} must be <= {schema['maximum']}")


def _matches_json_type(value: Any, expected: Any) -> bool:
    choices = expected if isinstance(expected, list) else [expected]
    for choice in choices:
        if choice == "null" and value is None:
            return True
        if choice == "object" and isinstance(value, dict):
            return True
        if choice == "array" and isinstance(value, list):
            return True
        if choice == "string" and isinstance(value, str):
            return True
        if choice == "boolean" and isinstance(value, bool):
            return True
        if choice == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if choice == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
    return False


def response_used_web_search(raw: dict[str, Any] | None) -> bool:
    if not isinstance(raw, dict):
        return False
    output = raw.get("output", [])
    return any(
        isinstance(item, dict)
        and item.get("type") in {"web_search_call", "web_search_preview_call"}
        and item.get("status") in {None, "completed"}
        for item in output
    )


def response_source_urls(raw: dict[str, Any] | None) -> set[str]:
    urls: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "url" and isinstance(item, str) and item.startswith(("https://", "http://")):
                    normalized = canonical_source_url(item)
                    if normalized:
                        urls.add(normalized)
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    if isinstance(raw, dict):
        for output_item in raw.get("output", []):
            if not isinstance(output_item, dict):
                continue
            if output_item.get("type") not in {"web_search_call", "web_search_preview_call"}:
                continue
            visit(output_item.get("action", {}))
            visit(output_item.get("results", []))
    return urls


def canonical_source_url(value: str) -> str:
    match = re.search(r"https?://[^\s\u00a7]+", value.strip())
    if not match:
        return ""
    parsed = urlparse(match.group(0))
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = re.sub(r"/+", "/", parsed.path).rstrip("/").lower()
    rfc_match = re.search(r"(?:^|/)rfc0*(\d+)(?:\.(?:html|txt|pdf))?$", path)
    if rfc_match and url_is_allowed(match.group(0), ["rfc-editor.org", "ietf.org"]):
        return f"rfc:{int(rfc_match.group(1))}"
    if not host:
        return ""
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme.lower()}://{host}{port}{path or '/'}"


def source_url_is_verified(url: str, searched_urls: set[str]) -> bool:
    canonical = canonical_source_url(url)
    return bool(canonical and canonical in searched_urls)


def url_is_allowed(url: str, allowed_domains: list[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == domain or host.endswith(f".{domain}") for domain in allowed_domains)
