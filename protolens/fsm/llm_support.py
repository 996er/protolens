from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse
import json
import re

from protolens.fsm.fsm_model import Divergence, ProtocolFSM
from protolens.utils.llm_client import LLMClient, LLMResponse


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
        "states": {"type": "array", "items": STATE_SCHEMA, "maxItems": 500},
        "transitions": {
            "type": "array",
            "items": TRANSITION_SCHEMA,
            "maxItems": 1000,
        },
        "initial_state": {"type": "string", "minLength": 1},
        "terminal_states": {"type": "array", "items": {"type": "string"}, "maxItems": 100},
        "error_states": {"type": "array", "items": {"type": "string"}, "maxItems": 100},
    },
}


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
    ) -> dict[str, Any]:
        return self._call(
            system=system,
            payload=payload,
            schema=schema,
            schema_name=schema_name,
            web_search=False,
            allowed_domains=None,
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
    ) -> tuple[dict[str, Any], LLMResponse]:
        data, response = self._call_with_response(
            system=system,
            payload=payload,
            schema=schema,
            schema_name=schema_name,
            web_search=True,
            allowed_domains=allowed_domains,
            max_tool_calls=max_tool_calls,
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
    ) -> dict[str, Any]:
        data, _ = self._call_with_response(
            system=system,
            payload=payload,
            schema=schema,
            schema_name=schema_name,
            web_search=web_search,
            allowed_domains=allowed_domains,
            max_tool_calls=max_tool_calls,
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
    ) -> tuple[dict[str, Any], LLMResponse]:
        base_user = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        last_error: Exception | None = None
        for attempt in range(self.llm_client.retries + 1):
            user = base_user
            if last_error is not None:
                user += (
                    "\n\nThe previous response was rejected by ProtoLens: "
                    f"{type(last_error).__name__}: {last_error}. Regenerate the complete JSON object."
                )
            record: dict[str, Any] = {
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
                record["response"] = {
                    "text": response.text,
                    "provider": response.provider,
                    "model": response.model,
                    "raw": response.raw,
                }
                data = load_json_object(response.text)
                validate_json_schema(data, schema)
                record["final_status"] = "success"
                self._conversations.append(record)
                return data, response
            except Exception as exc:
                last_error = exc
                raw = getattr(exc, "raw", None)
                if isinstance(raw, dict):
                    record["response"] = {
                        "text": "",
                        "provider": self.llm_client.provider,
                        "model": self.llm_client.model,
                        "raw": raw,
                    }
                record["error"] = {"type": type(exc).__name__, "message": str(exc)}
                record["final_status"] = "retrying" if attempt < self.llm_client.retries else "failed"
                self._conversations.append(record)
        assert last_error is not None
        raise last_error


def fsm_from_llm(data: Any, *, builder: str, metadata: dict[str, Any] | None = None) -> ProtocolFSM:
    if not isinstance(data, dict):
        raise ValueError("LLM FSM must be an object")
    states = data.get("states")
    if not isinstance(states, list):
        raise ValueError("LLM FSM states must be an array")
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
        raise ValueError(f"initial state {fsm.initial_state!r} is absent from states")
    unknown_terminal = fsm.terminal_states - set(fsm.states)
    unknown_error = fsm.error_states - set(fsm.states)
    if unknown_terminal or unknown_error:
        raise ValueError("terminal_states/error_states contain unknown state names")
    transition_ids: set[str] = set()
    for transition in fsm.transitions:
        if transition.source not in fsm.states or transition.target not in fsm.states:
            raise ValueError(f"transition {transition.id!r} references an unknown state")
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


def load_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        first_newline = stripped.find("\n")
        stripped = stripped[first_newline + 1 :] if first_newline >= 0 else ""
        if stripped.endswith("```"):
            stripped = stripped[:-3]
    data = json.loads(stripped)
    if not isinstance(data, dict):
        raise ValueError("LLM output must be a JSON object")
    return data


def validate_json_schema(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    expected_type = schema.get("type")
    if expected_type is not None and not _matches_json_type(value, expected_type):
        raise ValueError(f"{path} must have JSON type {expected_type!r}, got {type(value).__name__}")

    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} must be one of {schema['enum']!r}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise ValueError(f"{path} is missing required keys: {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extras = sorted(set(value) - set(properties))
            if extras:
                raise ValueError(f"{path} contains unexpected keys: {extras}")
        for key, item in value.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                validate_json_schema(item, child_schema, f"{path}.{key}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            raise ValueError(f"{path} must contain at least {schema['minItems']} items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise ValueError(f"{path} must contain at most {schema['maxItems']} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_json_schema(item, item_schema, f"{path}[{index}]")

    if isinstance(value, str) and "minLength" in schema and len(value) < int(schema["minLength"]):
        raise ValueError(f"{path} must contain at least {schema['minLength']} characters")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
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
