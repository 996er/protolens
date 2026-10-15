"""Strict decoding of model JSON objects, shared by transport and FSM validation."""
from typing import Any
import json


def load_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip().lstrip("\ufeff").strip()
    if stripped.startswith("```"):
        first_newline = stripped.find("\n")
        stripped = stripped[first_newline + 1:] if first_newline >= 0 else ""
        if stripped.endswith("```"):
            stripped = stripped[:-3]
        stripped = stripped.strip()
    if not stripped:
        raise ValueError("LLM final output is empty; expected a JSON object")

    def reject_constant(value: str) -> None:
        raise ValueError(f"LLM output contains non-finite JSON number {value}")

    try:
        data = json.loads(stripped, parse_constant=reject_constant)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"LLM final output is not valid JSON: {exc.msg} "
            f"at line {exc.lineno}, column {exc.colno} (char {exc.pos}); "
            "return only the complete JSON object, without prose or HTML"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError("LLM output must be a JSON object")
    return data
