"""Strict decoding of model JSON objects, shared by transport and FSM validation."""
from typing import Any
import json


def load_json_object(
    text: str, *, schema: dict[str, Any] | None = None,
    normalizations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Decode an object, optionally recovering lossless schema-keyed fragments.

    Recovery consumes the entire answer and never picks one of conflicting
    answers. Without a schema, retain strict single-document decoding.
    """
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
        if exc.msg == "Extra data" and schema is not None and schema.get("properties"):
            return _join_json_objects(
                stripped, schema, json.JSONDecoder(parse_constant=reject_constant),
                normalizations,
            )
        raise ValueError(
            f"LLM final output is not valid JSON: {exc.msg} "
            f"at line {exc.lineno}, column {exc.colno} (char {exc.pos}); "
            "return only the complete JSON object, without prose or HTML"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError("LLM output must be a JSON object")
    return data


def _join_json_objects(
    text: str, schema: dict[str, Any], decoder: json.JSONDecoder,
    normalizations: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Join complete adjacent objects with disjoint or identical root fields.

    Arrays and nested objects are atomic: appending graph fragments or choosing
    a newer value could change state identities, evidence or transition coverage.
    """
    merged: dict[str, Any] = {}
    field_documents: dict[str, int] = {}
    documents = 0
    offset = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        try:
            document, end = decoder.raw_decode(text, offset)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "LLM output contains multiple JSON objects or trailing content, "
                f"but document {documents + 1} is invalid at line {exc.lineno}, "
                f"column {exc.colno} (char {exc.pos}): {exc.msg}; "
                "return one complete JSON object without trailing text"
            ) from exc
        documents += 1
        if not isinstance(document, dict):
            raise ValueError(f"LLM output document {documents} must be a JSON object")
        unknown = sorted(set(document) - set(schema["properties"]))
        if unknown:
            raise ValueError(
                f"Cannot combine LLM output document {documents}: "
                f"unexpected top-level fields {unknown!r}; return one JSON object"
            )
        for key, value in document.items():
            if key in merged:
                # JSON encodings distinguish booleans from numbers (True == 1
                # in Python); object key ordering does not signify a conflict.
                if json.dumps(merged[key], sort_keys=True) != json.dumps(value, sort_keys=True):
                    raise ValueError(
                        f"LLM output documents {field_documents[key]} and {documents} "
                        f"contain conflicting values for field {key!r}; "
                        "return one complete, consistent JSON object"
                    )
            else:
                merged[key] = value
                field_documents[key] = documents
        offset = end
    if normalizations is not None:
        normalizations.append({
            "path": "$", "action": "combine_nonconflicting_json_documents",
            "document_count": documents, "fields": sorted(merged),
        })
    return merged
