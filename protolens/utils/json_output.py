"""Strict decoding of model JSON objects, shared by transport and FSM validation."""
from typing import Any
import json


class InvalidJSONOutput(ValueError):
    """A syntax failure with non-content diagnostics for logs and retry feedback."""

    def __init__(self, message: str, text: str) -> None:
        head = text.lstrip().lower()
        if not head:
            kind = "empty"
        elif head.startswith(("<!doctype html", "<html", "<head", "<body")):
            kind = "html"
        elif head.startswith(("<think", "<analysis", "<reasoning")):
            kind = "reasoning_markup"
        elif head[0] in "{[":
            kind = "malformed_json"
        elif head.startswith("```"):
            kind = "markdown"
        else:
            kind = "non_json_text"
        self.output_diagnostics = {"kind": kind, "characters": len(text)}
        super().__init__(f"{message}; output_kind={kind}, characters={len(text)}")


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
        raise InvalidJSONOutput("LLM final output is empty; expected a JSON object", stripped)

    def reject_constant(value: str) -> None:
        raise ValueError(f"LLM output contains non-finite JSON number {value}")

    try:
        data = json.loads(stripped, parse_constant=reject_constant)
    except json.JSONDecodeError as exc:
        if exc.msg == "Extra data" and schema is not None and schema.get("properties"):
            data = _join_json_objects(
                stripped, schema, json.JSONDecoder(parse_constant=reject_constant),
                normalizations,
            )
        else:
            raise InvalidJSONOutput(
                f"LLM final output is not valid JSON: {exc.msg} "
                f"at line {exc.lineno}, column {exc.colno} (char {exc.pos}); "
                "return only the complete JSON object, without prose or HTML",
                stripped,
            ) from exc
    if not isinstance(data, dict):
        raise ValueError("LLM output must be a JSON object")
    if schema is not None:
        _normalize_specification_result(data, schema, normalizations)
    return data


def _normalize_specification_result(
    data: dict[str, Any], schema: dict[str, Any],
    normalizations: list[dict[str, Any]] | None,
) -> None:
    """Recover explicit specification containers without creating graph data.

    Run in both the transport's completeness check and the recorder's decoder,
    before unknown fields are removed. Every recovered value still undergoes
    the normal graph, source and evidence validation.
    """
    properties = schema.get("properties", {})
    if not {"fsm", "sources", "latestness_rationale", "uncertainties"} <= properties.keys():
        return
    graph_fields = properties["fsm"].get("properties", {})
    if not {"states", "transitions"} <= graph_fields.keys():
        return
    aliases = {
        "specification_fsm": "fsm", "spec_fsm": "fsm",
        "state_machine": "fsm", "finite_state_machine": "fsm",
        "rfc_sources": "sources", "normative_sources": "sources",
    }

    def move(target: dict[str, Any], key: str, value: Any, origin: str, path: str) -> None:
        if key in target and json.dumps(target[key], sort_keys=True) != json.dumps(value, sort_keys=True):
            raise ValueError(
                f"Conflicting specification result fields: {path} and {origin}; "
                "return one consistent object with fsm, sources, latestness_rationale and uncertainties"
            )
        target[key] = value
        if normalizations is not None:
            normalizations.append({"path": path, "original_path": origin,
                                   "reason": "specification_result_container_normalized"})

    def normalize(container: dict[str, Any], path: str, depth: int = 0) -> None:
        if depth > 8:
            raise ValueError("Specification result has too many nested result containers")
        # Only named result envelopes qualify; never search arbitrary metadata
        # or pick one of multiple candidate answers.
        for envelope in ("result", "data", "output", "specification", "specification_result"):
            nested = container.get(envelope)
            if not isinstance(nested, dict):
                continue
            normalize(nested, f"{path}.{envelope}", depth + 1)
            if not ({"fsm", "sources"} & nested.keys()):
                continue
            for key in properties:
                if key in nested:
                    move(container, key, nested[key], f"{path}.{envelope}.{key}", f"{path}.{key}")
                    del nested[key]
            if not nested:
                del container[envelope]
        for alias, canonical in aliases.items():
            if alias in container:
                move(container, canonical, container[alias], f"{path}.{alias}", f"{path}.{canonical}")
                del container[alias]
        # A flattened graph must explicitly supply both collections. Missing
        # sources are never inferred from URLs or filled with an empty array.
        if {"states", "transitions"} <= container.keys():
            graph = container.get("fsm", {})
            if not isinstance(graph, dict):
                raise ValueError(f"{path}.fsm conflicts with flattened specification graph")
            for key in graph_fields:
                if key in container:
                    move(graph, key, container[key], f"{path}.{key}", f"{path}.fsm.{key}")
                    del container[key]
            container["fsm"] = graph

    normalize(data, "$")


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
