"""Protocol-independent validation and explicit normalization policies for JSON results."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Literal, Mapping
import hashlib
import json
import math


Path = tuple[str | int, ...]


def _location(path: Path, prefix: str = "$") -> str:
    for part in path:
        if isinstance(part, int):
            prefix += f"[{part}]"
        elif part.isidentifier():
            prefix += f".{part}"
        else:
            prefix += f"[{json.dumps(part, ensure_ascii=False)}]"
    return prefix


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


@dataclass(frozen=True)
class SchemaIssue:
    path: Path
    keyword: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": list(self.path), "keyword": self.keyword, "message": self.message}


class SchemaValidationError(ValueError):
    def __init__(self, issues: list[SchemaIssue]) -> None:
        self.issues = tuple(issues)
        super().__init__(issues[0].message)


def collect_schema_issues(
    value: Any, schema: dict[str, Any], path: str = "$", *, allow_missing: bool = False,
) -> list[SchemaIssue]:
    """Collect every failing location in the schema subset used by ProtoLens."""
    issues: list[SchemaIssue] = []

    def visit(item: Any, shape: dict[str, Any], parts: Path) -> None:
        here = _location(parts, path)

        def add(keyword: str, message: str, at: Path = parts) -> None:
            issues.append(SchemaIssue(at, keyword, message))

        expected = shape.get("type")
        if expected is not None and not _matches_json_type(item, expected):
            add("type", f"{here} must have JSON type {expected!r}, got {type(item).__name__}")
            return
        if "enum" in shape and item not in shape["enum"]:
            add("enum", f"{here} must be one of {shape['enum']!r}, got {item!r}")
        if isinstance(item, dict):
            properties = shape.get("properties", {})
            missing = [key for key in shape.get("required", []) if key not in item]
            if not allow_missing:
                for key in missing:
                    add("required", f"{here} is missing required keys: {missing!r}", (*parts, key))
            extra = sorted(set(item) - set(properties))
            if shape.get("additionalProperties") is False and extra:
                add("additionalProperties", f"{here} contains unexpected keys: {extra!r}")
            for key, child in item.items():
                child_schema = properties.get(key)
                if child_schema is None and isinstance(shape.get("additionalProperties"), dict):
                    child_schema = shape["additionalProperties"]
                if isinstance(child_schema, dict):
                    visit(child, child_schema, (*parts, key))
        if isinstance(item, list):
            for keyword, fails, description in (
                ("minItems", lambda bound: len(item) < bound, "at least"),
                ("maxItems", lambda bound: len(item) > bound, "at most"),
            ):
                if keyword in shape and fails(int(shape[keyword])):
                    add(keyword, f"{here} must contain {description} {shape[keyword]} items")
            if isinstance(shape.get("items"), dict):
                for index, child in enumerate(item):
                    visit(child, shape["items"], (*parts, index))
        if isinstance(item, str):
            if "minLength" in shape and len(item.strip()) < int(shape["minLength"]):
                add("minLength", f"{here} must contain at least {shape['minLength']} characters")
            if "maxLength" in shape and len(item) > int(shape["maxLength"]):
                add("maxLength", f"{here} must contain at most {shape['maxLength']} characters")
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            if isinstance(item, float) and not math.isfinite(item):
                add("finite", f"{here} must be a finite number")
                return
            if "minimum" in shape and item < shape["minimum"]:
                add("minimum", f"{here} must be >= {shape['minimum']}")
            if "maximum" in shape and item > shape["maximum"]:
                add("maximum", f"{here} must be <= {shape['maximum']}")

    visit(value, schema, ())
    return issues


def validate_json_schema(
    value: Any, schema: dict[str, Any], path: str = "$", *, allow_missing: bool = False,
) -> None:
    issues = collect_schema_issues(value, schema, path, allow_missing=allow_missing)
    if issues:
        raise SchemaValidationError(issues)


@dataclass(frozen=True)
class FieldPolicy:
    """Every nonsemantic default must be explicitly opted into by a contract."""
    role: Literal["semantic", "collection", "annotation"] = "semantic"
    aliases: tuple[str, ...] = ()
    empty_if_absent: bool = False
    singleton: bool = False
    canonicalize: Callable[[Any], Any] | None = None


def normalize_schema_fields(
    value: Any, schema: dict[str, Any], policies: Mapping[Path, FieldPolicy],
) -> list[dict[str, Any]]:
    """Apply declared format/annotation policies, without defaulting judgments.

    Schema defaults are deliberately ignored. Wildcards select item fields;
    policies never depend on a protocol, command spelling or state name.
    """
    notes: list[dict[str, Any]] = []

    def policy_for(path: Path) -> FieldPolicy:
        for pattern, policy in policies.items():
            if len(pattern) == len(path) and all(left == "*" or left == right for left, right in zip(pattern, path)):
                return policy
        return FieldPolicy()

    def note(path: Path, reason: str, **details: Any) -> None:
        notes.append({"path": _location(path), "reason": reason, **deepcopy(details)})

    def annotation(parent: dict[str, Any], key: str, shape: dict[str, Any], policy: FieldPolicy, path: Path) -> None:
        original = parent.get(key)
        source = original
        fields = [key] if key in parent else []
        if source is None or (isinstance(source, str) and not source.strip()):
            aliases = {alias: parent[alias] for alias in policy.aliases
                       if parent.get(alias) is not None and parent[alias] != ""}
            if aliases:
                fields = list(aliases)
                source = next(iter(aliases.values())) if len(aliases) == 1 else aliases
        limit = shape.get("maxLength")
        if source is None or (isinstance(source, str) and not source.strip()):
            rendered = f"[ProtoLens audit] Model supplied no {key} annotation; no semantic justification was inferred."
            reason = "missing_annotation"
        elif isinstance(source, str):
            if source == original and (limit is None or len(source) <= limit):
                return
            rendered, reason = source, "annotation_alias"
        else:
            rendered = "[Model annotation, JSON] " + json.dumps(source, ensure_ascii=False, sort_keys=True)
            reason = "structured_annotation"
        details: dict[str, Any] = {"was_missing": key not in parent, "source_fields": fields}
        if limit is not None and len(rendered) > limit:
            rendered = "[ProtoLens audit] Annotation exceeded the length limit; full content is preserved in response.text."
            if len(rendered) > limit:
                raise ValueError(f"annotation policy at {_location(path)} cannot fit its audit marker")
            encoded = json.dumps(source, ensure_ascii=False, sort_keys=True).encode("utf-8")
            details.update({"original_sha256": hashlib.sha256(encoded).hexdigest(), "original_in": "response.text"})
            reason = "oversized_annotation"
        else:
            details["original_value"] = original
        parent[key] = rendered
        note(path, reason, value=rendered, **details)

    def visit(item: Any, shape: dict[str, Any], path: Path) -> None:
        if isinstance(item, dict):
            for key, child_schema in shape.get("properties", {}).items():
                child_path = (*path, key)
                policy = policy_for(child_path)
                if policy.role == "annotation":
                    annotation(item, key, child_schema, policy, child_path)
                else:
                    for alias in policy.aliases:
                        if alias not in item:
                            continue
                        alias_value = policy.canonicalize(item[alias]) if policy.canonicalize else item[alias]
                        if key in item:
                            canonical = policy.canonicalize(item[key]) if policy.canonicalize else item[key]
                            if canonical != alias_value:
                                raise ValueError(f"{_location(path)} contains conflicting fields {key!r}, {alias!r}")
                        else:
                            item[key] = item[alias]
                        note(child_path, "schema_field_alias", original_path=_location((*path, alias)), original_value=item[alias])
                        del item[alias]
                    if key in item and policy.canonicalize:
                        normalized = policy.canonicalize(item[key])
                        if normalized != item[key]:
                            note(child_path, "schema_field_spelling", original_value=item[key], value=normalized)
                            item[key] = normalized
                    if policy.role == "collection" and child_schema.get("type") == "array":
                        if (policy.empty_if_absent and child_schema.get("minItems", 0) == 0
                                and (key not in item or item[key] is None)):
                            note(child_path, "unspecified_collection", was_missing=key not in item, original_value=item.get(key), value=[])
                            item[key] = []
                        elif (key in item and not isinstance(item[key], list) and policy.singleton
                              and _matches_json_type(item[key], child_schema.get("items", {}).get("type"))):
                            note(child_path, "singleton_collection", original_value=item[key])
                            item[key] = [item[key]]
                if key in item:
                    visit(item[key], child_schema, child_path)
        elif isinstance(item, list) and isinstance(shape.get("items"), dict):
            for index, child in enumerate(item):
                visit(child, shape["items"], (*path, index))

    visit(value, schema, ())
    return notes
