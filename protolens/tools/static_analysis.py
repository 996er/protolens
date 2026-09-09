from __future__ import annotations

from pathlib import Path
import re

from protolens.fsm.fsm_model import Evidence, StateTransition
from protolens.tools.rfc_parser import TRANSITION_RE

SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
SKIP_DIRS = {".git", "runs", "__pycache__", "queue", "crashes", "hangs", "out"}
STATE_ASSIGN_RE = re.compile(
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*(?:->|\.))?(?:state|status|phase)\s*=\s*(?P<target>[A-Z_][A-Z0-9_]{1,})\b"
)
STATE_GUARD_RE = re.compile(
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*(?:->|\.))?(?:state|status|phase)\s*(?:==|!=)\s*(?P<source>[A-Z_][A-Z0-9_]{1,})\b"
)
STATE_CASE_RE = re.compile(r"\bcase\s+(?P<source>[A-Z_][A-Z0-9_]{1,})\s*:")
COMMAND_LITERAL_RE = re.compile(
    r"\b(?:cmd|command|method|verb|request)\b[^\n;]{0,120}?[\"'](?P<trigger>[A-Z][A-Z0-9_.-]{1,})[\"']"
    r"|[\"'](?P<trigger_alt>[A-Z][A-Z0-9_.-]{1,})[\"'][^\n;]{0,120}?\b(?:cmd|command|method|verb|request)\b"
)
FUNCTION_RE = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{?")


class StaticAnalysis:
    """受资源上限约束的源码扫描器，抽取显式状态标记并保守恢复常见状态赋值边。"""

    def __init__(self, max_files: int = 400, max_file_bytes: int = 2_000_000) -> None:
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes

    def extract_transitions(self, source_root: Path, entrypoints: list[str] | None = None) -> list[StateTransition]:
        files = self._select_files(source_root, entrypoints or [])
        transitions: list[StateTransition] = []
        for path in files:
            if path.stat().st_size > self.max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            transitions.extend(self._parse_marked_transitions(path, text))
            transitions.extend(self._recover_state_assignments(path, text))
        return _dedupe_transitions(transitions)

    def collect_code_evidence(self, source_root: Path, entrypoints: list[str] | None = None, limit: int = 20) -> list[Evidence]:
        files = self._select_files(source_root, entrypoints or [])[:limit]
        evidence: list[Evidence] = []
        interesting = re.compile(r"(state|session|auth|guard|teardown|setup|play|transition)", re.IGNORECASE)
        for path in files:
            if path.stat().st_size > self.max_file_bytes:
                continue
            for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                if interesting.search(line):
                    evidence.append(
                        Evidence(
                            source_type="code",
                            location=f"{path}:{line_no}",
                            excerpt=line.strip()[:400],
                            confidence=0.7,
                        )
                    )
                    if len(evidence) >= limit:
                        return evidence
        return evidence

    def collect_command_handlers(
        self,
        source_root: Path,
        entrypoints: list[str] | None = None,
        prefix: str = "ftp",
    ) -> dict[str, Evidence]:
        """提取 ``ftpUSER(...)`` 这类 C handler，供协议专用保守模型使用。"""

        handlers: dict[str, Evidence] = {}
        pattern = re.compile(
            rf"^\s*(?:static\s+)?(?:int|void)\s+{re.escape(prefix)}(?P<command>[A-Z][A-Z0-9]*)\s*\(",
            re.MULTILINE,
        )
        for path in self._select_files(source_root, entrypoints or []):
            if path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in pattern.finditer(text):
                command = match.group("command")
                line_no = text.count("\n", 0, match.start()) + 1
                handlers.setdefault(
                    command,
                    Evidence(
                        source_type="code_handler",
                        location=f"{path}:{line_no}",
                        excerpt=match.group(0).strip(),
                        confidence=0.65,
                    ),
                )
        return handlers

    def _select_files(self, source_root: Path, entrypoints: list[str]) -> list[Path]:
        if not source_root.exists():
            raise FileNotFoundError(f"source root does not exist: {source_root}")
        if source_root.is_file():
            return [source_root]

        selected: list[Path] = []
        if entrypoints:
            for item in entrypoints:
                candidate = (source_root / item).resolve()
                if candidate.exists() and candidate.is_file():
                    selected.append(candidate)

        if selected:
            # 指定入口点时严格限制扫描边界，避免把依赖库状态误归入目标 FSM。
            return selected[: self.max_files]

        for path in source_root.rglob("*"):
            if len(selected) >= self.max_files:
                break
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS:
                selected.append(path)
        return selected

    def _parse_marked_transitions(self, path: Path, text: str) -> list[StateTransition]:
        transitions: list[StateTransition] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if "PROTOLENS_TRANSITION" not in line:
                continue
            match = TRANSITION_RE.search(line.replace("PROTOLENS_TRANSITION", "TRANSITION"))
            if not match:
                continue
            trigger = match.group("trigger").strip()
            attrs = _parse_transition_attrs(match.group("attrs"))
            evidence = Evidence(
                source_type="code",
                location=f"{path}:{line_no}",
                excerpt=line.strip(),
                confidence=0.97,
            )
            transitions.append(
                StateTransition(
                    source=match.group("source"),
                    target=match.group("target"),
                    trigger=trigger,
                    message_type=trigger.split()[0].upper(),
                    guard=_clean(match.group("guard")) or attrs.get("guard"),
                    action=attrs.get("action"),
                    error_handling=attrs.get("error") or attrs.get("error_handling"),
                    evidence=[evidence],
                    confidence=0.97,
                )
            )
        return transitions

    def _recover_state_assignments(self, path: Path, text: str) -> list[StateTransition]:
        transitions: list[StateTransition] = []
        lines = text.splitlines()
        current_function_by_line = _function_names_by_line(lines)
        for index, line in enumerate(lines):
            assignment = STATE_ASSIGN_RE.search(line)
            if not assignment:
                continue
            target = assignment.group("target")
            if not _looks_like_code_state(target):
                continue
            window_start = max(0, index - 10)
            window_end = min(len(lines), index + 8)
            window = lines[window_start:window_end]
            source = _nearest_source_state(window, index - window_start)
            if not source or source == target:
                continue
            trigger = _nearest_trigger(window, current_function_by_line.get(index + 1, ""))
            if not trigger:
                continue
            location = f"{path}:{index + 1}"
            excerpt = _compact_excerpt(window, index - window_start)
            evidence = Evidence(
                source_type="code_recovered_state",
                location=location,
                excerpt=excerpt,
                confidence=0.56,
            )
            transitions.append(
                StateTransition(
                    source=source,
                    target=target,
                    trigger=trigger,
                    message_type=trigger.split()[0].upper(),
                    error_handling=_infer_error_handling(target, window),
                    evidence=[evidence],
                    confidence=0.56,
                )
            )
        return transitions


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _parse_transition_attrs(raw: str | None) -> dict[str, str]:
    attrs: dict[str, str] = {}
    if not raw:
        return attrs
    for part in raw.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower().replace("-", "_")
        value = value.strip()
        if key and value:
            attrs[key] = value
    return attrs


def _function_names_by_line(lines: list[str]) -> dict[int, str]:
    names: dict[int, str] = {}
    current = ""
    depth = 0
    for line_no, line in enumerate(lines, start=1):
        if depth == 0:
            match = FUNCTION_RE.search(line)
            if match and not line.strip().startswith(("if ", "for ", "while ", "switch ")):
                current = match.group("name")
        if current:
            names[line_no] = current
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            depth = 0
            current = ""
    return names


def _nearest_source_state(lines: list[str], assignment_index: int) -> str | None:
    for offset in range(assignment_index, -1, -1):
        line = lines[offset]
        match = STATE_GUARD_RE.search(line) or STATE_CASE_RE.search(line)
        if match:
            source = match.group("source")
            if _looks_like_code_state(source):
                return source
    return None


def _nearest_trigger(lines: list[str], function_name: str) -> str | None:
    for line in lines:
        for match in COMMAND_LITERAL_RE.finditer(line):
            trigger = match.group("trigger") or match.group("trigger_alt")
            if _looks_like_trigger(trigger):
                return trigger
    return _trigger_from_function_name(function_name)


def _trigger_from_function_name(function_name: str) -> str | None:
    if not function_name:
        return None
    patterns = [
        r"(?:^|_)(?:handle|process|parse|do|on|cmd)_?(?P<trigger>[A-Z][A-Z0-9_.-]{1,})$",
        r"^(?:ftp|rtsp|smtp|http)(?P<trigger>[A-Z][A-Z0-9_.-]{1,})$",
        r"(?:^|_)(?P<trigger>[A-Z][A-Z0-9_.-]{1,})(?:_handler|_cmd)?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, function_name)
        if match and _looks_like_trigger(match.group("trigger")):
            return match.group("trigger")
    return None


def _looks_like_code_state(value: str) -> bool:
    return bool(value and len(value) <= 100 and re.fullmatch(r"[A-Z_][A-Z0-9_]*", value))


def _looks_like_trigger(value: str | None) -> bool:
    return bool(value and len(value) <= 80 and re.fullmatch(r"[A-Z][A-Z0-9_.-]+", value))


def _compact_excerpt(lines: list[str], assignment_index: int) -> str:
    selected = lines[max(0, assignment_index - 2) : assignment_index + 2]
    return " ".join(line.strip() for line in selected if line.strip())[:400]


def _infer_error_handling(target: str, lines: list[str]) -> str | None:
    joined = " ".join(lines).lower()
    if any(term in target.lower() for term in ("ERR", "ERROR", "FAIL", "CLOSE", "RESET")):
        if "reset" in joined or "rst" in joined:
            return "reset connection"
        if "close" in joined or "shutdown" in joined:
            return "close connection"
        return "enter error state"
    if re.search(r"\breturn\s+-[0-9]+\b", joined) or "send_error" in joined or "reply_error" in joined:
        return "reject request"
    if "close(" in joined or "shutdown(" in joined:
        return "close connection"
    if "reset" in joined or "rst" in joined:
        return "reset connection"
    return None


def _dedupe_transitions(transitions: list[StateTransition]) -> list[StateTransition]:
    seen: set[tuple[str, str, str, str | None, str | None, str | None]] = set()
    unique: list[StateTransition] = []
    for transition in transitions:
        key = (
            transition.source,
            transition.trigger,
            transition.target,
            transition.guard,
            transition.action,
            transition.error_handling,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(transition)
    return unique
