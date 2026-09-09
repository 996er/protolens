from __future__ import annotations

from pathlib import Path
import re

from protolens.fsm.fsm_model import Evidence, StateTransition

TRANSITION_RE = re.compile(
    r"(?:TRANSITION|transition)\s*:\s*"
    r"(?P<source>[A-Za-z0-9_.-]+)\s*--\s*"
    r"(?P<trigger>[A-Za-z0-9_ .:/-]+?)\s*"
    r"(?:\[(?P<guard>[^\]]+)\])?\s*->\s*"
    r"(?P<target>[A-Za-z0-9_.-]+)"
    r"(?P<attrs>(?:\s*;\s*[A-Za-z_][A-Za-z0-9_-]*\s*=\s*[^;]+)*)",
)


NL_TRANSITION_PATTERNS = [
    re.compile(
        r"\b(?:in|from)\s+(?:the\s+)?(?P<source>[A-Za-z0-9_.-]+)\s+state\b"
        r"(?P<body>.{0,260}?)"
        r"\b(?:upon|on|after|when|while)?\s*(?:receiv(?:e|es|ing)|processing|processes|accepting|accepts)\s+"
        r"(?:a|an|the\s+)?(?P<trigger>[A-Z][A-Z0-9_.-]{1,})\b"
        r"(?P<body2>.{0,260}?)"
        r"\b(?:enter|enters|transition(?:s)?|move(?:s)?|go(?:es)?|return(?:s)?)\s+"
        r"(?:to|into|back\s+to)?\s*(?:the\s+)?(?P<target>[A-Za-z0-9_.-]+)\s+state\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bfrom\s+(?:the\s+)?(?P<source>[A-Za-z0-9_.-]+)\s+state\b"
        r"(?P<body>.{0,260}?)"
        r"\b(?P<trigger>[A-Z][A-Z0-9_.-]{1,})\b"
        r"(?P<body2>.{0,260}?)"
        r"\bto\s+(?:the\s+)?(?P<target>[A-Za-z0-9_.-]+)\s+state\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:enter|enters|transition(?:s)?|move(?:s)?|go(?:es)?)\s+from\s+"
        r"(?:the\s+)?(?P<source>[A-Za-z0-9_.-]+)\s+state\s+to\s+"
        r"(?:the\s+)?(?P<target>[A-Za-z0-9_.-]+)\s+state\b"
        r"(?P<body>.{0,260}?)"
        r"\b(?:upon|on|after|when|while)?\s*(?:receiv(?:e|es|ing)|processing|processes|accepting|accepts)?\s*"
        r"(?P<trigger>[A-Z][A-Z0-9_.-]{1,})\b",
        re.IGNORECASE,
    ),
]


class RFCParser:
    """规范解析器：读取显式 transition，并保守抽取常见 RFC 自然语言状态句式。"""

    def __init__(self, max_bytes: int = 5_000_000) -> None:
        self.max_bytes = max_bytes

    def parse_transitions(self, paths: list[Path], protocol: str) -> list[StateTransition]:
        transitions: list[StateTransition] = []
        for path in paths:
            text = self._read_text(path)
            transitions.extend(self._parse_marked_transitions(path, text))
            transitions.extend(self._parse_natural_language_transitions(path, text))

        if transitions:
            return _dedupe_transitions(transitions)
        # 无标记时仅为 RTSP 提供低置信度基线，不能冒充完整 RFC 语义抽取。
        if protocol.lower() == "rtsp":
            return self._rtsp_fallback(paths)
        return []

    def _read_text(self, path: Path) -> str:
        if not path.exists():
            raise FileNotFoundError(f"spec path does not exist: {path}")
        if path.stat().st_size > self.max_bytes:
            raise ValueError(f"spec file is too large for MVP parser: {path}")
        return path.read_text(encoding="utf-8", errors="replace")

    def _parse_marked_transitions(self, path: Path, text: str) -> list[StateTransition]:
        transitions: list[StateTransition] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            match = TRANSITION_RE.search(line)
            if not match:
                continue
            trigger = match.group("trigger").strip()
            attrs = _parse_attrs(match.group("attrs"))
            evidence = Evidence(
                source_type="spec",
                location=f"{path}:{line_no}",
                excerpt=line.strip(),
                confidence=0.98,
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
                    confidence=0.98,
                )
            )
        return transitions

    def _parse_natural_language_transitions(self, path: Path, text: str) -> list[StateTransition]:
        transitions: list[StateTransition] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if "state" not in line.lower():
                continue
            for sentence in _split_sentences(line):
                for pattern in NL_TRANSITION_PATTERNS:
                    for match in pattern.finditer(sentence):
                        source = _clean_token(match.group("source"))
                        trigger_raw = _clean_token(match.group("trigger"))
                        trigger = trigger_raw.upper()
                        target = _clean_token(match.group("target"))
                        if (
                            not _looks_like_state(source)
                            or not _looks_like_state(target)
                            or not _looks_like_trigger(trigger_raw)
                        ):
                            continue
                        evidence = Evidence(
                            source_type="spec_nl",
                            location=f"{path}:{line_no}",
                            excerpt=sentence.strip(),
                            confidence=0.64,
                        )
                        transitions.append(
                            StateTransition(
                                source=source,
                                target=target,
                                trigger=trigger,
                                message_type=trigger.split()[0].upper(),
                                error_handling=_infer_error_handling(sentence),
                                evidence=[evidence],
                                confidence=0.64,
                            )
                        )
        return transitions

    def _rtsp_fallback(self, paths: list[Path]) -> list[StateTransition]:
        location = ", ".join(str(path) for path in paths)
        evidence = Evidence(
            source_type="spec",
            location=location,
            excerpt="RTSP conservative fallback transition model",
            confidence=0.55,
        )
        return [
            StateTransition("START", "READY_FOR_SETUP", "DESCRIBE", "DESCRIBE", evidence=[evidence], confidence=0.55),
            StateTransition(
                "READY_FOR_SETUP",
                "READY",
                "SETUP",
                "SETUP",
                guard="valid transport and media resource",
                evidence=[evidence],
                confidence=0.55,
            ),
            StateTransition("READY", "PLAYING", "PLAY", "PLAY", guard="valid session", evidence=[evidence], confidence=0.55),
            StateTransition("PLAYING", "READY", "PAUSE", "PAUSE", guard="valid session", evidence=[evidence], confidence=0.55),
            StateTransition("READY", "TEARDOWN", "TEARDOWN", "TEARDOWN", guard="valid session", evidence=[evidence], confidence=0.55),
            StateTransition("PLAYING", "TEARDOWN", "TEARDOWN", "TEARDOWN", guard="valid session", evidence=[evidence], confidence=0.55),
        ]


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _parse_attrs(raw: str | None) -> dict[str, str]:
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


def _infer_error_handling(sentence: str) -> str | None:
    lower = sentence.lower()
    if any(term in lower for term in ("tcp reset", "connection reset", "rst")):
        return "reset connection"
    if any(term in lower for term in ("close the connection", "connection is closed", "disconnect")):
        return "close connection"
    if any(term in lower for term in ("reject", "error response", "4xx", "5xx", "invalid")):
        return "reject request"
    if any(term in lower for term in ("ignore", "silently discard")):
        return "ignore request"
    return None


def _clean_token(value: str) -> str:
    return value.strip(" \t\r\n`'\".,;:()[]{}")


def _looks_like_state(value: str) -> bool:
    if not value or len(value) > 80:
        return False
    if value.lower() in {"the", "this", "next", "current", "same", "new", "valid", "invalid"}:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value))


def _looks_like_trigger(value: str) -> bool:
    if not value or len(value) > 80:
        return False
    # RFC request methods and event names are conventionally uppercase; reject ordinary prose words.
    return bool(re.fullmatch(r"[A-Z][A-Z0-9_.-]+", value))


def _split_sentences(line: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?<=[.;])\s+", line) if part.strip()]


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
