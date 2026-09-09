from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal
import re

Priority = Literal["P0", "P1", "P2"]


def stable_id(*parts: str) -> str:
    """把可读字段转换为稳定、可用于文件名和交叉引用的标识符。"""

    raw = "__".join(part for part in parts if part)
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw.strip()).strip("_")
    return normalized[:160] or "item"


@dataclass
class Evidence:
    source_type: str
    location: str
    excerpt: str
    confidence: float = 1.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        return cls(
            source_type=str(data.get("source_type", "unknown")),
            location=str(data.get("location", "")),
            excerpt=str(data.get("excerpt", "")),
            confidence=float(data.get("confidence", 1.0)),
        )


@dataclass
class State:
    name: str
    description: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 1.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "State":
        return cls(
            name=str(data["name"]),
            description=str(data.get("description", "")),
            evidence=[Evidence.from_dict(item) for item in data.get("evidence", [])],
            confidence=float(data.get("confidence", 1.0)),
        )


@dataclass
class StateTransition:
    source: str
    target: str
    trigger: str
    message_type: str | None = None
    guard: str | None = None
    action: str | None = None
    error_handling: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 1.0
    id: str = ""

    def __post_init__(self) -> None:
        self.source = self.source.strip()
        self.target = self.target.strip()
        self.trigger = self.trigger.strip()
        if not self.message_type:
            self.message_type = self.trigger.split()[0].upper() if self.trigger else None
        if not self.id:
            self.id = stable_id(self.source, self.trigger, self.target)

    @property
    def match_key(self) -> tuple[str, str, str]:
        return (self.source.lower(), self.trigger.lower(), self.target.lower())

    @property
    def loose_key(self) -> tuple[str, str]:
        return (self.source.lower(), self.trigger.lower())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StateTransition":
        return cls(
            source=str(data["source"]),
            target=str(data["target"]),
            trigger=str(data["trigger"]),
            message_type=data.get("message_type"),
            guard=data.get("guard"),
            action=data.get("action"),
            error_handling=data.get("error_handling"),
            evidence=[Evidence.from_dict(item) for item in data.get("evidence", [])],
            confidence=float(data.get("confidence", 1.0)),
            id=str(data.get("id", "")),
        )


@dataclass
class ProtocolFSM:
    """ProtoLens 在各阶段共享的协议状态机中间表示。"""

    protocol: str
    states: dict[str, State]
    transitions: list[StateTransition]
    initial_state: str
    version: str | None = None
    terminal_states: set[str] = field(default_factory=set)
    error_states: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_state(self, name: str, description: str = "", evidence: Evidence | None = None) -> None:
        if name not in self.states:
            self.states[name] = State(name=name, description=description)
        if evidence:
            self.states[name].evidence.append(evidence)

    def add_transition(self, transition: StateTransition) -> None:
        self.add_state(transition.source)
        self.add_state(transition.target)
        for existing in self.transitions:
            if existing.match_key != transition.match_key:
                continue
            # 规范与实现可能描述同一条边；合并证据而不是静默丢弃后加入的一侧。
            existing.evidence.extend(item for item in transition.evidence if item not in existing.evidence)
            existing.confidence = max(existing.confidence, transition.confidence)
            existing.guard = existing.guard or transition.guard
            existing.action = existing.action or transition.action
            existing.error_handling = existing.error_handling or transition.error_handling
            return
        self.transitions.append(transition)

    def outgoing(self, state: str) -> list[StateTransition]:
        return [transition for transition in self.transitions if transition.source == state]

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "version": self.version,
            "states": {name: _to_plain(state) for name, state in sorted(self.states.items())},
            "transitions": [_to_plain(transition) for transition in self.transitions],
            "initial_state": self.initial_state,
            "terminal_states": sorted(self.terminal_states),
            "error_states": sorted(self.error_states),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProtocolFSM":
        return cls(
            protocol=str(data["protocol"]),
            version=data.get("version"),
            states={name: State.from_dict(item) for name, item in data.get("states", {}).items()},
            transitions=[StateTransition.from_dict(item) for item in data.get("transitions", [])],
            initial_state=str(data.get("initial_state", "START")),
            terminal_states=set(data.get("terminal_states", [])),
            error_states=set(data.get("error_states", [])),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class Divergence:
    kind: Literal[
        "missing_transition",
        "extra_transition",
        "guard_mismatch",
        "state_mismatch",
        "action_mismatch",
        "error_handling_mismatch",
    ]
    spec_element: str | None
    impl_element: str | None
    severity: Priority
    rationale: str
    evidence: list[Evidence] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(self.kind, self.spec_element or "", self.impl_element or "")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Divergence":
        return cls(
            kind=data["kind"],
            spec_element=data.get("spec_element"),
            impl_element=data.get("impl_element"),
            severity=data.get("severity", "P2"),
            rationale=str(data.get("rationale", "")),
            evidence=[Evidence.from_dict(item) for item in data.get("evidence", [])],
            id=str(data.get("id", "")),
        )


@dataclass
class ReasoningFinding:
    agent: Literal["attacker", "defender", "cross_layer"]
    state: str
    transition: str | None
    claim: str
    confidence: float
    preconditions: list[str] = field(default_factory=list)
    suggested_tests: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(self.agent, self.state, self.transition or "", self.claim[:48])

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReasoningFinding":
        return cls(
            agent=data["agent"],
            state=str(data["state"]),
            transition=data.get("transition"),
            claim=str(data.get("claim", "")),
            confidence=float(data.get("confidence", 0.0)),
            preconditions=[str(item) for item in data.get("preconditions", [])],
            suggested_tests=[str(item) for item in data.get("suggested_tests", [])],
            evidence=[Evidence.from_dict(item) for item in data.get("evidence", [])],
            id=str(data.get("id", "")),
        )


@dataclass
class Conflict:
    kind: Literal[
        "asr_conflict",
        "fsm_divergence",
        "cross_layer_contamination",
        "unvalidated_hypothesis",
    ]
    priority: Priority
    state: str
    transition: str | None
    description: str
    expected_path: list[str]
    fuzzing_strategy: str
    source_findings: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = stable_id(self.kind, self.priority, self.state, self.transition or "")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Conflict":
        return cls(
            kind=data["kind"],
            priority=data.get("priority", "P2"),
            state=str(data["state"]),
            transition=data.get("transition"),
            description=str(data.get("description", "")),
            expected_path=[str(item) for item in data.get("expected_path", [])],
            fuzzing_strategy=str(data.get("fuzzing_strategy", "")),
            source_findings=[str(item) for item in data.get("source_findings", [])],
            risk_score=float(data.get("risk_score", 0.0)),
            id=str(data.get("id", "")),
        )


@dataclass
class PlannedStatePath:
    conflict_id: str
    states: list[str]
    messages: list[str]
    required_guards: list[str] = field(default_factory=list)
    mutation_points: list[int] = field(default_factory=list)
    reachable: bool = True
    reason: str = ""
    candidate_id: str = ""
    transition_ids: list[str] = field(default_factory=list)
    calibration: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PlannedStatePath":
        return cls(
            conflict_id=str(data["conflict_id"]),
            states=[str(item) for item in data.get("states", [])],
            messages=[str(item) for item in data.get("messages", [])],
            required_guards=[str(item) for item in data.get("required_guards", [])],
            mutation_points=[int(item) for item in data.get("mutation_points", [])],
            reachable=bool(data.get("reachable", True)),
            reason=str(data.get("reason", "")),
            candidate_id=str(data.get("candidate_id", "")),
            transition_ids=[str(item) for item in data.get("transition_ids", [])],
            calibration=dict(data.get("calibration", {})),
        )


@dataclass
class SeedIntent:
    seed_id: str
    conflict_id: str
    family_id: str
    variant: str
    objective: str
    states: list[str]
    messages: list[str]
    mutation_points: list[int] = field(default_factory=list)
    required_guards: list[str] = field(default_factory=list)
    expected_feedback: list[str] = field(default_factory=list)
    priority: int = 100
    reachable: bool = True
    reason: str = ""
    source_path_index: int | None = None
    source_candidate_id: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SeedIntent":
        return cls(
            seed_id=str(data["seed_id"]),
            conflict_id=str(data["conflict_id"]),
            family_id=str(data.get("family_id", "")),
            variant=str(data.get("variant", "baseline_valid_prefix")),
            objective=str(data.get("objective", "")),
            states=[str(item) for item in data.get("states", [])],
            messages=[str(item) for item in data.get("messages", [])],
            mutation_points=[int(item) for item in data.get("mutation_points", [])],
            required_guards=[str(item) for item in data.get("required_guards", [])],
            expected_feedback=[str(item) for item in data.get("expected_feedback", [])],
            priority=int(data.get("priority", 100)),
            reachable=bool(data.get("reachable", True)),
            reason=str(data.get("reason", "")),
            source_path_index=(
                int(data["source_path_index"])
                if data.get("source_path_index") is not None
                else None
            ),
            source_candidate_id=str(data.get("source_candidate_id", "")),
        )


@dataclass
class FuzzResult:
    mode: str
    command: list[str]
    corpus_dir: str
    dictionary_path: str
    output_dir: str
    exit_code: int | None = None
    crashes: list[str] = field(default_factory=list)
    hangs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    process_id: int | None = None
    started_at: str | None = None
    completed_at: str | None = None


def _to_plain(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, list):
        return [_to_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _to_plain(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return {key: _to_plain(item) for key, item in asdict(value).items()}
    return value
