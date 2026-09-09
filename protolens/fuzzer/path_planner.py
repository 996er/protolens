from __future__ import annotations

from collections import deque
import hashlib
import json
import re

from protolens.fsm.fsm_model import Conflict, PlannedStatePath, ProtocolFSM, StateTransition


class PathPlanner:
    """Generate bounded graph candidates; execution establishes feasibility."""

    def __init__(self, max_candidates: int = 3, max_depth: int = 16, max_expansions: int = 2000) -> None:
        self.max_candidates = max_candidates
        self.max_depth = max_depth
        self.max_expansions = max_expansions

    def plan(self, fsm: ProtocolFSM, conflicts: list[Conflict]) -> list[PlannedStatePath]:
        return [path for conflict in conflicts for path in self.candidates(fsm, conflict)]

    def plan_one(self, fsm: ProtocolFSM, conflict: Conflict) -> PlannedStatePath:
        return self.candidates(fsm, conflict)[0]

    def candidates(self, fsm: ProtocolFSM, conflict: Conflict) -> list[PlannedStatePath]:
        target = conflict.state
        if target not in fsm.states:
            return [self._failed_path(fsm, conflict, f"target state {target!r} is absent from unified FSM")]

        # BFS orders candidates by length; execution may favor a longer prefix.
        found = self._candidate_prefixes(fsm, fsm.initial_state, target)
        if not found:
            return [self._failed_path(fsm, conflict, f"no candidate to {target!r} within configured search bounds")]
        return [self._make_path(fsm, conflict, states, transitions) for states, transitions in found]

    def _failed_path(self, fsm: ProtocolFSM, conflict: Conflict, reason: str) -> PlannedStatePath:
        identity = json.dumps([conflict.id, fsm.initial_state, conflict.state, conflict.transition, reason],
                              ensure_ascii=True)
        return PlannedStatePath(
            conflict_id=conflict.id,
            states=[fsm.initial_state],
            messages=[],
            reachable=False,
            reason=reason,
            candidate_id="path_" + hashlib.sha256(identity.encode()).hexdigest()[:24],
            calibration={"status": "not_executable", "accepted_prefix_length": 0, "state_verified": False},
        )

    def _make_path(self, fsm: ProtocolFSM, conflict: Conflict, states: list[str], transitions: list[StateTransition]) -> PlannedStatePath:
        target = conflict.state
        disputed = _find_disputed_transition(fsm, target, conflict.transition)
        if disputed and (not transitions or transitions[-1].id != disputed.id):
            transitions = transitions + [disputed]
            states = states + [disputed.target]
        guards = [transition.guard for transition in transitions if transition.guard]
        messages = [transition.trigger for transition in transitions]
        identity = json.dumps([conflict.id, states, [item.id for item in transitions], messages, guards], ensure_ascii=True)
        if conflict.transition:
            mutation_points = [max(len(messages) - 1, 0)]
        else:
            mutation_points = list(range(max(len(messages) - 1, 0), len(messages)))
        return PlannedStatePath(
            conflict_id=conflict.id,
            states=states,
            messages=messages,
            required_guards=guards,
            mutation_points=mutation_points,
            reachable=True,
            reason="graph candidate; guards and runtime state are not yet verified",
            candidate_id="path_" + hashlib.sha256(identity.encode()).hexdigest()[:24],
            transition_ids=[item.id for item in transitions],
            calibration={"status": "candidate", "accepted_prefix_length": 0, "state_verified": False},
        )

    def _candidate_prefixes(self, fsm: ProtocolFSM, start: str, target: str) -> list[tuple[list[str], list[StateTransition]]]:
        queue: deque[tuple[str, list[str], list[StateTransition]]] = deque([(start, [start], [])])
        found = []
        seen: set[str] = set()
        expansions = 0
        while queue and len(found) < self.max_candidates and expansions < self.max_expansions:
            state, states, transitions = queue.popleft()
            expansions += 1
            if state == target:
                identity = json.dumps([states, [item.id for item in transitions],
                                       [item.trigger for item in transitions]], ensure_ascii=True)
                if identity not in seen:
                    seen.add(identity)
                    found.append((states, transitions))
                continue
            if len(transitions) >= self.max_depth:
                continue
            for edge in fsm.outgoing(state):
                # One visit per edge permits state-changing self loops without unbounded cycles.
                if any(item.id == edge.id for item in transitions):
                    continue
                if len(queue) + expansions >= self.max_expansions:
                    break
                queue.append((edge.target, states + [edge.target], transitions + [edge]))
        return found

def _find_disputed_transition(fsm: ProtocolFSM, source: str, label: str | None) -> StateTransition | None:
    if not label:
        return None
    trigger, target = _parse_transition_label(label)
    for transition in fsm.outgoing(source):
        trigger_matches = not trigger or transition.trigger.lower() == trigger.lower()
        target_matches = not target or transition.target.lower() == target.lower()
        if trigger_matches and target_matches:
            return transition
    return None


def _parse_transition_label(label: str) -> tuple[str | None, str | None]:
    cleaned = label.split(" guard=", 1)[0].strip()
    if "--" in cleaned:
        cleaned = cleaned.split("--", 1)[1].strip()
    match = re.match(r"(?P<trigger>.+?)-?>\s*(?P<target>[A-Za-z0-9_.-]+)$", cleaned)
    if match:
        return match.group("trigger").strip().strip("-").strip(), match.group("target").strip()
    if "->" in cleaned:
        trigger, target = cleaned.split("->", 1)
        return trigger.strip(), target.strip()
    return cleaned.split()[0] if cleaned.split() else None, None
