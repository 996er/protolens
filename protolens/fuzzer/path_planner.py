from __future__ import annotations

from collections import defaultdict
import hashlib
import heapq
from itertools import count
import json
import re

from protolens.fsm.fsm_model import Conflict, PlannedStatePath, ProtocolFSM, StateTransition
from protolens.utils.client_messages import is_client_send_transition, transition_client_seed_message


class PathPlanner:
    """Generate bounded graph candidates; execution establishes feasibility."""

    VERSION = "directed-paths-v2-source-entry"

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

        disputed = _find_disputed_transition(fsm, target, conflict.transition)
        start = self._entry_state(fsm, target, disputed)
        if disputed and disputed.source != target:
            return [self._failed_path(fsm, conflict, "disputed transition does not start at conflict state", start)]
        if disputed and is_client_send_transition(disputed) and not transition_client_seed_message(disputed, fsm.protocol):
            return [self._failed_path(fsm, conflict,
                                     f"client transition {disputed.id!r} has no encodable trigger: {disputed.trigger!r}", start)]
        found = self._candidate_prefixes(
            fsm, start, target,
            require_message=not (disputed and transition_client_seed_message(disputed, fsm.protocol)),
        )
        if not found:
            unsupported = sum(is_client_send_transition(edge) and not transition_client_seed_message(edge, fsm.protocol)
                              for edge in fsm.transitions)
            return [self._failed_path(
                fsm, conflict, f"no candidate from {start!r} to {target!r} within configured search bounds "
                f"(client-request depth={self.max_depth}, expansions={self.max_expansions}); "
                f"excluded {unsupported} client transitions with unencodable triggers", start,
            )]
        return [self._make_path(fsm, conflict, states, transitions) for states, transitions in found]

    @staticmethod
    def _entry_state(fsm: ProtocolFSM, target: str, disputed: StateTransition | None) -> str:
        # A semantic union can retain distinct spec and implementation entries.
        # Use the recorded source entry without inventing a bridge between them.
        entries = fsm.metadata.get("input_initial_states", {})
        side = "impl"
        sources = fsm.metadata.get("state_sources", {}).get(target, [])
        if sources and not any(row.get("side") == "impl" for row in sources):
            side = "spec"
        if disputed:
            for row in fsm.metadata.get("transition_sources", []):
                if row.get("unified_transition_id") == disputed.id:
                    side = "impl" if row.get("impl_transition_ids") else "spec"
                    break
        return entries.get(side, fsm.initial_state)

    def _failed_path(self, fsm: ProtocolFSM, conflict: Conflict, reason: str, start: str | None = None) -> PlannedStatePath:
        start = start if start is not None else fsm.initial_state
        identity = json.dumps([conflict.id, start, conflict.state, conflict.transition, reason],
                              ensure_ascii=True)
        return PlannedStatePath(
            conflict_id=conflict.id,
            states=[start],
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
        client_steps = [
            (transition, message)
            for transition in transitions
            for message in [transition_client_seed_message(transition, fsm.protocol)]
            if message
        ]
        messages = [message for _, message in client_steps]
        transition_ids = [transition.id for transition, _ in client_steps]
        identity = json.dumps([conflict.id, states, [item.id for item in transitions], messages, guards], ensure_ascii=True)
        if not messages:
            mutation_points = []
        elif conflict.transition:
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
            reason=("graph candidate; guards and runtime state are not yet verified" if messages else
                    "selected graph path contains only server/internal events; no encodable client request"),
            candidate_id="path_" + hashlib.sha256(identity.encode()).hexdigest()[:24],
            transition_ids=transition_ids,
            calibration={"status": "candidate" if messages else "not_executable",
                         "accepted_prefix_length": 0, "state_verified": False},
        )

    def _candidate_prefixes(
        self, fsm: ProtocolFSM, start: str, target: str, *, require_message: bool = False,
    ) -> list[tuple[list[str], list[StateTransition]]]:
        outgoing: dict[str, list[StateTransition]] = defaultdict(list)
        incoming: dict[str, list[StateTransition]] = defaultdict(list)
        costs = {}
        for edge in fsm.transitions:
            client = is_client_send_transition(edge)
            # Never silently omit an unsupported client prerequisite from a seed.
            if client and not transition_client_seed_message(edge, fsm.protocol):
                continue
            costs[edge.id] = int(client)
            outgoing[edge.source].append(edge)
            incoming[edge.target].append(edge)

        # Exact reverse distances prune dead components and guide candidates
        # toward the target before loops consume the path-enumeration budget.
        # Internal steps consume graph work, but not the client-request depth.
        # Track whether a client request has occurred. Otherwise zero-request
        # internal cycles can outrank every useful path until the budget ends.
        goals = [(target, True)] if require_message else [(target, False), (target, True)]
        distances = {goal: (0, 0) for goal in goals}
        pending = [(0, 0, *goal) for goal in goals]
        heapq.heapify(pending)
        while pending:
            requests, hops, state, has_request = heapq.heappop(pending)
            if distances[state, has_request] != (requests, hops):
                continue
            for edge in incoming[state]:
                cost = costs[edge.id]
                if cost and not has_request:
                    continue
                previous_flags = (False, True) if cost else (has_request,)
                for previous_flag in previous_flags:
                    previous = (edge.source, previous_flag)
                    distance = (requests + cost, hops + 1)
                    if previous not in distances or distance < distances[previous]:
                        distances[previous] = distance
                        heapq.heappush(pending, (*distance, *previous))
        initial = (start, False)
        if initial not in distances:
            if require_message:
                # Keep a graph-only diagnostic when the component has no
                # client path at all; never fabricate a request for it.
                return self._candidate_prefixes(fsm, start, target)
            return []
        if distances[initial][0] > self.max_depth:
            return []

        sequence = count()
        queue = [(*distances[initial], next(sequence), 0, start, [start], [])]
        found = []
        seen: set[str] = set()
        expansions = 0
        while queue and len(found) < self.max_candidates and expansions < self.max_expansions:
            _, _, _, requests, state, states, transitions = heapq.heappop(queue)
            expansions += 1
            if state == target and (not require_message or requests):
                identity = json.dumps([states, [item.id for item in transitions],
                                       [item.trigger for item in transitions]], ensure_ascii=True)
                if identity not in seen:
                    seen.add(identity)
                    found.append((states, transitions))
                continue
            for edge in outgoing[state]:
                # One visit per edge permits state-changing self loops without unbounded cycles.
                if any(item.id == edge.id for item in transitions):
                    continue
                next_requests = requests + costs[edge.id]
                next_node = (edge.target, bool(next_requests))
                if next_node not in distances:
                    continue
                remaining_requests, remaining_hops = distances[next_node]
                if next_requests + remaining_requests > self.max_depth:
                    continue
                heapq.heappush(queue, (
                    next_requests + remaining_requests, len(transitions) + 1 + remaining_hops,
                    next(sequence), next_requests, edge.target,
                    states + [edge.target], transitions + [edge],
                ))
            # Retain the best frontier entries rather than whichever edges
            # happened to occur first in the serialized FSM.
            capacity = self.max_expansions - expansions
            if len(queue) > capacity:
                queue = heapq.nsmallest(capacity, queue)
                heapq.heapify(queue)
        return found

def _find_disputed_transition(fsm: ProtocolFSM, source: str, label: str | None) -> StateTransition | None:
    if not label:
        return None
    for transition in fsm.transitions:
        if transition.id == label:
            return transition
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
