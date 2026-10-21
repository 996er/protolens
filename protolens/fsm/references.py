from __future__ import annotations

from collections import defaultdict
import re

from protolens.fsm.fsm_model import ProtocolFSM, StateTransition


class FSMReferenceResolver:
    """Resolve exact references through merger provenance, rejecting ambiguity."""

    def __init__(self, fsm: ProtocolFSM) -> None:
        self.fsm = fsm
        self.transitions = {edge.id: edge for edge in fsm.transitions}
        self.states: dict[tuple[str | None, str], set[str]] = defaultdict(set)
        self.edges: dict[tuple[str | None, str], set[str]] = defaultdict(set)
        for unified, sources in fsm.metadata.get("state_sources", {}).items():
            for source in sources:
                self.states[(source["side"], source["name"])].add(unified)
                self.states[(None, source["name"])].add(unified)
        for source in fsm.metadata.get("transition_sources", []):
            unified = source["unified_transition_id"]
            for side in ("spec", "impl"):
                for original in source.get(f"{side}_transition_ids", []):
                    self.edges[(side, original)].add(unified)
                    self.edges[(None, original)].add(unified)

    @staticmethod
    def _one(matches: set[str], kind: str, reference: str) -> str:
        if len(matches) != 1:
            reason = "ambiguous" if matches else "unknown"
            raise ValueError(f"{reason} {kind} reference {reference!r}: {sorted(matches)}")
        return next(iter(matches))

    def _matches(self, reference: str, side: str | None, *, state: bool) -> set[str]:
        aliases = self.states if state else self.edges
        canonical = self.fsm.states if state else self.transitions
        matches = set(aliases.get((side, reference), set()))
        # Side-scoped provenance takes precedence over a same-spelled ID.
        if not (side and matches) and reference in canonical:
            matches.add(reference)
        return matches

    def state(self, reference: str, side: str | None = None) -> str:
        name = self._one(self._matches(reference, side, state=True), "state", reference)
        if name not in self.fsm.states:
            raise ValueError(f"state mapping for {reference!r} points to absent state {name!r}")
        return name

    def transition(self, reference: str, side: str | None = None) -> StateTransition:
        matches = self._matches(reference, side, state=False)
        if not matches:
            # Older findings used complete labels rather than transition IDs.
            label = re.fullmatch(r"(.+?)\s+--(.+?)->\s*(.+?)(?:\s+guard=.*)?", reference)
            if label:
                source = self.state(label[1].strip(), side)
                target = self.state(label[3].strip(), side)
                matches = {edge.id for edge in self.fsm.transitions
                           if edge.source == source and edge.target == target
                           and edge.trigger == label[2].strip()}
        name = self._one(matches, "transition", reference)
        edge = self.transitions.get(name)
        if edge is None:
            raise ValueError(f"transition mapping for {reference!r} points to absent transition {name!r}")
        if edge.source not in self.fsm.states or edge.target not in self.fsm.states:
            raise ValueError(f"transition {name!r} has an endpoint absent from unified FSM")
        return edge

    def element(self, reference: str | None, side: str) -> tuple[str, str | None]:
        if not reference:
            raise ValueError(f"missing {side} element reference")
        states = self._matches(reference, side, state=True)
        edges = self._matches(reference, side, state=False)
        if states and edges:
            raise ValueError(f"ambiguous state/transition reference {reference!r} on {side} side")
        if states:
            return self.state(reference, side), None
        edge = self.transition(reference, side)
        return edge.source, edge.id

    def pair(self, state: str, transition: str | None) -> tuple[str, str | None]:
        canonical_state = self.state(state)
        if not transition:
            return canonical_state, None
        edge = self.transition(transition)
        if edge.source != canonical_state:
            raise ValueError(f"transition {edge.id!r} starts at {edge.source!r}, not state {canonical_state!r}")
        return canonical_state, edge.id
