from __future__ import annotations

from protolens.fsm.fsm_model import Divergence, ProtocolFSM


class DirectionGenerator:
    DEFAULT_DIRECTIONS = [
        "Authentication and authorization state",
        "Session lifecycle and teardown",
        "Parser recovery after malformed input",
        "Resource allocation across repeated requests",
        "Error response and partial state commit",
    ]

    def generate(self, fsm: ProtocolFSM, divergences: list[Divergence]) -> list[str]:
        directions = list(self.DEFAULT_DIRECTIONS)
        if any(item.kind in {"extra_transition", "guard_mismatch"} for item in divergences):
            directions.insert(0, "Spec-implementation divergence reachability")
        if any("tls" in state.lower() or "http" in state.lower() for state in fsm.states):
            directions.append("Cross-layer state synchronization")
        return directions
