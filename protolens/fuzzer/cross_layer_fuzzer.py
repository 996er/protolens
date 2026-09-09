from __future__ import annotations

from protolens.fsm.fsm_model import Conflict, PlannedStatePath


class CrossLayerFuzzer:
    """生成跨层测试意图；当前纯 seed 后端无法表达 TCP reset 等传输层动作。"""

    def synthesize_interleavings(self, conflicts: list[Conflict]) -> list[PlannedStatePath]:
        paths: list[PlannedStatePath] = []
        for conflict in conflicts:
            if conflict.kind != "cross_layer_contamination":
                continue
            paths.append(
                PlannedStatePath(
                    conflict_id=conflict.id,
                    states=[conflict.state, conflict.state],
                    messages=["TLS_RENEGOTIATION_OR_CONNECTION_RESET", "STALE_SESSION_REQUEST"],
                    required_guards=["session or connection context exists"],
                    mutation_points=[0, 1],
                    reachable=False,
                    reason="requires a transport-aware harness; plain AFLNet corpus cannot encode connection reset",
                )
            )
        return paths

    def transport_harness_manifest(self, paths: list[PlannedStatePath]) -> dict[str, object]:
        actions: list[dict[str, object]] = []
        for path in paths:
            if path.reachable:
                continue
            lower_reason = path.reason.lower()
            messages = {message.upper() for message in path.messages}
            if (
                "transport-aware harness" not in lower_reason
                and not {"TCP_RESET", "TLS_RENEGOTIATION_OR_CONNECTION_RESET", "HALF_CLOSE"} & messages
            ):
                continue
            actions.append(
                {
                    "conflict_id": path.conflict_id,
                    "states": path.states,
                    "messages": path.messages,
                    "required_guards": path.required_guards,
                    "executable_by_aflnet_seed": False,
                    "required_harness_capabilities": [
                        "open and close independent TCP connections",
                        "inject TCP reset or half-close events",
                        "drive TLS renegotiation or equivalent handshake transitions",
                        "preserve protocol/session context across transport events",
                    ],
                    "reason": path.reason,
                }
            )
        return {
            "format": "protolens.transport_harness_manifest.v1",
            "plain_aflnet_seed_supported": False,
            "actions": actions,
        }
