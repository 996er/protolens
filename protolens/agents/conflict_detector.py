from __future__ import annotations

from collections import defaultdict

from protolens.fsm.fsm_model import Conflict, Divergence, ReasoningFinding


class ConflictDetector:
    """把 FSM 差异和多 Agent 结论归一化为可排序的动态验证任务。"""

    def detect(self, divergences: list[Divergence], findings: list[ReasoningFinding]) -> list[Conflict]:
        conflicts: list[Conflict] = []
        conflicts.extend(self._from_divergences(divergences))
        conflicts.extend(self._from_cross_layer(findings))
        conflicts.extend(self._from_asr(findings))
        conflicts.extend(self._from_unvalidated_attacker(findings))
        return _dedupe_sorted(conflicts)

    def _from_divergences(self, divergences: list[Divergence]) -> list[Conflict]:
        conflicts: list[Conflict] = []
        for divergence in divergences:
            if divergence.kind in {"extra_transition", "guard_mismatch", "state_mismatch", "action_mismatch"}:
                state, transition = _state_and_transition(divergence.impl_element or divergence.spec_element)
                risk = {"P0": 3.0, "P1": 2.0, "P2": 1.0}[divergence.severity]
                conflicts.append(
                    Conflict(
                        kind="fsm_divergence",
                        priority=divergence.severity,
                        state=state,
                        transition=transition,
                        description=divergence.rationale,
                        expected_path=[state],
                        fuzzing_strategy="Reach the divergent source state and mutate the disputed trigger and guard fields.",
                        source_findings=[divergence.id],
                        risk_score=risk,
                    )
                )
        return conflicts

    def _from_cross_layer(self, findings: list[ReasoningFinding]) -> list[Conflict]:
        return [
            Conflict(
                kind="cross_layer_contamination",
                priority="P0",
                state=finding.state,
                transition=finding.transition,
                description=finding.claim,
                expected_path=[finding.state],
                fuzzing_strategy="Generate interleaved multi-layer request sequences around session or connection state changes.",
                source_findings=[finding.id],
                risk_score=2.7 + finding.confidence,
            )
            for finding in findings
            if finding.agent == "cross_layer" and finding.confidence >= 0.65
        ]

    def _from_asr(self, findings: list[ReasoningFinding]) -> list[Conflict]:
        by_state: dict[str, list[ReasoningFinding]] = defaultdict(list)
        for finding in findings:
            by_state[finding.state].append(finding)

        conflicts: list[Conflict] = []
        for state, state_findings in by_state.items():
            attackers = [finding for finding in state_findings if finding.agent == "attacker" and finding.confidence >= 0.7]
            defenders = [finding for finding in state_findings if finding.agent == "defender" and finding.confidence >= 0.7]
            if not attackers or not defenders:
                continue
            attack = max(attackers, key=lambda item: item.confidence)
            defense = max(defenders, key=lambda item: item.confidence)
            conflicts.append(
                Conflict(
                    kind="asr_conflict",
                    priority="P1",
                    state=state,
                    transition=attack.transition or defense.transition,
                    description="Attacker and Defender agents disagree on the effective security of this state.",
                    expected_path=[state],
                    fuzzing_strategy="Empirically verify the claimed protection by corrupting the defended fields at the attack boundary.",
                    source_findings=[attack.id, defense.id],
                    risk_score=1.5 + attack.confidence + defense.confidence,
                )
            )
        return conflicts

    def _from_unvalidated_attacker(self, findings: list[ReasoningFinding]) -> list[Conflict]:
        conflicts: list[Conflict] = []
        for finding in findings:
            if finding.agent == "attacker" and 0.5 <= finding.confidence < 0.7:
                conflicts.append(
                    Conflict(
                        kind="unvalidated_hypothesis",
                        priority="P2",
                        state=finding.state,
                        transition=finding.transition,
                        description=finding.claim,
                        expected_path=[finding.state],
                        fuzzing_strategy="Run a short exploratory campaign around this state to confirm reachability.",
                        source_findings=[finding.id],
                        risk_score=finding.confidence,
                    )
                )
        return conflicts


def _state_and_transition(label: str | None) -> tuple[str, str | None]:
    if not label:
        return "START", None
    if "--" in label:
        state, rest = label.split("--", 1)
        return state.strip(), rest.strip()
    return label.strip(), None


def _dedupe_sorted(conflicts: list[Conflict]) -> list[Conflict]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[Conflict] = []
    for conflict in sorted(conflicts, key=lambda item: (("P0", "P1", "P2").index(item.priority), -item.risk_score, item.id)):
        key = (conflict.kind, conflict.state, conflict.transition)
        if key in seen:
            continue
        seen.add(key)
        result.append(conflict)
    return result
