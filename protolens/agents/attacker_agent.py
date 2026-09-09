from __future__ import annotations

from protolens.agents.base_agent import AgentContext, BaseAgent
from protolens.fsm.fsm_model import Evidence, ReasoningFinding


class AttackerAgent(BaseAgent):
    name = "attacker"
    role = "attacker"

    def analyze(self, context: AgentContext) -> list[ReasoningFinding]:
        if self.should_use_llm():
            findings = self.analyze_with_llm(
                context,
                system_prompt=(
                    "You are the ProtoLens AttackerAgent. Analyze protocol state machines for "
                    "concrete, testable exploit hypotheses. Do not claim a confirmed vulnerability. "
                    "Return only valid JSON matching the requested schema. Prefer state/transition "
                    "specific findings over generic security advice."
                ),
                task_prompt=(
                    "Find ways an adversarial client could exploit, bypass, or confuse the target "
                    "state or divergent transition. Focus on reachability, guard bypass, malformed "
                    "message sequencing, stale session state, parser recovery, and resource lifecycle."
                ),
            )
            if findings or not self.last_llm_failed():
                return findings
        findings: list[ReasoningFinding] = []
        for divergence in context.divergences:
            if divergence.kind not in {"extra_transition", "guard_mismatch", "state_mismatch"}:
                continue
            state = _infer_state(divergence.impl_element or divergence.spec_element or context.fsm.initial_state)
            confidence = 0.88 if divergence.severity == "P0" else 0.72
            findings.append(
                ReasoningFinding(
                    agent="attacker",
                    state=state,
                    transition=divergence.impl_element or divergence.spec_element,
                    claim=(
                        f"{divergence.kind} may permit state confusion or guard bypass; "
                        "the transition should be fuzzed with valid prefix and malformed boundary inputs."
                    ),
                    confidence=confidence,
                    preconditions=["Reach the source state", "Send the disputed trigger near the conflict boundary"],
                    suggested_tests=[
                        "Replay the shortest valid prefix, then mutate the disputed message.",
                        "Remove or corrupt session/authentication fields around the disputed transition.",
                    ],
                    evidence=list(divergence.evidence),
                )
            )

        if not findings and context.fsm.transitions:
            transition = context.fsm.transitions[0]
            findings.append(
                ReasoningFinding(
                    agent="attacker",
                    state=transition.source,
                    transition=transition.id,
                    claim="No explicit divergence found; start with parser recovery and repeated request mutations.",
                    confidence=0.45,
                    preconditions=["Server accepts baseline seed"],
                    suggested_tests=["Mutate message order and duplicate the first protocol request."],
                    evidence=[
                        Evidence("fsm", transition.id, f"{transition.source} --{transition.trigger}-> {transition.target}", 0.5)
                    ],
                )
            )
        return findings


def _infer_state(label: str) -> str:
    if "--" in label:
        return label.split("--", 1)[0].strip()
    return label.strip() or "START"
