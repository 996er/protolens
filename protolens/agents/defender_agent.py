from __future__ import annotations

from protolens.agents.base_agent import AgentContext, BaseAgent
from protolens.fsm.fsm_model import ReasoningFinding


class DefenderAgent(BaseAgent):
    name = "defender"
    role = "defender"

    def analyze(self, context: AgentContext) -> list[ReasoningFinding]:
        if self.should_use_llm():
            findings = self.analyze_with_llm(
                context,
                system_prompt=(
                    "You are the ProtoLens DefenderAgent. Analyze the implementation and FSM for "
                    "guards, validation, recovery, state reset, authorization checks, and other "
                    "protections. Do not overstate safety. Return only valid JSON matching the "
                    "requested schema."
                ),
                task_prompt=(
                    "Identify protections that should prevent the attacker hypotheses or the listed "
                    "FSM divergences from being exploitable. Each finding must name the state, the "
                    "transition when applicable, evidence, confidence, and concrete tests that would "
                    "verify the protection empirically."
                ),
            )
            if findings or not self.last_llm_failed():
                return findings
        findings: list[ReasoningFinding] = []
        guard_terms = ("valid", "session", "auth", "token", "state", "transport")
        for transition in context.fsm.transitions:
            if not transition.guard:
                continue
            confidence = 0.82 if any(term in transition.guard.lower() for term in guard_terms) else 0.62
            findings.append(
                ReasoningFinding(
                    agent="defender",
                    state=transition.source,
                    transition=transition.id,
                    claim=f"Transition appears protected by guard: {transition.guard}",
                    confidence=confidence,
                    preconditions=[transition.guard],
                    suggested_tests=["Verify that corrupted guard material is rejected without state mutation."],
                    evidence=list(transition.evidence),
                )
            )

        for evidence in context.code_snippets[:8]:
            findings.append(
                ReasoningFinding(
                    agent="defender",
                    state=context.target_state or context.fsm.initial_state,
                    transition=None,
                    claim="Implementation contains state/session related code that may enforce constraints.",
                    confidence=0.55,
                    preconditions=[],
                    suggested_tests=["Replay baseline and then corrupt state-bearing fields."],
                    evidence=[evidence],
                )
            )
        return findings
