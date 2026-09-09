from __future__ import annotations

from protolens.agents.base_agent import AgentContext, BaseAgent
from protolens.fsm.fsm_model import Evidence, ReasoningFinding


CROSS_LAYER_FINDINGS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "maxItems": 12,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "state",
                    "transition",
                    "claim",
                    "confidence",
                    "preconditions",
                    "suggested_tests",
                    "evidence",
                ],
                "properties": {
                    "state": {
                        "type": "string",
                        "description": "Protocol state where the cross-layer interaction can be observed.",
                    },
                    "transition": {
                        "type": ["string", "null"],
                        "description": "Transition id or label when the finding is transition-specific.",
                    },
                    "claim": {
                        "type": "string",
                        "description": "Concrete cross-layer state-contamination hypothesis.",
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "preconditions": {
                        "type": "array",
                        "maxItems": 8,
                        "items": {"type": "string"},
                    },
                    "suggested_tests": {
                        "type": "array",
                        "maxItems": 8,
                        "items": {"type": "string"},
                    },
                    "evidence": {
                        "type": "array",
                        "maxItems": 8,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["source_type", "location", "excerpt", "confidence"],
                            "properties": {
                                "source_type": {"type": "string"},
                                "location": {"type": "string"},
                                "excerpt": {"type": "string"},
                                "confidence": {
                                    "type": "number",
                                    "minimum": 0,
                                    "maximum": 1,
                                },
                            },
                        },
                    },
                },
            },
        }
    },
}


class CrossLayerAgent(BaseAgent):
    name = "cross_layer"
    role = "cross_layer"

    CROSS_LAYER_TERMS = ("tls", "ssl", "http", "rtp", "rtcp", "auth", "session", "connection")

    def analyze(self, context: AgentContext) -> list[ReasoningFinding]:
        if self.should_use_llm():
            findings = self.analyze_with_llm(
                context,
                system_prompt=(
                    "You are the ProtoLens CrossLayerAgent. Look for protocol-layer state "
                    "contamination across transport, TLS, authentication, session, parser, and "
                    "application layers. Return only JSON that validates against the provided "
                    "JSON Schema; do not include Markdown, comments, or extra keys."
                ),
                task_prompt=(
                    "Identify cross-layer state interactions that should be fuzzed with interleaved "
                    "messages, renegotiation, reset, half-close, stale session tokens, teardown, or "
                    "authentication failure. Keep every finding executable as a fuzzing strategy. "
                    "If there is no concrete cross-layer hypothesis, return {\"findings\": []}."
                ),
                output_schema=CROSS_LAYER_FINDINGS_SCHEMA,
                schema_name="protolens_cross_layer_findings",
            )
            if findings or not self.last_llm_failed():
                return findings
        text = " ".join(
            [state for state in context.fsm.states]
            + [transition.trigger for transition in context.fsm.transitions]
            + [evidence.excerpt for evidence in context.code_snippets[:20]]
        ).lower()
        hits = [term for term in self.CROSS_LAYER_TERMS if term in text]
        if len(set(hits)) < 2:
            return []

        evidence = Evidence(
            source_type="cross_layer_heuristic",
            location=context.protocol,
            excerpt=f"Detected cross-layer terms: {', '.join(sorted(set(hits)))}",
            confidence=0.6,
        )
        return [
            ReasoningFinding(
                agent="cross_layer",
                state=context.target_state or context.fsm.initial_state,
                transition=None,
                claim="Protocol state appears coupled to connection/session layers; interleaved reset or renegotiation should be tested.",
                confidence=0.68,
                preconditions=["Reach authenticated or session-bearing state"],
                suggested_tests=[
                    "Interleave connection reset/half-close with an otherwise valid request sequence.",
                    "Send stale session-bearing requests after teardown or renegotiation.",
                ],
                evidence=[evidence],
            )
        ]
