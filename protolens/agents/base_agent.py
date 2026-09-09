from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
import ast
import json
import re

from protolens.fsm.fsm_model import Divergence, Evidence, ProtocolFSM, ReasoningFinding
from protolens.utils.llm_client import LLMClient


@dataclass
class AgentContext:
    """Agent 的只读推理上下文，避免各角色使用不一致的数据视图。"""

    protocol: str
    direction: str
    fsm: ProtocolFSM
    divergences: list[Divergence]
    code_snippets: list[Evidence] = field(default_factory=list)
    prior_traces: list[str] = field(default_factory=list)
    target_state: str | None = None


class BaseAgent:
    """Agent 公共基类，负责 LLM 调用、重试及结构化结果校验。"""

    name = "base"
    role: Literal["attacker", "defender", "cross_layer"] = "attacker"

    def __init__(self, llm_client: LLMClient | None = None) -> None:
        self.llm_client = llm_client or LLMClient()
        self._llm_conversations: list[dict[str, Any]] = []
        self._last_llm_failed = False

    def analyze(self, context: AgentContext) -> list[ReasoningFinding]:
        raise NotImplementedError

    def should_use_llm(self) -> bool:
        return not self.llm_client.is_offline

    def drain_llm_conversations(self) -> list[dict[str, Any]]:
        conversations = list(self._llm_conversations)
        self._llm_conversations.clear()
        return conversations

    def last_llm_failed(self) -> bool:
        return self._last_llm_failed

    def analyze_with_llm(
        self,
        context: AgentContext,
        system_prompt: str,
        task_prompt: str,
        output_schema: dict[str, Any] | None = None,
        schema_name: str | None = None,
    ) -> list[ReasoningFinding]:
        self._last_llm_failed = False
        payload = {
            "task": task_prompt,
            "required_output": {
                "findings": [
                    {
                        "state": "source state name",
                        "transition": "transition id or human label, or null",
                        "claim": "specific security claim",
                        "confidence": 0.0,
                        "preconditions": ["conditions needed to test the claim"],
                        "suggested_tests": ["concrete fuzzing or replay tests"],
                        "evidence": [
                            {
                                "source_type": "spec|code|fsm|reasoning",
                                "location": "file:line, RFC section, or transition id",
                                "excerpt": "short supporting excerpt",
                                "confidence": 0.0,
                            }
                        ],
                    }
                ]
            },
            "context": self._context_json(context),
        }
        if output_schema is not None:
            payload["json_schema"] = output_schema
        user_prompt = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        last_error: Exception | None = None
        for attempt in range(self.llm_client.retries + 1):
            conversation: dict[str, Any] = {
                "agent": self.name,
                "role": self.role,
                "direction": context.direction,
                "target_state": context.target_state,
                "provider": getattr(self.llm_client, "provider", ""),
                "model": getattr(self.llm_client, "model", ""),
                "attempt": attempt + 1,
                "system": system_prompt,
                "user": user_prompt,
            }
            if output_schema is not None:
                conversation["schema_name"] = schema_name or f"protolens_{self.name}_findings"
                conversation["json_schema"] = output_schema
            try:
                if output_schema is None:
                    response = self.llm_client.chat_json(system=system_prompt, user=user_prompt)
                else:
                    response = self.llm_client.chat_json(
                        system=system_prompt,
                        user=user_prompt,
                        response_schema=output_schema,
                        schema_name=schema_name or f"protolens_{self.name}_findings",
                    )
                conversation["response"] = {
                    "text": response.text,
                    "provider": response.provider,
                    "model": response.model,
                    "raw": response.raw,
                }
                findings = self._parse_findings(response.text)
                conversation["parsed_findings"] = len(findings)
                self._llm_conversations.append(conversation)
                return findings
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                last_error = exc
                conversation["error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
                self._llm_conversations.append(conversation)
            except Exception as exc:
                last_error = exc
                conversation["error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
                self._llm_conversations.append(conversation)
                break
        self._last_llm_failed = True
        self._llm_conversations.append(
            {
                "agent": self.name,
                "role": self.role,
                "direction": context.direction,
                "target_state": context.target_state,
                "provider": getattr(self.llm_client, "provider", ""),
                "model": getattr(self.llm_client, "model", ""),
                "final_status": "llm_failed_rule_fallback_required",
                "error": {
                    "type": type(last_error).__name__ if last_error else "UnknownError",
                    "message": str(last_error) if last_error else "LLM returned no valid findings",
                },
            }
        )
        return []

    def _parse_findings(self, text: str) -> list[ReasoningFinding]:
        data = _load_json_object(text)
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            raise ValueError("LLM output must be a JSON object with a findings array")
        findings: list[ReasoningFinding] = []
        for item in data["findings"]:
            if not isinstance(item, dict):
                raise ValueError("each finding must be an object")
            state = str(item.get("state", "")).strip()
            claim = str(item.get("claim", "")).strip()
            if not state or not claim:
                raise ValueError("each finding requires non-empty state and claim")
            confidence = _clamp_float(item.get("confidence", 0.0))
            findings.append(
                ReasoningFinding(
                    agent=self.role,
                    state=state,
                    transition=_optional_str(item.get("transition")),
                    claim=claim,
                    confidence=confidence,
                    preconditions=[str(value) for value in item.get("preconditions", [])][:8],
                    suggested_tests=[str(value) for value in item.get("suggested_tests", [])][:8],
                    evidence=[Evidence.from_dict(value) for value in item.get("evidence", [])[:8] if isinstance(value, dict)],
                )
            )
        return findings

    def _context_json(self, context: AgentContext) -> dict[str, Any]:
        return {
            "protocol": context.protocol,
            "direction": context.direction,
            "target_state": context.target_state,
            "fsm": {
                "protocol": context.fsm.protocol,
                "initial_state": context.fsm.initial_state,
                "states": sorted(context.fsm.states)[:80],
                "transitions": [
                    {
                        "id": transition.id,
                        "source": transition.source,
                        "target": transition.target,
                        "trigger": transition.trigger,
                        "message_type": transition.message_type,
                        "guard": transition.guard,
                        "action": transition.action,
                        "confidence": transition.confidence,
                    }
                    for transition in context.fsm.transitions[:160]
                ],
            },
            "divergences": [
                {
                    "id": divergence.id,
                    "kind": divergence.kind,
                    "severity": divergence.severity,
                    "spec_element": divergence.spec_element,
                    "impl_element": divergence.impl_element,
                    "rationale": divergence.rationale,
                    "evidence": [_evidence_json(item) for item in divergence.evidence[:4]],
                }
                for divergence in context.divergences[:80]
            ],
            "code_snippets": [_evidence_json(item) for item in context.code_snippets[:40]],
            "prior_traces": context.prior_traces[:10],
        }


def _evidence_json(evidence: Evidence) -> dict[str, Any]:
    return {
        "source_type": evidence.source_type,
        "location": evidence.location,
        "excerpt": evidence.excerpt[:500],
        "confidence": evidence.confidence,
    }


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clamp_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    return min(1.0, max(0.0, number))


def _strip_json_fence(text: str) -> str:
    """兼容部分模型即使被要求返回 JSON，仍附加 Markdown 围栏的情况。"""

    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[1] if "\n" in stripped else ""
        if stripped.endswith("```"):
            stripped = stripped[:-3]
    return stripped.strip()


def _load_json_object(text: str) -> Any:
    stripped = _extract_json_document(_strip_json_fence(text))
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    repaired = _remove_trailing_commas(stripped)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass

    try:
        return ast.literal_eval(repaired)
    except (SyntaxError, ValueError):
        return json.loads(_quote_simple_unquoted_keys(repaired))


def _extract_json_document(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    return text


def _remove_trailing_commas(text: str) -> str:
    return re.sub(r",(\s*[}\]])", r"\1", text)


def _quote_simple_unquoted_keys(text: str) -> str:
    return re.sub(r'([,{]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:', r'\1"\2":', text)
