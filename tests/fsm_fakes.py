from __future__ import annotations

from typing import Any
import json

from protolens.utils.llm_client import LLMResponse


class FakeFSMClient:
    is_offline = False
    retries = 0
    provider = "fake"
    model = "fake-fsm"

    def responses_json(
        self,
        *,
        system: str,
        user: str,
        response_schema: dict[str, Any],
        schema_name: str,
        web_search: bool = False,
        allowed_domains: list[str] | None = None,
        max_tool_calls: int | None = None,
    ) -> LLMResponse:
        if not web_search:
            return self.chat_json(
                system=system,
                user=user,
                response_schema=response_schema,
                schema_name=schema_name,
            )
        payload = json.loads(user)
        protocol = payload["protocol"]
        url = "https://www.rfc-editor.org/rfc/rfc0001.html"
        result = {
            "fsm": _fsm(
                protocol,
                transitions=[
                    _transition(
                        "spec_start_input_ready",
                        "START",
                        "READY",
                        "INPUT",
                        "normative input",
                        "spec",
                        f"{url}#section-1",
                    )
                ],
            ),
            "sources": [
                {
                    "url": url,
                    "title": "Fake protocol specification",
                    "rfc_number": "RFC 0001",
                    "status": "Internet Standard",
                    "published_at": "2026-01",
                    "relationship": "current",
                }
            ],
            "latestness_rationale": "Checked the authoritative RFC index.",
            "uncertainties": [],
        }
        return LLMResponse(
            text=json.dumps(result),
            provider=self.provider,
            model=self.model,
            raw={
                "output": [
                    {
                        "type": "web_search_call",
                        "status": "completed",
                        "action": {"sources": [{"type": "url", "url": url}]},
                    }
                ]
            },
        )

    def chat_json(
        self,
        *,
        system: str,
        user: str,
        response_schema: dict[str, Any] | None = None,
        schema_name: str = "",
    ) -> LLMResponse:
        payload = json.loads(user)
        if schema_name.startswith("protolens_impl_transition_facts_chunk_"):
            result = self._implementation_chunk_facts(payload)
        elif schema_name == "protolens_impl_fsm_assemble":
            result = self._implementation_assembly(payload)
        elif schema_name == "protolens_fsm_merge":
            result = self._merge(payload)
        else:
            result = {"findings": []}
        return LLMResponse(text=json.dumps(result), provider=self.provider, model=self.model, raw={})

    def _implementation_chunk_facts(self, payload: dict[str, Any]) -> dict[str, Any]:
        source = payload["source_chunk"]["files"][0]
        content = source["content"]
        excerpt = next((line for line in content.splitlines() if line.strip()), content[:80])
        transition = _transition(
            "impl_start_input_ready",
            "START",
            "READY",
            "INPUT",
            excerpt,
            "code",
            f"{source['path']}:1",
        )
        return {
            "transition_facts": [transition],
            "analyzed_files": [item["path"] for item in payload["source_chunk"]["files"]],
            "uncertainties": [],
        }

    def _implementation_assembly(self, payload: dict[str, Any]) -> dict[str, Any]:
        facts = payload["transition_facts"]
        transitions: list[dict[str, Any]] = []
        states = {"START"}
        for index, fact in enumerate(facts, 1):
            transition = {
                key: fact.get(key)
                for key in (
                    "source", "target", "trigger", "message_type", "guard", "action",
                    "error_handling", "confidence",
                )
            }
            transition["id"] = f"assembled_{index}"
            transition["fact_ids"] = [fact["id"]]
            transitions.append(transition)
            states.update((fact["source"], fact["target"]))
        return {
            "protocol": payload["protocol"],
            "version": "implementation",
            "states": [
                {"name": name, "description": "", "confidence": 1.0}
                for name in sorted(states)
            ],
            "transitions": transitions,
            "initial_state": "START",
            "terminal_states": [],
            "error_states": [],
            "uncertainties": [],
        }

    def _merge(self, payload: dict[str, Any]) -> dict[str, Any]:
        spec = payload["specification_fsm"]
        impl = payload["implementation_fsm"]
        transitions: list[dict[str, Any]] = []
        mappings: list[dict[str, Any]] = []
        states = set(spec["states"]) | set(impl["states"])
        for prefix, fsm, key in (("spec", spec, "spec_transition_ids"), ("impl", impl, "impl_transition_ids")):
            for transition in fsm["transitions"]:
                copied = dict(transition)
                copied["id"] = f"{prefix}_{transition['id']}"
                transitions.append(copied)
                mapping = {
                    "unified_transition_id": copied["id"],
                    "spec_transition_ids": [],
                    "impl_transition_ids": [],
                }
                mapping[key] = [transition["id"]]
                mappings.append(mapping)
        unified = {
            "protocol": spec["protocol"],
            "version": spec.get("version") or impl.get("version"),
            "states": [
                {"name": name, "description": "", "evidence": [], "confidence": 1.0}
                for name in sorted(states)
            ],
            "transitions": transitions,
            "initial_state": spec["initial_state"],
            "terminal_states": sorted(set(spec["terminal_states"]) | set(impl["terminal_states"])),
            "error_states": sorted(set(spec["error_states"]) | set(impl["error_states"])),
        }
        impl_transition = impl["transitions"][0]
        return {
            "unified_fsm": unified,
            "divergences": [
                {
                    "id": "fake_extra_transition",
                    "kind": "extra_transition",
                    "spec_element": None,
                    "impl_element": impl_transition["id"],
                    "severity": "P0",
                    "rationale": "Fake implementation-only behavior for pipeline testing.",
                    "evidence": impl_transition["evidence"],
                }
            ],
            "transition_sources": mappings,
            "merge_rationale": "Every input transition remains traceable.",
            "uncertainties": [],
        }


def _fsm(protocol: str, transitions: list[dict[str, Any]]) -> dict[str, Any]:
    states = {"START"}
    for transition in transitions:
        states.add(transition["source"])
        states.add(transition["target"])
    return {
        "protocol": protocol,
        "version": "latest",
        "states": [
            {"name": name, "description": "", "evidence": [], "confidence": 1.0}
            for name in sorted(states)
        ],
        "transitions": transitions,
        "initial_state": "START",
        "terminal_states": [],
        "error_states": [],
    }


def _transition(
    transition_id: str,
    source: str,
    target: str,
    trigger: str,
    excerpt: str,
    source_type: str,
    location: str,
) -> dict[str, Any]:
    return {
        "id": transition_id,
        "source": source,
        "target": target,
        "trigger": trigger,
        "message_type": trigger,
        "guard": None,
        "action": None,
        "error_handling": None,
        "evidence": [
            {
                "source_type": source_type,
                "location": location,
                "excerpt": excerpt,
                "confidence": 0.9,
            }
        ],
        "confidence": 0.9,
    }
