"""Semantic comparisons by the LLM; graph identity and assembly by Python."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from typing import Any, Callable, Iterable

from protolens.config import FSMBuildConfig
from protolens.fsm.fsm_model import Divergence, Evidence, ProtocolFSM, State, StateTransition
from protolens.fsm.llm_support import (
    FSM_SCHEMA, LLMConversationRecorder, normalize_fsm_protocol, validate_fsm, validate_json_schema,
)
from protolens.fsm.merge_records import (
    SemanticDecisionRunner, candidate_coverage, comparison_evidence_ids, decision_id, record_wide_uncertainty,
)
from protolens.utils.artifact_store import ArtifactStore
from protolens.utils.llm_client import LLMClient
from protolens.utils.stage_checkpoints import stable_fingerprint


# Extraction limits do not apply to the locally assembled union. No input
# element or citation is discarded to fit an LLM's output-length constraint.
MERGED_FSM_SCHEMA = deepcopy(FSM_SCHEMA)
for _field in ("states", "transitions", "terminal_states", "error_states"):
    MERGED_FSM_SCHEMA["properties"][_field].pop("maxItems", None)
for _field in ("states", "transitions"):
    MERGED_FSM_SCHEMA["properties"][_field]["items"]["properties"]["evidence"].pop("maxItems", None)


def _id(prefix: str, *parts: Any) -> str:
    return prefix + "_" + stable_fingerprint(parts)[:24]


class _Groups:
    def __init__(self, identifiers: Iterable[str]) -> None:
        self.parent = {identifier: identifier for identifier in identifiers}

    def root(self, identifier: str) -> str:
        root = identifier
        while self.parent[root] != root:
            root = self.parent[root]
        while identifier != root:
            parent = self.parent[identifier]
            self.parent[identifier] = root
            identifier = parent
        return root

    def join(self, left: str, right: str) -> None:
        left, right = self.root(left), self.root(right)
        if left != right:
            self.parent[max(left, right)] = min(left, right)

    def members(self) -> list[list[str]]:
        groups: dict[str, list[str]] = {}
        for identifier in sorted(self.parent):
            groups.setdefault(self.root(identifier), []).append(identifier)
        return sorted(groups.values())


def _wire_graph(fsm: ProtocolFSM) -> dict[str, Any]:
    wire = fsm.to_dict()
    wire.pop("metadata", None)
    wire["states"] = list(wire["states"].values())
    return wire


class FSMMerger:
    """Compare bounded candidate blocks, then assemble every input locally."""

    CACHE_VERSION = "fsm-semantic-records-v4"
    # Evidence selection changes assembled results, while the record contract
    # stays compatible. Reuse verified records whose exact inputs are unchanged.
    DECISION_CONTRACT = "fsm-semantic-records-v3"

    def __init__(self, llm_client: LLMClient, config: FSMBuildConfig | None = None) -> None:
        self.recorder = LLMConversationRecorder("fsm_merge", llm_client)
        self.config = config or FSMBuildConfig()

    def merge(
        self, spec_fsm: ProtocolFSM, impl_fsm: ProtocolFSM, *,
        store: ArtifactStore | None = None, force: bool = False,
        on_progress: Callable[[str], None] | None = None,
    ) -> tuple[ProtocolFSM, list[Divergence]]:
        if self.recorder.llm_client.is_offline:
            raise RuntimeError("FSM comparison and merge require an online LLM")
        spec_fsm, impl_fsm = deepcopy(spec_fsm), deepcopy(impl_fsm)
        normalize_fsm_protocol(impl_fsm, spec_fsm.protocol, component="ImplementationFSM")
        for fsm in (spec_fsm, impl_fsm):
            validate_fsm(fsm)
            validate_json_schema(_wire_graph(fsm), MERGED_FSM_SCHEMA)
            if any(name != state.name for name, state in fsm.states.items()):
                raise ValueError("input FSM state keys must equal their declared names")
        limits = self.cache_settings()
        if not 1 <= limits["batch_records"] <= 16 or not 1 <= limits["candidate_limit"] <= 64:
            raise ValueError("merge batch_records must be 1..16 and candidate_limit must be 1..64")
        if limits["request_bytes"] < 8000:
            raise ValueError("merge_request_bytes must be at least 8000")
        elements, evidence_table = self._index_inputs(spec_fsm, impl_fsm)
        runner = SemanticDecisionRunner(
            self.recorder, protocol=spec_fsm.protocol, evidence_table=evidence_table,
            version=self.DECISION_CONTRACT, batch_records=limits["batch_records"],
            request_bytes=limits["request_bytes"], store=store, force=force, on_progress=on_progress,
        )
        state_inputs = {key: value for key, value in elements.items() if value["kind"] == "state"}
        if on_progress:
            on_progress(f"semantic merge: comparing {len(state_inputs)} input states in bounded batches")
        state_results = list(runner.evaluate(self._comparison_jobs(state_inputs, "state", runner), self._validate_decision))
        states, state_map, state_sources = self._assemble_states(state_inputs, state_results, evidence_table)
        transitions = {key: deepcopy(value) for key, value in elements.items() if value["kind"] == "transition"}
        for value in transitions.values():
            value["unified_source"] = state_map[value["source"]]
            value["unified_target"] = state_map[value["target"]]
        if on_progress:
            on_progress(f"semantic merge: comparing {len(transitions)} input transitions in bounded batches")
        transition_results = list(runner.evaluate(self._comparison_jobs(transitions, "transition", runner), self._validate_decision))
        unmatched_jobs = self._unmatched_jobs(transitions, transition_results)
        unmatched_results = list(runner.evaluate(unmatched_jobs, self._validate_decision))
        merged_transitions, mappings, variants = self._assemble_transitions(transitions, transition_results, evidence_table)
        all_results = [*state_results, *transition_results, *unmatched_results]
        divergences = self._assemble_divergences(elements, all_results, evidence_table)
        uncertainties = [
            {"record_id": job["record_id"], "query_id": job["query"]["id"],
             "scope": "record" if record_wide_uncertainty(row) else "candidates",
             "candidate_ids": ([item["id"] for item in job["candidates"]]
                               if record_wide_uncertainty(row) else row["uncertain_ids"]),
             "rationale": row["rationale"]}
            for job, row in all_results if row["assessment"] == "uncertain"
        ]
        spec_initial = _id("spec_state", spec_fsm.initial_state)
        impl_initial = _id("impl_state", impl_fsm.initial_state)
        unified = ProtocolFSM(
            protocol=spec_fsm.protocol, version=spec_fsm.version or impl_fsm.version,
            states=states, transitions=merged_transitions, initial_state=state_map[spec_initial],
            terminal_states={state_map[key] for key, value in state_inputs.items() if value["roles"]["terminal"]},
            error_states={state_map[key] for key, value in state_inputs.items() if value["roles"]["error"]},
            metadata={
                "builder": self.CACHE_VERSION, "comparison": "llm_semantic_batches",
                "merge_rationale": "All input elements were preserved and assembled locally from validated semantic decisions.",
                "state_sources": state_sources, "transition_sources": mappings,
                "transition_variants": variants, "uncertainties": uncertainties,
                "input_initial_states": {"spec": state_map[spec_initial], "impl": state_map[impl_initial]},
                "input_versions": {"spec": spec_fsm.version, "impl": impl_fsm.version},
                "semantic_decision_count": len(runner.completed), "comparison_record_count": len(all_results),
                "merge_limits": limits,
            },
        )
        validate_json_schema(_wire_graph(unified), MERGED_FSM_SCHEMA)
        validate_fsm(unified)
        self._validate_transition_coverage(spec_fsm, impl_fsm, unified, mappings)
        if store is not None:
            store.write_json("merge_decisions.json", {
                "contract": self.DECISION_CONTRACT, "builder": self.CACHE_VERSION, "decisions": runner.completed,
                "input_index": {key: {**{field: value[field] for field in ("side", "kind", "original_id")},
                                      **({"evidence_context": value["evidence_context"]} if "evidence_context" in value else {})}
                                for key, value in elements.items()},
            })
        return unified, divergences

    def cache_settings(self) -> dict[str, int]:
        return {"batch_records": self.config.merge_batch_records,
                "candidate_limit": self.config.merge_candidate_limit,
                "request_bytes": self.config.merge_request_bytes}

    @staticmethod
    def _index_inputs(
        spec: ProtocolFSM, impl: ProtocolFSM,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        elements, evidence_table = {}, {}

        def evidence_ids(evidence: list[Evidence]) -> list[str]:
            refs = []
            for citation in evidence:
                wire = asdict(citation)
                ref = _id("evidence", wire)
                if ref in evidence_table and evidence_table[ref] != wire:
                    raise ValueError("evidence identifier collision")
                evidence_table[ref] = wire
                refs.append(ref)
            return sorted(set(refs))

        for side, fsm in (("spec", spec), ("impl", impl)):
            incident: dict[str, list[dict[str, Any]]] = {name: [] for name in fsm.states}
            for name, state in sorted(fsm.states.items()):
                identifier = _id(f"{side}_state", name)
                elements[identifier] = {
                    "id": identifier, "original_id": name, "side": side, "kind": "state",
                    "name": name, "description": state.description, "confidence": state.confidence,
                    "roles": {"initial": name == fsm.initial_state, "terminal": name in fsm.terminal_states,
                              "error": name in fsm.error_states}, "evidence": evidence_ids(state.evidence),
                }
            for transition in sorted(fsm.transitions, key=lambda item: item.id):
                identifier = _id(f"{side}_transition", transition.id)
                wire = asdict(transition)
                wire.update({"id": identifier, "original_id": transition.id, "side": side, "kind": "transition",
                             "source": _id(f"{side}_state", transition.source),
                             "target": _id(f"{side}_state", transition.target),
                             "source_name": transition.source, "target_name": transition.target,
                             "evidence": evidence_ids(transition.evidence)})
                if identifier in elements:
                    raise ValueError(f"input identifier collision: {identifier}")
                elements[identifier] = wire
                for name in {transition.source, transition.target}:
                    incident[name].append(wire)
            for name in sorted(fsm.states):
                state = elements[_id(f"{side}_state", name)]
                if state["evidence"] or not incident[name]:
                    continue
                # Supply bounded witnesses for states that have no direct
                # annotations. Keep all original transition citations intact;
                # a sample is explicitly not a complete behavioral account.
                selected: dict[str, dict[str, Any]] = {}
                for endpoint in ("source_name", "target_name"):
                    witness = next((item for item in incident[name] if item[endpoint] == name), None)
                    if witness is not None:
                        selected[witness["id"]] = witness
                fields = ("id", "original_id", "source_name", "target_name", "trigger", "message_type",
                          "guard", "action", "error_handling", "confidence", "evidence")
                state["evidence_context"] = {
                    "origin": "incident_transitions", "total_incident_transitions": len(incident[name]),
                    "complete": len(selected) == len(incident[name]),
                    "transitions": [{**{field: deepcopy(item[field]) for field in fields},
                                     "directions": [direction for field, direction in (("source_name", "outgoing"), ("target_name", "incoming"))
                                                    if item[field] == name]}
                                    for _, item in sorted(selected.items())],
                }
        return elements, evidence_table

    def _comparison_jobs(
        self, elements: dict[str, dict[str, Any]], task: str, runner: SemanticDecisionRunner,
    ) -> Iterable[dict[str, Any]]:
        # Every cross-side candidate is assessed. Batching must not turn an
        # unexamined counterpart into a fabricated missing/extra transition.
        candidates = [item for _, item in sorted(elements.items()) if item["side"] == "spec"]

        def block(query: dict[str, Any], items: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
            job = {"record_id": decision_id(task, query["id"], [item["id"] for item in items]),
                   "task": task, "query": query, "candidates": items}
            if runner.fits([job]):
                yield job
            elif len(items) > 1:
                middle = len(items) // 2
                yield from block(query, items[:middle])
                yield from block(query, items[middle:])
            else:
                raise ValueError(f"semantic comparison {job['record_id']} exceeds merge_request_bytes; no evidence was truncated")

        for _, query in sorted(elements.items()):
            if query["side"] == "impl":
                for start in range(0, len(candidates), self.config.merge_candidate_limit):
                    yield from block(query, candidates[start:start + self.config.merge_candidate_limit])

    @staticmethod
    def _validate_decision(job: dict[str, Any], row: dict[str, Any]) -> None:
        if row["record_id"] != job["record_id"]:
            raise ValueError("semantic decision changed record_id")
        candidates = {item["id"]: item for item in job["candidates"]}
        query, task = job["query"], job["task"]
        deferred = record_wide_uncertainty(row)
        coverage = candidate_coverage(job, row)
        if any(coverage.values()):
            raise ValueError(
                f"candidate coverage invalid for {job['record_id']}: "
                f"missing={coverage['missing_ids']!r}, foreign={coverage['foreign_ids']!r}, "
                f"conflicting={coverage['conflicting_ids']!r}, duplicate={coverage['duplicate_ids']!r}; "
                f"allowed_candidate_ids={sorted(candidates)!r}"
            )
        for difference in row["differences"]:
            identifier, kind = difference["candidate_id"], difference["kind"]
            if task.startswith("unmatched_"):
                expected = "missing_transition" if task == "unmatched_spec" else "extra_transition"
                if identifier is not None or kind != expected:
                    raise ValueError(f"{task} must use {expected} with candidate_id=null")
            else:
                allowed = {"state_mismatch"} if task == "state" else {
                    "state_mismatch", "guard_mismatch", "action_mismatch", "error_handling_mismatch"}
                if identifier not in candidates or kind not in allowed:
                    raise ValueError("difference references an unknown candidate or inappropriate kind")
            citations = [*comparison_evidence_ids(query),
                         *(comparison_evidence_ids(candidates[identifier]) if identifier in candidates else [])]
            if not citations and not deferred:
                resolution = (
                    "return assessment='uncertain' and empty matches/differences/unrelated_ids/uncertain_ids"
                    if task.startswith("unmatched_") else
                    f"remove differences for {identifier!r}, classify it only in uncertain_ids and set assessment='uncertain'; "
                    "setting assessment alone does not defer this individual difference"
                )
                raise ValueError(
                    f"difference has no supporting input evidence for query={query['id']!r}, candidate={identifier!r}, task={task!r}; "
                    f"both direct citations and incident-transition context are empty; {resolution}; never fabricate evidence"
                )
        if task.startswith("unmatched_"):
            if row["assessment"] == "complete" and not row["differences"]:
                raise ValueError("unmatched assessment needs an evidenced finding or an explicit uncertain judgment")
        elif row["uncertain_ids"] and row["assessment"] != "uncertain":
            raise ValueError("explicit uncertain candidates require an uncertain assessment")
        if deferred:
            return  # Tentative matches/findings are audited, never assembled.
        for identifier in row["matches"]:
            candidate = candidates[identifier]
            if task == "state" and query["roles"] != candidate["roles"]:
                raise ValueError("states with different initial/terminal/error roles cannot be coalesced")
            if task == "transition" and (query["unified_source"], query["unified_target"]) != (candidate["unified_source"], candidate["unified_target"]):
                raise ValueError("equivalent transitions must use semantically matched state endpoints")

    @staticmethod
    def _groups(
        elements: dict[str, dict[str, Any]], results: list[tuple[dict[str, Any], dict[str, Any]]],
    ) -> list[list[str]]:
        groups = _Groups(elements)
        for job, row in results:
            if record_wide_uncertainty(row):
                continue
            for candidate in row["matches"]:
                groups.join(job["query"]["id"], candidate)
        for job, row in results:
            if record_wide_uncertainty(row):
                continue
            query = job["query"]["id"]
            for difference in row["differences"]:
                if groups.root(query) == groups.root(difference["candidate_id"]):
                    raise ValueError(f"contradictory equivalence and difference decisions at {job['record_id']}; graph assembly refused")
        return groups.members()

    @staticmethod
    def _citations(
        members: list[dict[str, Any]], table: dict[str, dict[str, Any]], *, include_context: bool = False,
    ) -> list[Evidence]:
        refs = sorted({ref for member in members
                       for ref in (comparison_evidence_ids(member) if include_context else member["evidence"])})
        return [Evidence.from_dict(deepcopy(table[ref])) for ref in refs]

    def _assemble_states(
        self, inputs: dict[str, dict[str, Any]], results: list[tuple[dict[str, Any], dict[str, Any]]],
        table: dict[str, dict[str, Any]],
    ) -> tuple[dict[str, State], dict[str, str], dict[str, list[dict[str, str]]]]:
        states, mapping, sources = {}, {}, {}
        for group in self._groups(inputs, results):
            identifier = _id("U_S", group)
            members = [inputs[key] for key in group]
            description = "\n".join(dict.fromkeys(
                f"[{item['side']}] {item['name']}: {item['description']}" for item in members))
            states[identifier] = State(identifier, description, self._citations(members, table),
                                       min(item["confidence"] for item in members))
            sources[identifier] = [{"side": item["side"], "name": item["name"]} for item in members]
            mapping.update({key: identifier for key in group})
        return states, mapping, sources

    def _assemble_transitions(
        self, inputs: dict[str, dict[str, Any]], results: list[tuple[dict[str, Any], dict[str, Any]]],
        table: dict[str, dict[str, Any]],
    ) -> tuple[list[StateTransition], list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
        transitions, mappings, variants = [], [], {}
        semantic_fields = ("trigger", "message_type", "guard", "action", "error_handling")
        for group in self._groups(inputs, results):
            identifier = _id("U_T", group)
            members = sorted((inputs[key] for key in group), key=lambda item: (item["side"] != "spec", item["id"]))
            representative = members[0]
            transitions.append(StateTransition(
                id=identifier, source=representative["unified_source"], target=representative["unified_target"],
                **{field: representative[field] for field in semantic_fields},
                evidence=self._citations(members, table), confidence=min(item["confidence"] for item in members),
            ))
            mappings.append({"unified_transition_id": identifier,
                             "spec_transition_ids": sorted(item["original_id"] for item in members if item["side"] == "spec"),
                             "impl_transition_ids": sorted(item["original_id"] for item in members if item["side"] == "impl")})
            variants[identifier] = [{"side": item["side"], "original_id": item["original_id"],
                                     **{field: item[field] for field in semantic_fields}} for item in members]
        return transitions, mappings, variants

    @staticmethod
    def _unmatched_jobs(
        inputs: dict[str, dict[str, Any]], results: list[tuple[dict[str, Any], dict[str, Any]]],
    ) -> Iterable[dict[str, Any]]:
        related, uncertain = set(), set()
        for job, row in results:
            query = job["query"]["id"]
            if record_wide_uncertainty(row):
                uncertain.update({query, *(item["id"] for item in job["candidates"])})
                continue
            counterparts = set(row["matches"]) | {item["candidate_id"] for item in row["differences"]}
            if counterparts:
                related.update({query, *counterparts})
            if row["uncertain_ids"]:
                uncertain.update({query, *row["uncertain_ids"]})
        coverage = stable_fingerprint([(job["record_id"], row) for job, row in results])
        for identifier, query in sorted(inputs.items()):
            if identifier in related or identifier in uncertain:
                continue
            task = f"unmatched_{query['side']}"
            yield {"record_id": decision_id(task, identifier, []), "task": task,
                   "query": query, "candidates": [],
                   "comparison_summary": {"all_opposite_transitions_assessed": True,
                                          "opposite_transition_count": sum(item["side"] != query["side"] for item in inputs.values()),
                                          "related_count": 0, "uncertain_count": 0, "coverage_sha256": coverage}}

    def _assemble_divergences(
        self, inputs: dict[str, dict[str, Any]], results: list[tuple[dict[str, Any], dict[str, Any]]],
        table: dict[str, dict[str, Any]],
    ) -> list[Divergence]:
        divergences = {}
        for job, row in results:
            if record_wide_uncertainty(row):
                continue
            query = inputs[job["query"]["id"]]
            for difference in row["differences"]:
                counterpart = inputs.get(difference["candidate_id"])
                members = [query, *([counterpart] if counterpart else [])]
                spec = next((item for item in members if item["side"] == "spec"), None)
                impl = next((item for item in members if item["side"] == "impl"), None)
                identifier = _id("D", difference["kind"], spec["id"] if spec else None, impl["id"] if impl else None)
                divergences[identifier] = Divergence(
                    id=identifier, kind=difference["kind"], severity=difference["severity"],
                    spec_element=spec["original_id"] if spec else None,
                    impl_element=impl["original_id"] if impl else None,
                    rationale=difference["rationale"], evidence=self._citations(members, table, include_context=True),
                )
        return sorted(divergences.values(), key=lambda item: (item.severity, item.id))

    @staticmethod
    def _validate_transition_coverage(
        spec: ProtocolFSM, impl: ProtocolFSM, unified: ProtocolFSM, mappings: list[dict[str, Any]],
    ) -> None:
        expected = {"spec_transition_ids": {item.id for item in spec.transitions},
                    "impl_transition_ids": {item.id for item in impl.transitions}}
        seen = {key: set() for key in expected}
        unified_ids = {item.id for item in unified.transitions}
        if len(mappings) != len(unified_ids) or {row["unified_transition_id"] for row in mappings} != unified_ids:
            raise ValueError("local assembly did not map every unified transition exactly once")
        for row in mappings:
            if not row["spec_transition_ids"] and not row["impl_transition_ids"]:
                raise ValueError("local assembly produced an unsupported transition")
            for key in expected:
                if seen[key].intersection(row[key]):
                    raise ValueError("input transition appears in more than one assembled transition")
                seen[key].update(row[key])
        if seen != expected:
            raise ValueError("local assembly did not preserve every input transition")

    def drain_conversations(self) -> list[dict[str, Any]]:
        return self.recorder.drain_conversations()
