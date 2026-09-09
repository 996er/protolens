from __future__ import annotations

import inspect
import json

from protolens.agents.attacker_agent import AttackerAgent
from protolens.agents.base_agent import AgentContext
from protolens.agents.conflict_detector import ConflictDetector
from protolens.agents.cross_layer_agent import CrossLayerAgent
from protolens.agents.defender_agent import DefenderAgent
from protolens.agents.direction_agent import DirectionGenerator
from protolens.agents.monitor_agent import MonitorAgent
from protolens.config import ProtoLensConfig
from protolens.fsm.fsm_merger import FSMMerger
from protolens.fsm.fsm_model import (
    Conflict,
    Divergence,
    Evidence,
    FuzzResult,
    PlannedStatePath,
    ProtocolFSM,
    ReasoningFinding,
    SeedIntent,
)
from protolens.fsm.impl_fsm_builder import ImplementationFSMBuilder
from protolens.fsm.spec_fsm_builder import SpecificationFSMBuilder
from protolens.fuzzer.aflnet_feedback import (
    AFLNetDynamicAnalyzer,
    AFLNetStateMapper,
    ClosedLoopReplanner,
    CrashReplayVerifier,
    SeedFeedbackAnalyzer,
)
from protolens.fuzzer.cross_layer_fuzzer import CrossLayerFuzzer
from protolens.fuzzer.path_aware_fuzzer import PathAwareFuzzer
from protolens.fuzzer.path_planner import PathPlanner
from protolens.fuzzer.path_calibrator import PathCalibrator
from protolens.fuzzer.state_aware_synthesizer import StateAwareTestSynthesizer
from protolens.fuzzer.transport_harness import TransportAwareHarness
from protolens.utils.artifact_store import ArtifactStore
from protolens.utils.llm_client import LLMClient
from protolens.utils.logger import Logger
from protolens.utils.stage_checkpoints import StageCheckpointStore, file_sha256, stable_fingerprint


class ProtoLensPipeline:
    """串联 FSM 构建、对抗推理、路径规划与 AFLNet 执行的主流程。"""

    def __init__(self, config: ProtoLensConfig, logger: Logger | None = None) -> None:
        self.config = config
        self.store = ArtifactStore(config.run_dir)
        self.checkpoints = StageCheckpointStore(self.store)
        self.stage_reuse: dict[str, bool] = {}
        self.logger = logger or Logger(debug_enabled=config.debug, log_file=config.run_dir / "protolens.log")
        self.llm_client = LLMClient.from_config(config.llm)
        self.spec_builder = SpecificationFSMBuilder(self.llm_client)
        self.impl_builder = ImplementationFSMBuilder(self.llm_client)
        self.merger = FSMMerger(self.llm_client)
        self.direction_generator = DirectionGenerator()
        self.agents = [
            AttackerAgent(self.llm_client),
            DefenderAgent(self.llm_client),
            CrossLayerAgent(self.llm_client),
        ]
        self.conflict_detector = ConflictDetector()
        self.path_planner = PathPlanner(config.path_calibration.max_candidates,
                                        config.path_calibration.max_depth,
                                        config.path_calibration.max_expansions)
        self.path_calibrator = PathCalibrator()
        self.state_aware_synthesizer = StateAwareTestSynthesizer()
        self.cross_layer_fuzzer = CrossLayerFuzzer()
        self.path_aware_fuzzer = PathAwareFuzzer()
        self.dynamic_analyzer = AFLNetDynamicAnalyzer()
        self.state_mapper = AFLNetStateMapper()
        self.seed_feedback_analyzer = SeedFeedbackAnalyzer()
        self.crash_replay_verifier = CrashReplayVerifier()
        self.closed_loop_replanner = ClosedLoopReplanner()
        self.transport_harness = TransportAwareHarness()
        self.monitor_agent = MonitorAgent(self.llm_client)
        self.logger.debug(
            "pipeline initialized",
            protocol=config.protocol,
            target=config.target_name,
            run_dir=config.run_dir,
            source_root=config.source_root,
            llm_provider=config.llm.provider,
            llm_model=config.llm.model,
            aflnet_dry_run=config.aflnet.dry_run,
        )

    def init_run(self) -> None:
        path = self.store.write_json("config.json", self.config.to_json_dict())
        self.logger.debug("wrote run configuration", path=path)

    def build_implementation(self, *, force: bool = False) -> tuple[ProtocolFSM, bool]:
        artifacts = [
            "impl_fsm.json",
            "implementation_transition_facts.json",
            "implementation_evidence_table.json",
            "implementation_source_manifest.json",
        ]
        source_snapshot = self.impl_builder.input_snapshot(self.config)
        fingerprint = stable_fingerprint(
            {
                "builder": self.impl_builder.CACHE_VERSION,
                "protocol": self.config.protocol,
                "target_name": self.config.target_name,
                "entrypoints": self.config.entrypoints,
                "source_extensions": self.config.fsm_build.source_extensions,
                "ignore_directories": self.config.fsm_build.ignore_directories,
                "chunk_chars": self.config.fsm_build.chunk_chars,
                "max_file_bytes": self.config.fsm_build.max_file_bytes,
                "source_snapshot": source_snapshot,
                "llm": _llm_cache_identity(self.config),
            }
        )
        if not force and self.checkpoints.is_valid("implementation", fingerprint, artifacts):
            self.logger.info("reusing implementation FSM checkpoint")
            self.stage_reuse["implementation"] = True
            return self._load_implementation_fsm(), True

        self.checkpoints.invalidate("implementation", "specification", "merge")
        self.store.path("findings/fsm_implementation.llm.jsonl").unlink(missing_ok=True)
        self.logger.info("building implementation transition facts and FSM")
        self.logger.debug(
            "implementation input paths",
            source_root=self.config.source_root,
            entrypoints=self.config.entrypoints,
        )
        try:
            impl_fsm = self.impl_builder.build(self.config)
        finally:
            self._write_fsm_llm_conversations(self.impl_builder)
            if self.impl_builder.last_manifest:
                self.store.write_json("implementation_source_manifest.json", self.impl_builder.last_manifest)
        self.store.write_json("implementation_transition_facts.json", self.impl_builder.last_transition_facts)
        self.store.write_json("implementation_evidence_table.json", self.impl_builder.last_evidence_table)
        self.store.write_json(
            "impl_fsm.json",
            _implementation_fsm_with_evidence_refs(impl_fsm, self.impl_builder.last_evidence_table),
        )
        self.checkpoints.record(
            "implementation",
            fingerprint,
            artifacts,
            invalidate=("specification", "merge"),
        )
        self.logger.debug(
            "implementation FSM built",
            states=len(impl_fsm.states),
            transitions=len(impl_fsm.transitions),
            initial_state=impl_fsm.initial_state,
        )
        self.stage_reuse["implementation"] = False
        return impl_fsm, False

    def build_specification(self, *, force: bool = False) -> tuple[ProtocolFSM, bool]:
        facts_path = self.store.path("implementation_transition_facts.json")
        if not facts_path.is_file():
            raise ValueError("implementation_transition_facts.json is required; run build-impl first")
        fact_artifact = self.store.read_json("implementation_transition_facts.json")
        capabilities = _implementation_capabilities(fact_artifact)
        artifacts = ["spec_fsm.json"]
        fingerprint = stable_fingerprint(
            {
                "builder": self.spec_builder.CACHE_VERSION,
                "protocol": self.config.protocol,
                "rfc_queries": self.config.fsm_build.rfc_queries,
                "rfc_analysis_scope": self.config.fsm_build.rfc_analysis_scope,
                "target_supported_extensions_only": self.config.fsm_build.target_supported_extensions_only,
                "allowed_rfc_domains": self.config.fsm_build.allowed_rfc_domains,
                "max_web_search_calls": self.config.fsm_build.max_web_search_calls,
                "implementation_capabilities": capabilities,
                "llm": _llm_cache_identity(self.config),
            }
        )
        if not force and self.checkpoints.is_valid("specification", fingerprint, artifacts):
            self.logger.info("reusing specification FSM checkpoint")
            self.stage_reuse["specification"] = True
            return ProtocolFSM.from_dict(self.store.read_json("spec_fsm.json")), True

        self.checkpoints.invalidate("specification", "merge")
        self.store.path("findings/fsm_specification.llm.jsonl").unlink(missing_ok=True)
        self.logger.info("building scoped specification FSM")
        self.logger.debug("spec input paths", spec_paths=[str(path) for path in self.config.spec_paths])
        try:
            spec_fsm = self.spec_builder.build(self.config, capabilities)
        finally:
            self._write_fsm_llm_conversations(self.spec_builder)
        self.store.write_json("spec_fsm.json", spec_fsm)
        self.checkpoints.record("specification", fingerprint, artifacts, invalidate=("merge",))
        self.logger.debug(
            "spec FSM built",
            states=len(spec_fsm.states),
            transitions=len(spec_fsm.transitions),
            initial_state=spec_fsm.initial_state,
        )
        self.stage_reuse["specification"] = False
        return spec_fsm, False

    def merge_fsms(self, *, force: bool = False) -> tuple[ProtocolFSM, list[Divergence], bool]:
        for name in ("spec_fsm.json", "impl_fsm.json", "implementation_evidence_table.json"):
            if not self.store.path(name).is_file():
                raise ValueError(f"{name} is required before merge-fsm")
        spec_fsm = ProtocolFSM.from_dict(self.store.read_json("spec_fsm.json"))
        impl_fsm = self._load_implementation_fsm()
        artifacts = ["unified_fsm.json", "divergences.json"]
        fingerprint = stable_fingerprint(
            {
                "builder": self.merger.CACHE_VERSION,
                "spec_fsm_sha256": file_sha256(self.store.path("spec_fsm.json")),
                "impl_fsm_sha256": file_sha256(self.store.path("impl_fsm.json")),
                "implementation_evidence_sha256": file_sha256(
                    self.store.path("implementation_evidence_table.json")
                ),
                "llm": _llm_cache_identity(self.config),
            }
        )
        if not force and self.checkpoints.is_valid("merge", fingerprint, artifacts):
            self.logger.info("reusing merged FSM checkpoint")
            unified = ProtocolFSM.from_dict(self.store.read_json("unified_fsm.json"))
            divergences = [Divergence.from_dict(item) for item in self.store.read_json("divergences.json")]
            self.stage_reuse["merge"] = True
            return unified, divergences, True

        self.checkpoints.invalidate("merge")
        self.store.path("findings/fsm_merge.llm.jsonl").unlink(missing_ok=True)
        self.logger.info("merging FSMs and detecting divergences")
        try:
            unified_fsm, divergences = self.merger.merge(spec_fsm, impl_fsm)
        finally:
            self._write_fsm_llm_conversations(self.merger)
        self.store.write_json("unified_fsm.json", unified_fsm)
        self.store.write_json("divergences.json", divergences)
        self.checkpoints.record("merge", fingerprint, artifacts)
        self.logger.debug(
            "FSM merge complete",
            unified_states=len(unified_fsm.states),
            unified_transitions=len(unified_fsm.transitions),
            divergences=len(divergences),
            p0=sum(1 for item in divergences if item.severity == "P0"),
            p1=sum(1 for item in divergences if item.severity == "P1"),
            p2=sum(1 for item in divergences if item.severity == "P2"),
        )
        for divergence in divergences[:10]:
            self.logger.debug(
                "divergence detected",
                id=divergence.id,
                kind=divergence.kind,
                severity=divergence.severity,
                spec=divergence.spec_element,
                impl=divergence.impl_element,
            )
        self.stage_reuse["merge"] = False
        return unified_fsm, divergences, False

    def build_fsm(
        self,
        *,
        force: bool = False,
    ) -> tuple[ProtocolFSM, ProtocolFSM, ProtocolFSM, list[Divergence]]:
        impl_fsm, _ = self.build_implementation(force=force)
        spec_fsm, _ = self.build_specification(force=force)
        unified_fsm, divergences, _ = self.merge_fsms(force=force)
        return spec_fsm, impl_fsm, unified_fsm, divergences

    def reason(self, fsm: ProtocolFSM, divergences: list[Divergence]) -> tuple[list[str], list[ReasoningFinding], list[Conflict]]:
        self.logger.info("running adversarial reasoning agents")
        # reason 子命令允许重复执行；清理本轮拥有的 JSONL，避免旧 finding 混入审计结果。
        for agent in self.agents:
            self.store.path(f"findings/{agent.name}.jsonl").unlink(missing_ok=True)
            self.store.path(f"findings/{agent.name}.llm.jsonl").unlink(missing_ok=True)
        directions = self.direction_generator.generate(fsm, divergences)
        code_evidence = _code_evidence_from_fsm(fsm)
        self.logger.debug(
            "reasoning context prepared",
            directions=len(directions),
            code_evidence=len(code_evidence),
            divergences=len(divergences),
            llm_provider=self.config.llm.provider,
            llm_model=self.config.llm.model,
        )
        findings: list[ReasoningFinding] = []
        finding_ids: set[str] = set()
        for direction in directions:
            self.logger.debug("reasoning direction started", direction=direction)
            context = AgentContext(
                protocol=self.config.protocol,
                direction=direction,
                fsm=fsm,
                divergences=divergences,
                code_snippets=code_evidence,
            )
            for agent in self.agents:
                self.logger.debug("agent started", agent=agent.name, direction=direction)
                try:
                    agent_findings = agent.analyze(context)
                except Exception as exc:
                    # 单个远端模型或单个角色失败时保留其余结果，FSM 分歧仍可继续生成任务。
                    self.logger.error(
                        "agent failed; continuing with remaining agents",
                        agent=agent.name,
                        direction=direction,
                        error=exc,
                    )
                    self._write_agent_llm_conversations(agent)
                    continue
                self._write_agent_llm_conversations(agent)
                unique_findings = [item for item in agent_findings if item.id not in finding_ids]
                finding_ids.update(item.id for item in unique_findings)
                findings.extend(unique_findings)
                self.logger.debug(
                    "agent completed",
                    agent=agent.name,
                    direction=direction,
                    findings=len(unique_findings),
                    llm_enabled=agent.should_use_llm(),
                )
                for finding in unique_findings:
                    self.store.append_jsonl(f"findings/{agent.name}.jsonl", finding)
        conflicts = self.conflict_detector.detect(divergences, findings)
        self.logger.debug(
            "conflict detection complete",
            findings=len(findings),
            conflicts=len(conflicts),
            p0=sum(1 for item in conflicts if item.priority == "P0"),
            p1=sum(1 for item in conflicts if item.priority == "P1"),
            p2=sum(1 for item in conflicts if item.priority == "P2"),
        )
        for conflict in conflicts[:10]:
            self.logger.debug(
                "conflict detected",
                id=conflict.id,
                kind=conflict.kind,
                priority=conflict.priority,
                state=conflict.state,
                transition=conflict.transition,
                risk_score=conflict.risk_score,
            )
        self.logger.debug("wrote artifact", path=self.store.write_json("directions.json", directions))
        self.logger.debug("wrote artifact", path=self.store.write_json("conflicts.json", conflicts))
        return directions, findings, conflicts

    def _write_agent_llm_conversations(self, agent: object) -> None:
        drain = getattr(agent, "drain_llm_conversations", None)
        if not callable(drain):
            return
        for conversation in drain():
            self.store.append_jsonl(f"findings/{agent.name}.llm.jsonl", conversation)

    def _write_fsm_llm_conversations(self, component: object) -> None:
        drain = getattr(component, "drain_conversations", None)
        recorder = getattr(component, "recorder", None)
        if not callable(drain) or recorder is None:
            return
        for conversation in drain():
            self.store.append_jsonl(f"findings/{recorder.name}.llm.jsonl", conversation)

    def synthesize_and_fuzz(
        self,
        fsm: ProtocolFSM,
        conflicts: list[Conflict],
    ) -> tuple[list[PlannedStatePath], FuzzResult]:
        self.logger.info("planning state paths and preparing AFLNet campaign")
        candidates = self.path_planner.plan(fsm, conflicts)
        self.store.write_json("candidate_paths.json", candidates)
        calibration = self.path_calibrator.calibrate(self.config, candidates)
        planned_paths = self.path_calibrator.select(candidates)
        calibration["selected_candidate_ids"] = [path.candidate_id for path in planned_paths]
        self.store.write_json("path_calibration.json", calibration)
        self.store.write_json("calibrated_paths.json", candidates)
        self.logger.info("candidate path calibration complete", candidates=len(candidates),
                         selected=len(planned_paths), probes=calibration["probe_count"],
                         statuses=calibration["status_counts"])
        planned_paths.extend(self.cross_layer_fuzzer.synthesize_interleavings(conflicts))
        seed_intents = self.state_aware_synthesizer.synthesize(planned_paths, conflicts, self.config.protocol)
        transport_manifest = self.cross_layer_fuzzer.transport_harness_manifest(planned_paths)
        self.logger.debug("wrote artifact", path=self.store.write_json("planned_paths.json", planned_paths))
        self.logger.debug("wrote artifact", path=self.store.write_json("seed_intents.json", seed_intents))
        self.logger.debug(
            "wrote artifact",
            path=self.store.write_json("transport_harness_manifest.json", transport_manifest),
        )
        self.logger.debug(
            "path planning complete",
            conflicts=len(conflicts),
            planned_paths=len(planned_paths),
            seed_intents=len(seed_intents),
            reachable=sum(1 for item in planned_paths if item.reachable),
            unreachable=sum(1 for item in planned_paths if not item.reachable),
        )
        for path in planned_paths[:10]:
            self.logger.debug(
                "planned path",
                conflict_id=path.conflict_id,
                states="->".join(path.states),
                messages=",".join(path.messages),
                reachable=path.reachable,
            )
        prepared = self._prepare_fuzzer(planned_paths, seed_intents)
        self._write_campaign_artifacts(
            planned_paths,
            conflicts,
            prepared,
            transport_manifest,
            campaign_complete=prepared.mode in {"dry-run", "error"},
        )
        if prepared.mode == "prepared":
            fuzz_result = self.path_aware_fuzzer.execute(
                self.config,
                prepared,
                on_progress=lambda result: self._handle_fuzz_progress(
                    planned_paths,
                    conflicts,
                    result,
                    transport_manifest,
                ),
            )
            self._write_campaign_artifacts(
                planned_paths,
                conflicts,
                fuzz_result,
                transport_manifest,
                campaign_complete=True,
            )
        else:
            fuzz_result = prepared
        dynamic_analysis = self._read_optional_json("dynamic_analysis.json") or {}
        crash_replay = self._read_optional_json("crash_replay.json") or {"items": []}
        transport_result = self._read_optional_json("transport_harness_result.json") or {"executed": False, "items": []}
        self.logger.debug(
            "fuzzer preparation complete",
            mode=fuzz_result.mode,
            corpus_dir=fuzz_result.corpus_dir,
            dictionary_path=fuzz_result.dictionary_path,
            output_dir=fuzz_result.output_dir,
            command=" ".join(fuzz_result.command),
            dynamic_signals=",".join(dynamic_analysis.get("health_signals", [])),
            replay_items=len(crash_replay.get("items", [])),
            transport_executed=transport_result.get("executed", False),
        )
        return planned_paths, fuzz_result

    def _prepare_fuzzer(self, planned_paths: list[PlannedStatePath], seed_intents: list[SeedIntent]) -> FuzzResult:
        prepare = self.path_aware_fuzzer.prepare
        if "seed_intents" in inspect.signature(prepare).parameters:
            return prepare(self.config, planned_paths, seed_intents=seed_intents)
        return prepare(self.config, planned_paths)

    def _write_campaign_artifacts(
        self,
        planned_paths: list[PlannedStatePath],
        conflicts: list[Conflict],
        fuzz_result: FuzzResult,
        transport_manifest: dict[str, object],
        *,
        campaign_complete: bool,
    ) -> dict[str, object]:
        dynamic_analysis = self.dynamic_analyzer.analyze(fuzz_result)
        dynamic_analysis["campaign_complete"] = campaign_complete
        dynamic_analysis["campaign_phase"] = fuzz_result.mode
        state_mapping = self.state_mapper.map(dynamic_analysis, planned_paths)
        seed_manifest = self._read_optional_json("seed_manifest.json")
        seed_feedback = self.seed_feedback_analyzer.analyze(
            dynamic_analysis,
            seed_manifest if isinstance(seed_manifest, dict) else None,
        )
        if campaign_complete:
            crash_replay = self.crash_replay_verifier.verify(self.config, fuzz_result)
            replanning_plan = self.closed_loop_replanner.plan(dynamic_analysis, planned_paths, conflicts, seed_feedback)
            transport_result = self.transport_harness.execute(self.config, transport_manifest)
        else:
            crash_replay = _pending_crash_replay(fuzz_result)
            replanning_plan = _pending_replanning_plan(fuzz_result, seed_feedback)
            transport_result = _pending_transport_result(fuzz_result)
        self.logger.debug("wrote artifact", path=self.store.write_json("fuzz_result.json", fuzz_result))
        self.logger.debug("wrote artifact", path=self.store.write_json("dynamic_analysis.json", dynamic_analysis))
        self.logger.debug("wrote artifact", path=self.store.write_json("state_mapping.json", state_mapping))
        self.logger.debug("wrote artifact", path=self.store.write_json("seed_feedback.json", seed_feedback))
        self.logger.debug("wrote artifact", path=self.store.write_json("crash_replay.json", crash_replay))
        self.logger.debug("wrote artifact", path=self.store.write_json("replanning_plan.json", replanning_plan))
        self.logger.debug(
            "wrote artifact",
            path=self.store.write_json("transport_harness_result.json", transport_result),
        )
        self.logger.debug("wrote artifact", path=self.store.write_json("monitor_agent_report.json", self.monitor_agent.report()))
        return dynamic_analysis

    def _handle_fuzz_progress(
        self,
        planned_paths: list[PlannedStatePath],
        conflicts: list[Conflict],
        fuzz_result: FuzzResult,
        transport_manifest: dict[str, object],
    ) -> None:
        dynamic_analysis = self._write_campaign_artifacts(
            planned_paths,
            conflicts,
            fuzz_result,
            transport_manifest,
            campaign_complete=False,
        )
        seed_feedback = self._read_optional_json("seed_feedback.json")
        decision = self.monitor_agent.observe(
            self.config,
            fuzz_result,
            dynamic_analysis,
            planned_paths,
            conflicts,
            seed_feedback=seed_feedback if isinstance(seed_feedback, dict) else None,
        )
        self._write_monitor_llm_conversations()
        if decision is None:
            return
        self.store.append_jsonl("findings/monitor_agent.jsonl", decision)
        self.logger.debug("wrote artifact", path=self.store.write_json("monitor_agent_report.json", self.monitor_agent.report()))
        if decision.get("generated_seeds"):
            self.logger.info(
                "monitor agent injected breakthrough seeds",
                generated=len(decision.get("generated_seeds", [])),
                import_dir=decision.get("import_dir", ""),
            )

    def _write_monitor_llm_conversations(self) -> None:
        for conversation in self.monitor_agent.drain_llm_conversations():
            self.store.append_jsonl("findings/monitor_agent.llm.jsonl", conversation)

    def run(self, *, force_fsm: bool = False) -> dict[str, object]:
        self.logger.debug("end-to-end run started")
        self.init_run()
        _, _, unified_fsm, divergences = self.build_fsm(force=force_fsm)
        _, findings, conflicts = self.reason(unified_fsm, divergences)
        planned_paths, fuzz_result = self.synthesize_and_fuzz(unified_fsm, conflicts)
        self.write_report(unified_fsm, divergences, conflicts, planned_paths, fuzz_result)
        self.logger.debug(
            "end-to-end run completed",
            states=len(unified_fsm.states),
            transitions=len(unified_fsm.transitions),
            divergences=len(divergences),
            findings=len(findings),
            conflicts=len(conflicts),
            planned_paths=len(planned_paths),
            fuzz_mode=fuzz_result.mode,
        )
        return {
            "run_dir": str(self.config.run_dir),
            "states": len(unified_fsm.states),
            "transitions": len(unified_fsm.transitions),
            "divergences": len(divergences),
            "findings": len(findings),
            "conflicts": len(conflicts),
            "planned_paths": len(planned_paths),
            "fuzz_mode": fuzz_result.mode,
            "fsm_stage_reuse": dict(self.stage_reuse),
        }

    def write_report(
        self,
        fsm: ProtocolFSM,
        divergences: list[Divergence],
        conflicts: list[Conflict],
        planned_paths: list[PlannedStatePath],
        fuzz_result: FuzzResult,
    ) -> None:
        lines = [
            "# ProtoLens Report",
            "",
            f"- Protocol: {self.config.protocol}",
            f"- Target: {self.config.target_name}",
            f"- States: {len(fsm.states)}",
            f"- Transitions: {len(fsm.transitions)}",
            f"- Divergences: {len(divergences)}",
            f"- Conflicts: {len(conflicts)}",
            f"- Fuzz mode: {fuzz_result.mode}",
            "",
            "## Top Conflicts",
            "",
        ]
        for conflict in conflicts[:20]:
            lines.extend(
                [
                    f"### {conflict.priority} {conflict.kind} {conflict.id}",
                    "",
                    conflict.description,
                    "",
                    f"- State: {conflict.state}",
                    f"- Transition: {conflict.transition or '<state-level>'}",
                    f"- Strategy: {conflict.fuzzing_strategy}",
                    "",
                ]
            )
        lines.extend(["## Planned Paths", ""])
        for path in planned_paths[:20]:
            calibration = path.calibration or {}
            lines.extend(
                [
                    f"- {path.conflict_id}: {' -> '.join(path.states)}",
                    f"  candidate: {path.candidate_id or '<none>'}",
                    f"  messages: {', '.join(path.messages) if path.messages else '<none>'}",
                    f"  reachable: {path.reachable}",
                    f"  calibration: {calibration.get('status', '<none>')} "
                    f"accepted_prefix={calibration.get('accepted_prefix_length', 0)} "
                    f"state_verified={calibration.get('state_verified', False)}",
                ]
            )
        lines.extend(["", "## AFLNet Command", "", "```text", " ".join(fuzz_result.command), "```", ""])
        for note in fuzz_result.notes:
            lines.append(f"- {note}")
        path_calibration = self._read_optional_json("path_calibration.json")
        dynamic = self._read_optional_json("dynamic_analysis.json")
        crash_replay = self._read_optional_json("crash_replay.json")
        replanning = self._read_optional_json("replanning_plan.json")
        state_mapping = self._read_optional_json("state_mapping.json")
        seed_feedback = self._read_optional_json("seed_feedback.json")
        transport_result = self._read_optional_json("transport_harness_result.json")
        monitor_report = self._read_optional_json("monitor_agent_report.json")
        if path_calibration:
            statuses = path_calibration.get("status_counts", {}) if isinstance(path_calibration, dict) else {}
            selected = path_calibration.get("selected_candidate_ids", []) if isinstance(path_calibration, dict) else []
            lines.extend(
                [
                    "",
                    "## Path Calibration",
                    "",
                    f"- Probes: {path_calibration.get('probe_count', 0) if isinstance(path_calibration, dict) else 0}",
                    f"- Target starts: {path_calibration.get('target_start_count', 0) if isinstance(path_calibration, dict) else 0}",
                    f"- Connected: {path_calibration.get('connected_count', 0) if isinstance(path_calibration, dict) else 0}",
                    f"- Statuses: {json.dumps(statuses, ensure_ascii=False, sort_keys=True)}",
                    f"- Selected candidates: {', '.join(selected) if selected else '<none>'}",
                ]
            )
        if dynamic:
            lines.extend(
                [
                    "",
                    "## Dynamic Feedback",
                    "",
                    f"- Stats present: {dynamic.get('stats_present', False)}",
                    f"- Queue: {dynamic.get('queue_count', 0)}",
                    f"- Crashes: {dynamic.get('crash_count', 0)}",
                    f"- Hangs: {dynamic.get('hang_count', 0)}",
                    f"- Signals: {', '.join(dynamic.get('health_signals', [])) or '<none>'}",
                ]
            )
        if state_mapping:
            observed = sum(1 for item in state_mapping.get("items", []) if item.get("status") == "observed")
            lines.extend(["", "## AFLNet State Mapping", "", f"- Observed planned paths: {observed}/{len(state_mapping.get('items', []))}"])
        if seed_feedback:
            lines.extend(
                [
                    "",
                    "## Seed Feedback",
                    "",
                    f"- Seed manifest present: {seed_feedback.get('seed_manifest_present', False)}",
                    f"- Observed seeds: {seed_feedback.get('observed_count', 0)}/{seed_feedback.get('seed_count', 0)}",
                    f"- Variants: {len(seed_feedback.get('by_variant', []))}",
                ]
            )
        if crash_replay:
            confirmed = sum(1 for item in crash_replay.get("items", []) if item.get("confirmed"))
            lines.extend(["", "## Crash Replay", "", f"- Confirmed crashes: {confirmed}/{len(crash_replay.get('items', []))}"])
        if replanning:
            lines.extend(
                [
                    "",
                    "## Replanning",
                    "",
                    f"- Dynamic basis present: {replanning.get('based_on_dynamic_output', False)}",
                    f"- Recommended actions: {len(replanning.get('actions', []))}",
                ]
            )
        if transport_result:
            lines.extend(
                [
                    "",
                    "## Transport Harness",
                    "",
                    f"- Executed: {transport_result.get('executed', False)}",
                    f"- Items: {len(transport_result.get('items', []))}",
                    f"- Reason: {transport_result.get('reason', '<none>')}",
                ]
            )
        if monitor_report:
            decisions = monitor_report.get("decisions", []) if isinstance(monitor_report, dict) else []
            generated = sum(len(item.get("generated_seeds", [])) for item in decisions if isinstance(item, dict))
            last_status = decisions[-1].get("status") if decisions and isinstance(decisions[-1], dict) else "<none>"
            lines.extend(["", "## Monitor Agent", "", f"- Decisions: {len(decisions)}", f"- Generated seeds: {generated}", f"- Last status: {last_status}"])
        path = self.store.write_text("report.md", "\n".join(lines))
        self.logger.debug("wrote report", path=path)

    def _read_optional_json(self, name: str) -> object | None:
        path = self.store.path(name)
        if not path.exists():
            return None
        return self.store.read_json(name)

    def _load_implementation_fsm(self) -> ProtocolFSM:
        artifact = self.store.read_json("impl_fsm.json")
        evidence_artifact = self.store.read_json("implementation_evidence_table.json")
        if not isinstance(artifact, dict):
            raise ValueError("impl_fsm.json must be an object")
        if not isinstance(evidence_artifact, dict) or evidence_artifact.get("version") != 1:
            raise ValueError("implementation_evidence_table.json has an unsupported format")
        entries = evidence_artifact.get("entries")
        if not isinstance(entries, dict):
            raise ValueError("implementation evidence table entries must be an object")

        hydrated = dict(artifact)
        hydrated_transitions: list[dict[str, object]] = []
        transitions = artifact.get("transitions")
        if not isinstance(transitions, list):
            raise ValueError("impl_fsm.json transitions must be an array")
        for source_transition in transitions:
            if not isinstance(source_transition, dict):
                raise ValueError("implementation FSM transition must be an object")
            transition = dict(source_transition)
            evidence_ids = transition.pop("evidence_ids", None)
            if not isinstance(evidence_ids, list) or not evidence_ids:
                raise ValueError(
                    f"implementation transition {transition.get('id')!r} must reference evidence_ids"
                )
            missing = [str(item) for item in evidence_ids if str(item) not in entries]
            if missing:
                raise ValueError(f"implementation FSM references unknown evidence ids: {missing}")
            transition["evidence"] = [entries[str(item)] for item in evidence_ids]
            hydrated_transitions.append(transition)
        hydrated["transitions"] = hydrated_transitions
        return ProtocolFSM.from_dict(hydrated)


def _code_evidence_from_fsm(fsm: ProtocolFSM) -> list[Evidence]:
    evidence_items: list[Evidence] = []
    seen: set[tuple[str, str]] = set()
    for transition in fsm.transitions:
        for evidence in transition.evidence:
            if evidence.source_type.lower() not in {"code", "source", "implementation"}:
                continue
            key = (evidence.location, evidence.excerpt)
            if key in seen:
                continue
            seen.add(key)
            evidence_items.append(evidence)
    return evidence_items


def _llm_cache_identity(config: ProtoLensConfig) -> dict[str, object]:
    return {
        "provider": config.llm.provider,
        "model": config.llm.model,
        "temperature": config.llm.temperature,
        "base_url": config.llm.base_url,
        "max_tokens": config.llm.max_tokens,
        "response_format": config.llm.response_format,
        "extra_headers": config.llm.extra_headers,
    }


def _pending_crash_replay(fuzz_result: FuzzResult) -> dict[str, object]:
    return {
        "format": "protolens.crash_replay.v1",
        "status": "pending",
        "items": [],
        "notes": [
            f"campaign phase is {fuzz_result.mode}; "
            "crash replay runs only after the AFLNet campaign reaches a terminal state"
        ],
    }


def _pending_replanning_plan(fuzz_result: FuzzResult, seed_feedback: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "format": "protolens.closed_loop_replanning.v1",
        "status": "pending",
        "based_on_dynamic_output": False,
        "actions": [],
        "next_round_path_priorities": [],
        "seed_feedback_present": bool(seed_feedback and seed_feedback.get("seed_manifest_present")),
        "seed_actions": [],
        "next_round_seed_priorities": [],
        "notes": [
            f"campaign phase is {fuzz_result.mode}; "
            "closed-loop replanning runs after terminal dynamic feedback is available"
        ],
    }


def _pending_transport_result(fuzz_result: FuzzResult) -> dict[str, object]:
    return {
        "format": "protolens.transport_harness_result.v1",
        "status": "pending",
        "executed": False,
        "reason": (
            f"campaign phase is {fuzz_result.mode}; "
            "transport harness execution is deferred until campaign completion"
        ),
        "items": [],
    }


def _implementation_capabilities(artifact: object) -> list[dict[str, str]]:
    if not isinstance(artifact, dict) or artifact.get("version") != 1:
        raise ValueError("implementation_transition_facts.json has an unsupported format")
    facts = artifact.get("facts")
    if not isinstance(facts, list):
        raise ValueError("implementation_transition_facts.json facts must be an array")

    capabilities: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for fact in facts:
        if not isinstance(fact, dict):
            raise ValueError("implementation transition fact must be an object")
        trigger = str(fact.get("trigger", "")).strip()
        if not trigger:
            raise ValueError("implementation transition fact requires trigger")
        message_type = str(fact.get("message_type") or trigger).strip()
        key = (message_type, trigger)
        if key in seen:
            continue
        seen.add(key)
        capabilities.append({"message_type": message_type, "trigger": trigger})
    return capabilities


def _implementation_fsm_with_evidence_refs(
    fsm: ProtocolFSM,
    evidence_artifact: object,
) -> dict[str, object]:
    if not isinstance(evidence_artifact, dict) or not isinstance(evidence_artifact.get("entries"), dict):
        raise ValueError("implementation evidence table is unavailable")
    entries = evidence_artifact["entries"]
    evidence_ids_by_value = {
        stable_fingerprint(value): evidence_id
        for evidence_id, value in entries.items()
    }
    artifact = fsm.to_dict()
    compact_transitions: list[dict[str, object]] = []
    for source_transition in artifact["transitions"]:
        transition = dict(source_transition)
        evidence_ids: list[str] = []
        for evidence in transition.pop("evidence", []):
            evidence_id = evidence_ids_by_value.get(stable_fingerprint(evidence))
            if evidence_id is None:
                raise ValueError(
                    f"implementation transition {transition.get('id')!r} contains evidence absent from EvidenceTable"
                )
            if evidence_id not in evidence_ids:
                evidence_ids.append(evidence_id)
        if not evidence_ids:
            raise ValueError(f"implementation transition {transition.get('id')!r} has no EvidenceTable references")
        transition["evidence_ids"] = evidence_ids
        compact_transitions.append(transition)
    artifact["transitions"] = compact_transitions
    metadata = dict(artifact.get("metadata", {}))
    metadata["evidence_storage"] = "references_only"
    metadata["evidence_table_artifact"] = "implementation_evidence_table.json"
    artifact["metadata"] = metadata
    return artifact
