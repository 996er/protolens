from pathlib import Path
from tempfile import TemporaryDirectory
import json
import shutil
import unittest

from protolens.config import ProtoLensConfig
from protolens.agents.attacker_agent import AttackerAgent
from protolens.agents.base_agent import AgentContext
from protolens.agents.cross_layer_agent import CrossLayerAgent
from protolens.agents.defender_agent import DefenderAgent
from protolens.fsm.fsm_model import Conflict, Evidence, FuzzResult, PlannedStatePath
from protolens.fsm.fsm_model import ProtocolFSM, StateTransition
from protolens.fsm.fsm_merger import FSMMerger
from protolens.fsm.impl_fsm_builder import ImplementationFSMBuilder
from protolens.fsm.spec_fsm_builder import SpecificationFSMBuilder
from protolens.pipeline import ProtoLensPipeline
from protolens.utils.llm_client import LLMResponse
from tests.fsm_fakes import FakeFSMClient


class FakeLLMClient:
    is_offline = False
    retries = 0

    def chat_json(self, *, system: str, user: str) -> LLMResponse:
        self.system = system
        self.user = user
        return LLMResponse(
            text=(
                '{"findings":[{"state":"START","transition":"START --PLAY-> PLAYING",'
                '"claim":"LLM identified a disputed fast path.","confidence":0.91,'
                '"preconditions":["reach START"],'
                '"suggested_tests":["send PLAY before SETUP"],'
                '"evidence":[{"source_type":"reasoning","location":"fake",'
                '"excerpt":"fake evidence","confidence":0.8}]}]}'
            ),
            provider="fake",
            model="fake",
        )


class BadJsonLLMClient:
    is_offline = False
    retries = 0
    provider = "fake"
    model = "bad-json"

    def chat_json(self, *, system: str, user: str) -> LLMResponse:
        return LLMResponse(
            text=(
                '{"findings":[{"state":"START","transition":null,'
                '"claim":"Recoverable trailing comma.","confidence":0.7,'
                '"preconditions":[],"suggested_tests":[],'
                '"evidence":[{"source_type":"reasoning","location":"fake",'
                '"excerpt":"fake","confidence":0.5,},],}]}'
            ),
            provider="fake",
            model="bad-json",
        )


class EmptyLLMClient:
    is_offline = False
    retries = 0
    provider = "fake"
    model = "empty"

    def chat_json(self, *, system: str, user: str) -> LLMResponse:
        raise RuntimeError("LLM request failed after 3 attempt(s): LLM returned an empty response")


class SchemaRecordingLLMClient:
    is_offline = False
    retries = 0
    provider = "fake"
    model = "schema-aware"

    def chat_json(
        self,
        *,
        system: str,
        user: str,
        response_schema: dict | None = None,
        schema_name: str = "",
    ) -> LLMResponse:
        self.system = system
        self.user = user
        self.response_schema = response_schema
        self.schema_name = schema_name
        return LLMResponse(
            text='{"findings":[]}',
            provider="fake",
            model="schema-aware",
        )


class CountingFSMClient(FakeFSMClient):
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.payloads: list[tuple[str, dict]] = []

    def responses_json(
        self,
        *,
        system: str,
        user: str,
        response_schema: dict,
        schema_name: str,
        web_search: bool = False,
        allowed_domains: list[str] | None = None,
        max_tool_calls: int | None = None,
    ) -> LLMResponse:
        self.calls.append(schema_name)
        self.payloads.append((schema_name, json.loads(user)))
        return super().responses_json(
            system=system,
            user=user,
            response_schema=response_schema,
            schema_name=schema_name,
            web_search=web_search,
            allowed_domains=allowed_domains,
            max_tool_calls=max_tool_calls,
        )


class _SnapshotFuzzer:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir

    def prepare(self, config: ProtoLensConfig, paths: list[PlannedStatePath]) -> FuzzResult:
        corpus_dir = self.run_dir / "in"
        output_dir = self.run_dir / "out"
        dictionary_path = self.run_dir / "rtsp.dict"
        corpus_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        dictionary_path.write_text('tok_0="OPTIONS"\n', encoding="utf-8")
        return FuzzResult(
            mode="prepared",
            command=["/bin/true", "-i", str(corpus_dir), "-o", str(output_dir), "--", "/bin/true"],
            corpus_dir=str(corpus_dir),
            dictionary_path=str(dictionary_path),
            output_dir=str(output_dir),
            notes=["AFLNet queue schedule: " + str(self.run_dir / "weights.tsv")],
        )

    def execute(self, config: ProtoLensConfig, prepared: FuzzResult, on_progress=None) -> FuzzResult:
        running = FuzzResult(
            mode="running",
            command=prepared.command,
            corpus_dir=prepared.corpus_dir,
            dictionary_path=prepared.dictionary_path,
            output_dir=prepared.output_dir,
            notes=["AFLNet campaign is running."],
            process_id=1234,
        )
        if on_progress is not None:
            on_progress(running)
        for name in (
            "candidate_paths.json",
            "path_calibration.json",
            "calibrated_paths.json",
            "planned_paths.json",
            "fuzz_result.json",
            "dynamic_analysis.json",
            "state_mapping.json",
            "crash_replay.json",
            "replanning_plan.json",
            "transport_harness_manifest.json",
            "transport_harness_result.json",
            "monitor_agent_report.json",
        ):
            assert (config.run_dir / name).exists(), name
        dynamic = json.loads((config.run_dir / "dynamic_analysis.json").read_text(encoding="utf-8"))
        assert dynamic["campaign_phase"] == "running"
        assert dynamic["campaign_complete"] is False
        return FuzzResult(
            mode="timed-out",
            command=prepared.command,
            corpus_dir=prepared.corpus_dir,
            dictionary_path=prepared.dictionary_path,
            output_dir=prepared.output_dir,
            exit_code=124,
            notes=["campaign stopped after 1 seconds"],
            process_id=1234,
        )


class PipelineTest(unittest.TestCase):
    def test_sample_pipeline_runs(self) -> None:
        with TemporaryDirectory() as tmp:
            config = ProtoLensConfig.load("benchmarks/rtsp_live555.json")
            config.run_dir = Path(tmp) / "run"
            pipeline = ProtoLensPipeline(config)
            fake = FakeFSMClient()
            pipeline.spec_builder = SpecificationFSMBuilder(fake)
            pipeline.impl_builder = ImplementationFSMBuilder(fake)
            pipeline.merger = FSMMerger(fake)
            result = pipeline.run()
            self.assertGreaterEqual(result["divergences"], 1)
            self.assertGreaterEqual(result["conflicts"], 1)
            self.assertTrue((config.run_dir / "report.md").exists())
            self.assertTrue((config.run_dir / "dynamic_analysis.json").exists())
            self.assertTrue((config.run_dir / "state_mapping.json").exists())
            self.assertTrue((config.run_dir / "crash_replay.json").exists())
            self.assertTrue((config.run_dir / "replanning_plan.json").exists())
            self.assertTrue((config.run_dir / "transport_harness_manifest.json").exists())
            self.assertTrue((config.run_dir / "transport_harness_result.json").exists())
            self.assertTrue((config.run_dir / "monitor_agent_report.json").exists())
            self.assertTrue((config.run_dir / "seed_intents.json").exists())
            self.assertTrue((config.run_dir / "seed_manifest.json").exists())
            self.assertTrue((config.run_dir / "seed_feedback.json").exists())
            self.assertTrue((config.run_dir / "implementation_source_manifest.json").exists())
            self.assertTrue((config.run_dir / "implementation_transition_facts.json").exists())
            self.assertTrue((config.run_dir / "implementation_evidence_table.json").exists())
            self.assertTrue((config.run_dir / "checkpoints" / "fsm_stages.json").exists())
            self.assertTrue((config.run_dir / "findings" / "fsm_specification.llm.jsonl").exists())

    def test_fuzz_artifacts_are_written_while_campaign_is_running(self) -> None:
        with TemporaryDirectory() as tmp:
            config = ProtoLensConfig.load("benchmarks/rtsp_live555.json")
            config.run_dir = Path(tmp) / "run"
            pipeline = ProtoLensPipeline(config)
            pipeline.path_aware_fuzzer = _SnapshotFuzzer(config.run_dir)
            fsm = ProtocolFSM(
                protocol="rtsp",
                states={},
                transitions=[StateTransition("START", "READY", "OPTIONS")],
                initial_state="START",
            )
            conflicts = [
                Conflict(
                    kind="fsm_divergence",
                    priority="P1",
                    state="START",
                    transition=None,
                    description="exercise running snapshot",
                    expected_path=["START", "READY"],
                    fuzzing_strategy="send OPTIONS",
                )
            ]

            _, fuzz_result = pipeline.synthesize_and_fuzz(fsm, conflicts)

            self.assertEqual(fuzz_result.mode, "timed-out")
            final_dynamic = json.loads((config.run_dir / "dynamic_analysis.json").read_text(encoding="utf-8"))
            self.assertTrue(final_dynamic["campaign_complete"])
            self.assertTrue((config.run_dir / "findings" / "monitor_agent.jsonl").exists())
            self.assertTrue((config.run_dir / "seed_intents.json").exists())
            self.assertTrue((config.run_dir / "seed_feedback.json").exists())

    def test_fsm_stages_resume_without_repeating_llm_calls(self) -> None:
        with TemporaryDirectory() as tmp:
            config = ProtoLensConfig.load("benchmarks/rtsp_live555.json")
            config.run_dir = Path(tmp) / "run"
            pipeline = ProtoLensPipeline(config)
            fake = CountingFSMClient()
            pipeline.spec_builder = SpecificationFSMBuilder(fake)
            pipeline.impl_builder = ImplementationFSMBuilder(fake)
            pipeline.merger = FSMMerger(fake)
            pipeline.init_run()

            pipeline.build_fsm()
            first_calls = list(fake.calls)
            self.assertIn("protolens_impl_fsm_assemble", first_calls)
            self.assertEqual(first_calls.count("protolens_impl_fsm_assemble"), 1)
            self.assertFalse(any("consolidat" in name for name in first_calls))

            pipeline.build_fsm()

            self.assertEqual(fake.calls, first_calls)
            self.assertEqual(
                pipeline.stage_reuse,
                {"implementation": True, "specification": True, "merge": True},
            )

    def test_implementation_artifacts_store_source_excerpt_only_in_evidence_table(self) -> None:
        with TemporaryDirectory() as tmp:
            config = ProtoLensConfig.load("benchmarks/rtsp_live555.json")
            config.run_dir = Path(tmp) / "run"
            pipeline = ProtoLensPipeline(config)
            fake = CountingFSMClient()
            pipeline.impl_builder = ImplementationFSMBuilder(fake)
            pipeline.init_run()

            pipeline.build_implementation()

            facts = json.loads((config.run_dir / "implementation_transition_facts.json").read_text(encoding="utf-8"))
            evidence_table = json.loads((config.run_dir / "implementation_evidence_table.json").read_text(encoding="utf-8"))
            compact_fsm = json.loads((config.run_dir / "impl_fsm.json").read_text(encoding="utf-8"))
            self.assertTrue(facts["facts"])
            self.assertTrue(evidence_table["entries"])
            self.assertTrue(all("evidence" not in fact for fact in facts["facts"]))
            self.assertTrue(all(fact["evidence_ids"] for fact in facts["facts"]))
            self.assertTrue(all("evidence" not in transition for transition in compact_fsm["transitions"]))
            self.assertTrue(all(transition["evidence_ids"] for transition in compact_fsm["transitions"]))
            excerpt = next(iter(evidence_table["entries"].values()))["excerpt"]
            self.assertNotIn(excerpt, json.dumps(facts, ensure_ascii=False))
            self.assertNotIn(excerpt, json.dumps(compact_fsm, ensure_ascii=False))

    def test_source_change_invalidates_all_downstream_fsm_checkpoints(self) -> None:
        with TemporaryDirectory() as tmp:
            config = ProtoLensConfig.load("benchmarks/rtsp_live555.json")
            source_copy = Path(tmp) / "source"
            shutil.copytree(config.source_root, source_copy)
            config.source_root = source_copy
            config.run_dir = Path(tmp) / "run"
            pipeline = ProtoLensPipeline(config)
            fake = CountingFSMClient()
            pipeline.spec_builder = SpecificationFSMBuilder(fake)
            pipeline.impl_builder = ImplementationFSMBuilder(fake)
            pipeline.merger = FSMMerger(fake)
            pipeline.init_run()

            pipeline.build_fsm()
            first_call_count = len(fake.calls)
            source_path = source_copy / config.entrypoints[0]
            source_path.write_text(source_path.read_text(encoding="utf-8") + "\n/* checkpoint invalidation */\n", encoding="utf-8")

            pipeline.build_fsm()

            self.assertGreater(len(fake.calls), first_call_count)
            self.assertEqual(
                pipeline.stage_reuse,
                {"implementation": False, "specification": False, "merge": False},
            )

    def test_specification_scope_receives_only_compact_implementation_capabilities(self) -> None:
        with TemporaryDirectory() as tmp:
            config = ProtoLensConfig.load("benchmarks/rtsp_live555.json")
            config.run_dir = Path(tmp) / "run"
            pipeline = ProtoLensPipeline(config)
            fake = CountingFSMClient()
            pipeline.spec_builder = SpecificationFSMBuilder(fake)
            pipeline.impl_builder = ImplementationFSMBuilder(fake)
            pipeline.init_run()

            pipeline.build_implementation()
            pipeline.build_specification()

            spec_payload = next(
                payload
                for schema_name, payload in fake.payloads
                if schema_name == "protolens_specification_fsm"
            )
            self.assertEqual(spec_payload["analysis_scope"], config.fsm_build.rfc_analysis_scope)
            self.assertTrue(spec_payload["target_implementation_capabilities"])
            self.assertEqual(
                set(spec_payload["target_implementation_capabilities"][0]),
                {"message_type", "trigger"},
            )
            self.assertNotIn("evidence", json.dumps(spec_payload["target_implementation_capabilities"]))

    def test_agent_uses_llm_when_configured(self) -> None:
        fsm = ProtocolFSM(
            protocol="rtsp",
            states={},
            transitions=[],
            initial_state="START",
        )
        fsm.add_transition(StateTransition("START", "PLAYING", "PLAY"))
        agent = AttackerAgent(FakeLLMClient())
        findings = agent.analyze(
            AgentContext(
                protocol="rtsp",
                direction="Spec-implementation divergence reachability",
                fsm=fsm,
                divergences=[],
            )
        )
        self.assertEqual(findings[0].agent, "attacker")
        self.assertEqual(findings[0].confidence, 0.91)
        self.assertIn("LLM identified", findings[0].claim)
        conversations = agent.drain_llm_conversations()
        self.assertEqual(len(conversations), 1)
        self.assertIn("ProtoLens AttackerAgent", conversations[0]["system"])
        self.assertIn("required_output", conversations[0]["user"])
        self.assertIn("LLM identified", conversations[0]["response"]["text"])

    def test_agent_repairs_common_malformed_json(self) -> None:
        fsm = ProtocolFSM(
            protocol="rtsp",
            states={},
            transitions=[],
            initial_state="START",
        )
        agent = AttackerAgent(BadJsonLLMClient())

        findings = agent.analyze(
            AgentContext(
                protocol="rtsp",
                direction="Spec-implementation divergence reachability",
                fsm=fsm,
                divergences=[],
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].claim, "Recoverable trailing comma.")

    def test_agent_returns_empty_findings_on_empty_llm_response(self) -> None:
        fsm = ProtocolFSM(
            protocol="rtsp",
            states={},
            transitions=[],
            initial_state="START",
        )
        fsm.add_transition(StateTransition("START", "PLAYING", "PLAY"))
        agent = AttackerAgent(EmptyLLMClient())

        findings = agent.analyze(
            AgentContext(
                protocol="rtsp",
                direction="Spec-implementation divergence reachability",
                fsm=fsm,
                divergences=[],
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].agent, "attacker")
        self.assertTrue(agent.last_llm_failed())
        conversations = agent.drain_llm_conversations()
        self.assertEqual(conversations[-1]["final_status"], "llm_failed_rule_fallback_required")

    def test_all_agents_use_rule_fallback_after_empty_llm_response(self) -> None:
        fsm = ProtocolFSM(
            protocol="ftp",
            states={},
            transitions=[],
            initial_state="START",
        )
        fsm.add_transition(StateTransition("START", "AUTHENTICATED", "AUTH", guard="valid TLS session"))
        context = AgentContext(
            protocol="ftp",
            direction="Cross-layer state synchronization",
            fsm=fsm,
            divergences=[],
            code_snippets=[
                Evidence("code", "server.c:10", "tls session connection auth state", 0.7),
            ],
        )

        for agent_cls in (AttackerAgent, DefenderAgent, CrossLayerAgent):
            agent = agent_cls(EmptyLLMClient())
            findings = agent.analyze(context)
            self.assertTrue(agent.last_llm_failed(), agent.name)
            self.assertGreaterEqual(len(findings), 1, agent.name)

    def test_cross_layer_agent_passes_json_schema_to_llm(self) -> None:
        fsm = ProtocolFSM(
            protocol="rtsp",
            states={},
            transitions=[],
            initial_state="START",
        )
        llm = SchemaRecordingLLMClient()
        agent = CrossLayerAgent(llm)

        findings = agent.analyze(
            AgentContext(
                protocol="rtsp",
                direction="Cross-layer state synchronization",
                fsm=fsm,
                divergences=[],
            )
        )

        self.assertEqual(findings, [])
        self.assertEqual(llm.schema_name, "protolens_cross_layer_findings")
        self.assertIsNotNone(llm.response_schema)
        self.assertEqual(llm.response_schema["required"], ["findings"])
        self.assertIn("json_schema", json.loads(llm.user))
        conversations = agent.drain_llm_conversations()
        self.assertEqual(conversations[0]["schema_name"], "protolens_cross_layer_findings")

    def test_pipeline_writes_agent_llm_conversations_to_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            config = ProtoLensConfig.load("benchmarks/rtsp_live555.json")
            config.run_dir = Path(tmp) / "run"
            pipeline = ProtoLensPipeline(config)
            pipeline.agents = [AttackerAgent(FakeLLMClient())]
            fsm = ProtocolFSM(
                protocol="rtsp",
                states={},
                transitions=[],
                initial_state="START",
            )
            fsm.add_transition(StateTransition("START", "PLAYING", "PLAY"))

            pipeline.reason(fsm, [])

            path = config.run_dir / "findings" / "attacker.llm.jsonl"
            self.assertTrue(path.exists())
            first = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(first["agent"], "attacker")
            self.assertIn("system", first)
            self.assertIn("user", first)
            self.assertIn("response", first)


if __name__ == "__main__":
    unittest.main()
