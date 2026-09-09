from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import threading
import unittest

from protolens.agents.monitor_agent import MonitorAgent
from protolens.config import AFLNetConfig, AFLNetMonitorConfig, LLMConfig, ProtoLensConfig
from protolens.fsm.fsm_merger import FSMMerger
from protolens.fsm.fsm_model import Conflict, Evidence, FuzzResult, PlannedStatePath, ProtocolFSM, SeedIntent, StateTransition
from protolens.fsm.impl_fsm_builder import ImplementationFSMBuilder
from protolens.fsm.llm_support import (
    LLMConversationRecorder,
    canonical_source_url,
    normalize_fsm_protocol,
    protocol_label_matches,
    response_source_urls,
)
from protolens.fsm.spec_fsm_builder import SpecificationFSMBuilder
from protolens.fuzzer.aflnet_feedback import AFLNetDynamicAnalyzer, AFLNetStateMapper, SeedFeedbackAnalyzer
from protolens.fuzzer.aflnet_adapter import AFLNetAdapter
from protolens.fuzzer.aflnet_adapter import _list_findings
from protolens.fuzzer.state_aware_synthesizer import StateAwareTestSynthesizer
from protolens.fuzzer.transport_harness import TransportAwareHarness
from protolens.main import main as protolens_main
from protolens.tools.corpus_encoder import CorpusEncoder
from protolens.tools.rfc_parser import RFCParser
from protolens.tools.static_analysis import StaticAnalysis
from protolens.utils.llm_client import IncompleteLLMResponse, LLMClient, LLMResponse
from tests.fsm_fakes import FakeFSMClient


def _config(root: Path, *, dry_run: bool = True, binary: str = "/bin/true") -> ProtoLensConfig:
    spec = root / "spec.txt"
    spec.write_text("TRANSITION: START -- USER -> READY\n", encoding="utf-8")
    return ProtoLensConfig(
        protocol="ftp",
        target_name="test-target",
        spec_paths=[spec],
        source_root=root,
        entrypoints=[],
        host="127.0.0.1",
        port=2121,
        run_command="/bin/true",
        run_dir=root / "run",
        aflnet=AFLNetConfig(binary=binary, duration_seconds=1, dry_run=dry_run, cmd=[binary]),
        monitor_agent=AFLNetMonitorConfig(interval_seconds=0.01, stagnation_seconds=0.01, min_exec_delta=0),
        llm=LLMConfig(),
    )


class CorpusEncoderTest(unittest.TestCase):
    def test_rtsp_seed_is_raw_protocol_stream(self) -> None:
        with TemporaryDirectory() as tmp:
            path = PlannedStatePath("conflict", ["START", "READY", "PLAYING"], ["DESCRIBE", "PLAY"])
            files = CorpusEncoder().write_corpus([path], Path(tmp), "rtsp")
            payload = files[0].read_bytes()

            self.assertTrue(payload.startswith(b"DESCRIBE "))
            self.assertNotEqual(payload[:4], len(payload[4:]).to_bytes(4, "big"))
            self.assertIn(b"CSeq: 1\r\n", payload)
            self.assertIn(b"CSeq: 2\r\n", payload)

    def test_ftp_seed_skips_server_side_connect_event(self) -> None:
        with TemporaryDirectory() as tmp:
            path = PlannedStatePath("conflict", ["START", "CONNECTED", "USER_SEEN"], ["CONNECT", "USER", "PASS"])
            files = CorpusEncoder().write_corpus([path], Path(tmp), "ftp")
            self.assertEqual(
                files[0].read_bytes(),
                b"USER anonymous\r\nPASS protolens@example.com\r\n",
            )

    def test_rewrite_removes_stale_generated_seed(self) -> None:
        with TemporaryDirectory() as tmp:
            corpus = Path(tmp)
            stale = corpus / "id_999999_stale.raw"
            stale.write_bytes(b"stale")
            path = PlannedStatePath("new", ["START"], ["USER"])
            CorpusEncoder().write_corpus([path], corpus, "ftp")
            self.assertFalse(stale.exists())

    def test_queue_schedule_uses_mutation_points(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = PlannedStatePath(
                "conflict",
                ["START", "READY", "PLAYING"],
                ["USER", "PASS"],
                required_guards=["authenticated"],
                mutation_points=[0, 1],
            )
            schedule = CorpusEncoder().write_queue_schedule([path], root / "corpus", root, "ftp")
            entries = schedule["entries"]

            self.assertEqual(len(entries), 1)
            self.assertGreater(entries[0]["weight"], 100)
            self.assertEqual(entries[0]["mutation_points"], [0, 1])
            self.assertTrue((root / "aflnet_queue_weights.json").exists())
            self.assertIn("id_000000_conflict.raw", (root / "aflnet_queue_weights.tsv").read_text(encoding="utf-8"))

    def test_state_aware_synthesizer_expands_shortest_path_to_seed_family(self) -> None:
        path = PlannedStatePath(
            "conflict",
            ["START", "READY_FOR_SETUP", "READY", "PLAYING"],
            ["DESCRIBE", "SETUP", "PLAY"],
            required_guards=["valid transport and media resource", "valid session"],
            mutation_points=[2],
        )
        conflict = Conflict(
            kind="fsm_divergence",
            priority="P0",
            state="READY",
            transition="PLAY-> PLAYING guard=session present",
            description="guard mismatch around session state",
            expected_path=["READY"],
            fuzzing_strategy="exercise state-aware seed family",
            id="conflict",
        )

        intents = StateAwareTestSynthesizer().synthesize([path], [conflict], "rtsp")
        variants = {intent.variant for intent in intents}

        self.assertIn("baseline_valid_prefix", variants)
        self.assertIn("missing_guard_material", variants)
        self.assertIn("stale_session_value", variants)
        self.assertIn("wrong_message_order", variants)
        self.assertGreater(len(intents), 4)
        self.assertTrue(all(intent.conflict_id == "conflict" for intent in intents))
        self.assertTrue(all(intent.priority >= 100 for intent in intents))

    def test_seed_intent_corpus_manifest_deduplicates_payloads_and_records_ranges(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = PlannedStatePath(
                "conflict",
                ["START", "READY_FOR_SETUP", "READY", "PLAYING"],
                ["DESCRIBE", "SETUP", "PLAY"],
                required_guards=["valid session"],
                mutation_points=[2],
            )
            conflict = Conflict(
                kind="fsm_divergence",
                priority="P0",
                state="READY",
                transition="PLAY-> PLAYING",
                description="guard mismatch",
                expected_path=["READY"],
                fuzzing_strategy="exercise state-aware seed family",
                id="conflict",
            )
            intents = StateAwareTestSynthesizer().synthesize([path], [conflict], "rtsp")
            intents.append(intents[0])

            manifest = CorpusEncoder().write_seed_intents(
                intents,
                root / "corpus",
                "rtsp",
                managed_manifest=root / "aflnet_corpus_manifest.json",
                seed_manifest_path=root / "seed_manifest.json",
            )
            schedule = CorpusEncoder().write_seed_queue_schedule(manifest, root)

            self.assertEqual(manifest["deduplicated_count"], 1)
            self.assertEqual(len(manifest["entries"]), len({item["payload_sha256"] for item in manifest["entries"]}))
            self.assertTrue(any(item["byte_ranges"] for item in manifest["entries"]))
            self.assertTrue((root / "seed_manifest.json").exists())
            self.assertEqual(len(schedule["entries"]), manifest["seed_count"])
            missing = next(item for item in manifest["entries"] if item["variant"] == "missing_guard_material")
            self.assertNotIn(b"Session:", Path(missing["path"]).read_bytes())

    def test_seed_queue_schedule_consumes_replanning_seed_priorities(self) -> None:
        manifest = {
            "entries": [
                {
                    "seed_file": "id_000000_seed_a.raw",
                    "seed_id": "seed_a",
                    "conflict_id": "conflict",
                    "family_id": "family",
                    "variant": "baseline_valid_prefix",
                    "priority": 100,
                    "mutation_points": [],
                    "byte_ranges": [],
                    "messages": ["USER"],
                    "required_guards": [],
                }
            ]
        }
        replanning = {"next_round_seed_priorities": [{"seed_id": "seed_a", "score": 700}]}
        with TemporaryDirectory() as tmp:
            schedule = CorpusEncoder().write_seed_queue_schedule(manifest, Path(tmp), replanning_plan=replanning)

        entry = schedule["entries"][0]
        self.assertGreater(entry["weight"], entry["base_weight"])
        self.assertEqual(entry["replanned_score"], 700)

    def test_seed_feedback_attributes_queue_entries_to_seed_manifest(self) -> None:
        manifest = {
            "format": "protolens.seed_manifest.v1",
            "entries": [
                {
                    "seed_id": "seed_conflict_001_baseline",
                    "seed_file": "id_000000_seed_conflict_001_baseline.raw",
                    "conflict_id": "conflict",
                    "family_id": "family_conflict",
                    "variant": "baseline_valid_prefix",
                    "objective": "reach state",
                    "payload_sha256": "abc",
                    "states": ["START", "READY"],
                    "priority": 200,
                    "mutation_points": [0],
                    "byte_ranges": [],
                    "expected_feedback": ["queue_match"],
                }
            ],
        }
        dynamic = {
            "stats_present": True,
            "plot_data_present": True,
            "queue_files": ["id:000001,orig:id_000000_seed_conflict_001_baseline.raw"],
            "crash_files": [],
            "hang_files": [],
            "ipsm": {"node_labels": ["START", "READY"]},
        }

        feedback = SeedFeedbackAnalyzer().analyze(dynamic, manifest)

        self.assertEqual(feedback["seed_count"], 1)
        self.assertEqual(feedback["observed_count"], 1)
        self.assertEqual(feedback["items"][0]["status"], "queued_by_aflnet")
        self.assertTrue(feedback["items"][0]["matched_states"])
        self.assertEqual(feedback["items"][0]["queue_ids"], ["000001"])

    def test_seed_feedback_uses_exact_queue_lineage_not_shared_conflict_id(self) -> None:
        manifest = {
            "format": "protolens.seed_manifest.v2",
            "entries": [
                {
                    "seed_id": "seed_a",
                    "seed_file": "id_000000_seed_a.raw",
                    "conflict_id": "same_conflict",
                    "variant": "baseline_valid_prefix",
                    "states": ["READY"],
                    "priority": 100,
                },
                {
                    "seed_id": "seed_b",
                    "seed_file": "id_000001_seed_b.raw",
                    "conflict_id": "same_conflict",
                    "variant": "malformed_guard_field",
                    "states": ["READY"],
                    "priority": 100,
                },
            ],
        }
        dynamic = {
            "stats_present": True,
            "plot_data_present": True,
            "queue_files": [
                "id:000001,orig:id_000000_seed_a.raw",
                "id:000010,src:000001,op:havoc",
            ],
            "crash_files": ["id:000002,sig:11,src:000010,op:havoc"],
            "hang_files": [],
            "ipsm": {"present": True, "nodes": 1, "edges": 0, "node_labels": ["READY"]},
        }

        feedback = SeedFeedbackAnalyzer().analyze(dynamic, manifest)
        by_seed = {item["seed_id"]: item for item in feedback["items"]}

        self.assertEqual(by_seed["seed_a"]["status"], "crash_attributed")
        self.assertEqual(by_seed["seed_a"]["direct_queue_ids"], ["000001"])
        self.assertEqual(by_seed["seed_a"]["derived_queue_ids"], ["000010"])
        self.assertEqual(by_seed["seed_a"]["crash_matches"], ["id:000002,sig:11,src:000010,op:havoc"])
        self.assertEqual(by_seed["seed_b"]["status"], "unobserved")
        self.assertEqual(by_seed["seed_b"]["queue_ids"], [])
        self.assertEqual(by_seed["seed_b"]["matched_states"], [])
        self.assertEqual(by_seed["seed_b"]["global_state_overlap"][0]["fsm_state"], "READY")
        self.assertEqual(feedback["observed_count"], 1)
        self.assertEqual(feedback["global_state_observation"]["scope"], "campaign_global")

    def test_corpus_encoder_preserves_arguments_and_coalesces_duplicate_intents(self) -> None:
        encoder = CorpusEncoder()
        cwd_one = encoder.payload_for_path(PlannedStatePath("c1", ["S"], ["CWD /one"]), "ftp")
        cwd_two = encoder.payload_for_path(PlannedStatePath("c2", ["S"], ["CWD /two"]), "ftp")

        self.assertIn(b"CWD /one\r\n", cwd_one)
        self.assertIn(b"CWD /two\r\n", cwd_two)
        self.assertNotEqual(cwd_one, cwd_two)

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            intent_a = SeedIntent("seed_a", "c", "family", "baseline_valid_prefix", "a", ["S"], ["USER anonymous"])
            intent_b = SeedIntent("seed_b", "c", "family", "duplicate_variant", "b", ["S"], ["USER anonymous"])
            manifest = encoder.write_seed_intents([intent_a, intent_b], root / "corpus", "ftp")

        self.assertEqual(manifest["format"], "protolens.seed_manifest.v2")
        self.assertEqual(manifest["seed_count"], 1)
        self.assertEqual(manifest["deduplicated_count"], 1)
        self.assertEqual([item["seed_id"] for item in manifest["entries"][0]["coalesced_intents"]], ["seed_a", "seed_b"])


class LegacyParserAndStaticAnalysisCompatibilityTest(unittest.TestCase):
    def test_rfc_parser_extracts_explicit_natural_language_transition(self) -> None:
        with TemporaryDirectory() as tmp:
            spec = Path(tmp) / "spec.txt"
            spec.write_text(
                "In the START state, upon receiving USER, the server transitions to the USER_SEEN state.\n",
                encoding="utf-8",
            )

            transitions = RFCParser().parse_transitions([spec], "ftp")

            self.assertEqual(len(transitions), 1)
            self.assertEqual((transitions[0].source, transitions[0].trigger, transitions[0].target), ("START", "USER", "USER_SEEN"))
            self.assertEqual(transitions[0].evidence[0].source_type, "spec_nl")

    def test_rfc_parser_does_not_invent_generic_non_rtsp_transitions(self) -> None:
        with TemporaryDirectory() as tmp:
            spec = Path(tmp) / "spec.txt"
            spec.write_text("The protocol has several states and commands.\n", encoding="utf-8")

            self.assertEqual(RFCParser().parse_transitions([spec], "ftp"), [])

    def test_rfc_parser_extracts_marked_error_handling(self) -> None:
        with TemporaryDirectory() as tmp:
            spec = Path(tmp) / "spec.txt"
            spec.write_text(
                "TRANSITION: READY -- PLAY [valid session] -> ERROR ; action=reject ; error=close connection\n",
                encoding="utf-8",
            )

            transitions = RFCParser().parse_transitions([spec], "rtsp")

            self.assertEqual(transitions[0].action, "reject")
            self.assertEqual(transitions[0].error_handling, "close connection")

    def test_static_analysis_recovers_guarded_state_assignment(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "server.c"
            source.write_text(
                "struct Ctx { int state; };\n"
                "void handle_USER(struct Ctx *ctx) {\n"
                "  if (ctx->state == START) {\n"
                "    ctx->state = USER_SEEN;\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )

            transitions = StaticAnalysis().extract_transitions(root)

            self.assertEqual(len(transitions), 1)
            self.assertEqual((transitions[0].source, transitions[0].trigger, transitions[0].target), ("START", "USER", "USER_SEEN"))
            self.assertEqual(transitions[0].evidence[0].source_type, "code_recovered_state")


class FSMMergerTest(unittest.TestCase):
    def test_protocol_display_labels_normalize_to_configured_id(self) -> None:
        self.assertTrue(protocol_label_matches("ftp", "FTP (File Transfer Protocol)"))
        self.assertTrue(protocol_label_matches("rtsp", "Real Time Streaming Protocol (RTSP)"))
        self.assertTrue(protocol_label_matches("ftp", "File Transfer Protocol"))
        self.assertFalse(protocol_label_matches("ftp", "SFTP (SSH File Transfer Protocol)"))

        fsm = ProtocolFSM("FTP (File Transfer Protocol)", {}, [], "START")
        normalize_fsm_protocol(fsm, "ftp", component="test")
        self.assertEqual(fsm.protocol, "ftp")
        self.assertEqual(fsm.metadata["model_protocol_label"], "FTP (File Transfer Protocol)")

    def test_spec_builder_accepts_protocol_display_label(self) -> None:
        class DisplayProtocolClient(FakeFSMClient):
            def responses_json(self, **kwargs: object) -> object:
                response = super().responses_json(**kwargs)
                if kwargs.get("web_search"):
                    data = json.loads(response.text)
                    data["fsm"]["protocol"] = "FTP (File Transfer Protocol)"
                    response.text = json.dumps(data)
                return response

        with TemporaryDirectory() as tmp:
            fsm = SpecificationFSMBuilder(DisplayProtocolClient()).build(_config(Path(tmp)))

        self.assertEqual(fsm.protocol, "ftp")
        self.assertEqual(fsm.metadata["model_protocol_label"], "FTP (File Transfer Protocol)")

    def test_spec_builder_normalizes_textual_rfc_evidence_location(self) -> None:
        class TextualRFCLocationClient(FakeFSMClient):
            def __init__(self) -> None:
                self.repair_calls = 0

            def responses_json(self, **kwargs: object) -> object:
                if kwargs.get("schema_name") == "protolens_spec_transition_evidence_repair":
                    self.repair_calls += 1
                response = super().responses_json(**kwargs)
                if kwargs.get("schema_name") == "protolens_specification_fsm":
                    data = json.loads(response.text)
                    data["fsm"]["transitions"][0]["evidence"][0]["location"] = "RFC 0001 Section 1"
                    response.text = json.dumps(data)
                return response

        with TemporaryDirectory() as tmp:
            client = TextualRFCLocationClient()
            fsm = SpecificationFSMBuilder(client).build(_config(Path(tmp)))

        self.assertEqual(client.repair_calls, 0)
        self.assertEqual(
            fsm.transitions[0].evidence[0].location,
            "https://www.rfc-editor.org/rfc/rfc0001.html#section-1",
        )
        self.assertEqual(
            fsm.metadata["evidence_repairs"][0]["action"],
            "normalized_declared_rfc_reference",
        )

    def test_spec_builder_removes_non_normative_socket_failure_transition(self) -> None:
        class SocketFailureClient(FakeFSMClient):
            def responses_json(self, **kwargs: object) -> object:
                if kwargs.get("schema_name") == "protolens_spec_transition_evidence_repair":
                    return LLMResponse(
                        text=json.dumps(
                            {
                                "repairs": [
                                    {
                                        "transition_id": "t1_sock_fail",
                                        "action": "remove_non_normative_transition",
                                        "evidence": [],
                                        "rationale": "A socket API failure is implementation behavior, not an RFC transition.",
                                    }
                                ]
                            }
                        ),
                        provider=self.provider,
                        model=self.model,
                        raw={},
                    )
                response = super().responses_json(**kwargs)
                if kwargs.get("schema_name") == "protolens_specification_fsm":
                    data = json.loads(response.text)
                    data["fsm"]["states"].append(
                        {"name": "SOCKET_ERROR", "description": "", "evidence": [], "confidence": 0.5}
                    )
                    invalid = dict(data["fsm"]["transitions"][0])
                    invalid.update(
                        {
                            "id": "t1_sock_fail",
                            "source": "READY",
                            "target": "SOCKET_ERROR",
                            "trigger": "send() failure",
                            "message_type": None,
                            "evidence": [
                                {
                                    "source_type": "implementation",
                                    "location": "socket.c:42",
                                    "excerpt": "send() returned -1",
                                    "confidence": 0.4,
                                }
                            ],
                        }
                    )
                    data["fsm"]["transitions"].append(invalid)
                    response.text = json.dumps(data)
                return response

        with TemporaryDirectory() as tmp:
            builder = SpecificationFSMBuilder(SocketFailureClient())
            fsm = builder.build(_config(Path(tmp)))
            conversations = builder.drain_conversations()

        self.assertNotIn("t1_sock_fail", {item.id for item in fsm.transitions})
        self.assertEqual(
            fsm.metadata["evidence_repairs"][-1]["action"],
            "remove_non_normative_transition",
        )
        self.assertEqual([item["schema_name"] for item in conversations], [
            "protolens_specification_fsm",
            "protolens_spec_transition_evidence_repair",
        ])

    def test_impl_builder_restores_unique_whitespace_only_evidence(self) -> None:
        class WhitespaceEvidenceClient(FakeFSMClient):
            def responses_json(self, **kwargs: object) -> object:
                response = super().responses_json(**kwargs)
                if str(kwargs.get("schema_name", "")).startswith("protolens_impl_transition_facts_chunk_"):
                    data = json.loads(response.text)
                    evidence = data["transition_facts"][0]["evidence"][0]
                    evidence["location"] = "ftp.c"
                    evidence["excerpt"] = "int handle(void) {\nreturn 1;\n}"
                    response.text = json.dumps(data)
                return response

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = "int handle(void) {\n\treturn 1;\n}\n"
            (root / "ftp.c").write_text(source, encoding="utf-8")
            fsm = ImplementationFSMBuilder(WhitespaceEvidenceClient()).build(_config(root))

        evidence = fsm.transitions[0].evidence[0]
        self.assertEqual(evidence.location, "ftp.c:1")
        self.assertEqual(evidence.excerpt, source.rstrip("\n"))
        self.assertEqual(
            fsm.metadata["evidence_repairs"][0]["action"],
            "restored_unique_whitespace_exact_excerpt",
        )

    def test_impl_builder_retries_llm_after_unverifiable_excerpt(self) -> None:
        class EvidenceRetryClient(FakeFSMClient):
            retries = 1

            def __init__(self) -> None:
                self.chunk_calls = 0
                self.chunk_payloads: list[dict[str, object]] = []

            def responses_json(self, **kwargs: object) -> object:
                response = super().responses_json(**kwargs)
                if str(kwargs.get("schema_name", "")).startswith("protolens_impl_transition_facts_chunk_"):
                    self.chunk_calls += 1
                    payload = json.loads(str(kwargs["user"]))
                    self.chunk_payloads.append(payload)
                    if self.chunk_calls == 1:
                        data = json.loads(response.text)
                        data["transition_facts"][0]["evidence"][0]["excerpt"] = "int ...;"
                        response.text = json.dumps(data)
                return response

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ftp.c").write_text("int handle(void) { return 1; }\n", encoding="utf-8")
            client = EvidenceRetryClient()
            builder = ImplementationFSMBuilder(client)
            fsm = builder.build(_config(root))
            conversations = builder.drain_conversations()

        self.assertEqual(client.chunk_calls, 2)
        self.assertNotIn("evidence_validation_feedback", client.chunk_payloads[0])
        self.assertIn("evidence_validation_feedback", client.chunk_payloads[1])
        self.assertEqual(conversations[0]["final_status"], "rejected")
        self.assertIn(fsm.transitions[0].evidence[0].excerpt, "int handle(void) { return 1; }\n")

    def test_rfc_source_urls_are_compared_by_document_identity(self) -> None:
        raw = {
            "output": [
                {
                    "type": "web_search_call",
                    "status": "completed",
                    "action": {
                        "sources": [
                            {
                                "url": (
                                    "https://www.rfc-editor.org/info/rfc959/"
                                    "#ws_call_id=call_123"
                                )
                            }
                        ]
                    },
                },
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "https://www.rfc-editor.org/info/rfc2389/",
                        }
                    ],
                },
            ]
        }

        self.assertEqual(response_source_urls(raw), {"rfc:959"})
        self.assertEqual(
            canonical_source_url("https://www.rfc-editor.org/rfc/rfc959.html?format=txt §4.1"),
            "rfc:959",
        )
        self.assertEqual(canonical_source_url("https://datatracker.ietf.org/doc/html/rfc0959"), "rfc:959")
        self.assertEqual(canonical_source_url("https://www.rfc-editor.org/errata/rfc959"), "rfc:959")
        self.assertEqual(canonical_source_url("https://datatracker.ietf.org/doc/pdf/rfc1123"), "rfc:1123")
        self.assertEqual(canonical_source_url("https://dt-main.dev.ietf.org/doc/rfc1123/"), "rfc:1123")

    def test_spec_builder_researches_unverified_rfc_before_accepting_it(self) -> None:
        class SourceRetryClient(FakeFSMClient):
            retries = 1

            def __init__(self) -> None:
                self.web_calls = 0
                self.users: list[dict[str, object]] = []

            def responses_json(self, **kwargs: object) -> object:
                if kwargs.get("schema_name") == "protolens_rfc_source_verification":
                    payload = json.loads(str(kwargs["user"]).split("\n\n", 1)[0])
                    self.web_calls += 1
                    self.users.append(payload)
                    candidates = payload["candidate_urls"]
                    return LLMResponse(
                        text=json.dumps({"opened_urls": candidates, "unresolved_urls": []}),
                        provider=self.provider,
                        model=self.model,
                        raw={
                            "output": [
                                {
                                    "type": "web_search_call",
                                    "status": "completed",
                                    "action": {
                                        "type": "open_page",
                                        "url": f"{candidates[0]}#ws_call_id=verification",
                                    },
                                }
                            ]
                        },
                    )
                response = super().responses_json(**kwargs)
                if not kwargs.get("web_search"):
                    return response
                self.web_calls += 1
                self.users.append(json.loads(str(kwargs["user"])))
                data = json.loads(response.text)
                missing_url = "https://www.rfc-editor.org/rfc/rfc2389.html"
                data["sources"].append(
                    {
                        "url": missing_url,
                        "title": "Feature negotiation mechanism",
                        "rfc_number": "RFC 2389",
                        "status": "Proposed Standard",
                        "published_at": "1998-08",
                        "relationship": "updates protocol",
                    }
                )
                response.text = json.dumps(data)
                return response

        with TemporaryDirectory() as tmp:
            client = SourceRetryClient()
            builder = SpecificationFSMBuilder(client)
            fsm = builder.build(_config(Path(tmp)))
            conversations = builder.drain_conversations()

        self.assertEqual(fsm.protocol, "ftp")
        self.assertEqual(client.web_calls, 2)
        self.assertIn("protocol", client.users[0])
        self.assertEqual(
            client.users[1]["candidate_urls"],
            ["https://www.rfc-editor.org/rfc/rfc2389.html"],
        )
        self.assertEqual([item["final_status"] for item in conversations], ["rejected", "success"])

    def test_spec_builder_keeps_web_evidence_when_verifier_output_fails(self) -> None:
        class FailedVerifierClient(FakeFSMClient):
            retries = 0

            def responses_json(self, **kwargs: object) -> object:
                if kwargs.get("schema_name") == "protolens_rfc_source_verification":
                    payload = json.loads(str(kwargs["user"]))
                    candidate = payload["candidate_urls"][0]
                    raise IncompleteLLMResponse(
                        {
                            "status": "incomplete",
                            "incomplete_details": {"reason": "max_output_tokens"},
                            "output": [
                                {
                                    "type": "web_search_call",
                                    "status": "completed",
                                    "action": {
                                        "type": "open_page",
                                        "url": f"{candidate}#ws_call_id=preserved",
                                    },
                                }
                            ],
                        }
                    )
                response = super().responses_json(**kwargs)
                data = json.loads(response.text)
                data["sources"].append(
                    {
                        "url": "https://www.rfc-editor.org/rfc/rfc2389.html",
                        "title": "Feature negotiation mechanism",
                        "rfc_number": "RFC 2389",
                        "status": "Proposed Standard",
                        "published_at": "1998-08",
                        "relationship": "updates protocol",
                    }
                )
                response.text = json.dumps(data)
                return response

        with TemporaryDirectory() as tmp:
            builder = SpecificationFSMBuilder(FailedVerifierClient())
            fsm = builder.build(_config(Path(tmp)))
            conversations = builder.drain_conversations()

        self.assertEqual(fsm.protocol, "ftp")
        self.assertEqual([item["final_status"] for item in conversations], ["rejected", "failed"])
        self.assertEqual(
            conversations[1]["response"]["raw"]["output"][0]["action"]["type"],
            "open_page",
        )

    def test_llm_merge_preserves_transition_coverage(self) -> None:
        spec = ProtocolFSM("ftp", {}, [], "START")
        impl = ProtocolFSM("ftp", {}, [], "START")
        spec.add_transition(
            StateTransition(
                "START",
                "READY",
                "USER",
                action="store username",
                evidence=[Evidence("spec", "spec:1", "spec edge")],
            )
        )
        impl.add_transition(
            StateTransition(
                "START",
                "READY",
                "USER",
                action="authenticate immediately",
                evidence=[Evidence("code", "server.c:10", "code edge")],
            )
        )

        unified, divergences = FSMMerger(FakeFSMClient()).merge(spec, impl)

        self.assertEqual(len(unified.transitions), 2)
        self.assertEqual({item.kind for item in divergences}, {"extra_transition"})
        mappings = unified.metadata["transition_sources"]
        self.assertEqual({item["spec_transition_ids"][0] for item in mappings if item["spec_transition_ids"]}, {spec.transitions[0].id})
        self.assertEqual({item["impl_transition_ids"][0] for item in mappings if item["impl_transition_ids"]}, {impl.transitions[0].id})

    def test_llm_implementation_builder_uses_exact_source_evidence(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ftp.c").write_text(
                "int ftpUSER(void *ctx, const char *p) { return 1; }\n"
                "int ftpPASS(void *ctx, const char *p) { return 1; }\n"
                "int ftpQUIT(void *ctx, const char *p) { return 1; }\n",
                encoding="utf-8",
            )
            config = _config(root)
            fsm = ImplementationFSMBuilder(FakeFSMClient()).build(config)

            self.assertEqual(fsm.metadata["semantic_extractor"], "llm_only")
            self.assertIn("INPUT", {item.trigger for item in fsm.transitions})
            self.assertTrue(all(item.evidence for item in fsm.transitions))

    def test_offline_fsm_builders_fail_instead_of_using_rule_fallback(self) -> None:
        with TemporaryDirectory() as tmp:
            config = _config(Path(tmp))
            offline = LLMClient()
            with self.assertRaises(RuntimeError):
                SpecificationFSMBuilder(offline).build(config)
            with self.assertRaises(RuntimeError):
                ImplementationFSMBuilder(offline).build(config)


class ConfigAndAdapterTest(unittest.TestCase):
    def test_init_config_exposes_path_calibration_without_aflnet_cmd(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            run_dir = root / "run"
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                status = protolens_main([
                    "init",
                    "--protocol", "ftp",
                    "--target", "sample",
                    "--source", str(source),
                    "--out", str(run_dir),
                ])

            self.assertEqual(status, 0)
            self.assertIn('"config"', stdout.getvalue())
            config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
            self.assertIn("path_calibration", config)
            self.assertFalse(config["path_calibration"]["enabled"])
            self.assertNotIn("cmd", config["aflnet"])

    def test_config_snapshot_redacts_auth_headers(self) -> None:
        with TemporaryDirectory() as tmp:
            config = _config(Path(tmp))
            config.llm.extra_headers = {"Authorization": "secret", "X-Title": "ProtoLens"}
            snapshot = config.to_json_dict()
            self.assertEqual(snapshot["llm"]["extra_headers"]["Authorization"], "***")
            self.assertEqual(snapshot["llm"]["extra_headers"]["X-Title"], "ProtoLens")

    def test_invalid_live_config_requires_port_and_target(self) -> None:
        raw = {
            "protocol": "ftp",
            "target_name": "bad",
            "spec_paths": ["spec.txt"],
            "source_root": ".",
            "port": 0,
            "aflnet": {"dry_run": False},
        }
        with self.assertRaises(ValueError):
            ProtoLensConfig.from_dict(raw)

    def test_dry_run_command_resolves_binary_and_separates_target(self) -> None:
        with TemporaryDirectory() as tmp:
            config = _config(Path(tmp))
            config.aflnet.cmd = ["/bin/true", "--", "/bin/true"]
            result = AFLNetAdapter().prepare_and_run(config, [])
            self.assertEqual(result.mode, "dry-run")
            self.assertEqual(result.command[0], "/usr/bin/true")
            separator = result.command.index("--")
            self.assertEqual(result.command[separator + 1], "/bin/true")

    def test_configured_aflnet_cmd_is_used_directly(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root)
            corpus = root / "manual-corpus"
            output = root / "manual-output"
            dictionary = root / "manual.dict"
            config.aflnet.cmd = [
                "/bin/true",
                "-i",
                str(corpus),
                "-o",
                str(output),
                "-x",
                str(dictionary),
                "-P",
                "MANUAL",
                "--",
                str(root / "manual-server"),
            ]

            result = AFLNetAdapter().prepare_and_run(config, [])

            self.assertEqual(result.mode, "dry-run")
            self.assertEqual(result.command[0], "/usr/bin/true")
            self.assertEqual(result.command[1:3], ["-i", str(corpus)])
            self.assertEqual(result.corpus_dir, str(corpus))
            self.assertEqual(result.dictionary_path, str(dictionary))
            self.assertEqual(result.output_dir, str(output))
            self.assertIn(str(output), result.command)
            self.assertIn("MANUAL", result.command)
            separator = result.command.index("--")
            self.assertEqual(result.command[separator + 1], str(root / "manual-server"))

    def test_monitor_import_dir_is_passed_to_live_aflnet_process(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_aflnet = root / "fake-aflnet"
            seen_env = root / "seen-env"
            fake_aflnet.write_text(
                "#!/bin/sh\n"
                "test -d \"$AFLNET_PROTOLENS_IMPORT_DIR\" || exit 42\n"
                "printf '%s' \"$AFLNET_PROTOLENS_IMPORT_DIR\" > " + str(seen_env) + "\n"
                "sleep 10\n",
                encoding="utf-8",
            )
            fake_aflnet.chmod(0o755)
            config = _config(root, dry_run=False, binary=str(fake_aflnet))
            config.aflnet.duration_seconds = 1
            config.aflnet.cmd = [
                str(fake_aflnet),
                "-i",
                str(root / "in"),
                "-o",
                str(root / "out"),
                "--",
                "/bin/true",
            ]

            result = AFLNetAdapter().prepare_and_run(config, [])

            self.assertEqual(result.mode, "timed-out")
            self.assertEqual(seen_env.read_text(encoding="utf-8"), str(config.run_dir / "monitor_import_queue"))

    def test_campaign_timeout_returns_structured_result(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_aflnet = root / "fake-aflnet"
            fake_aflnet.write_text("#!/bin/sh\nsleep 10\n", encoding="utf-8")
            fake_aflnet.chmod(0o755)
            config = _config(root, dry_run=False, binary=str(fake_aflnet))
            config.aflnet.cmd = [
                str(fake_aflnet),
                "-i",
                str(root / "in"),
                "-o",
                str(root / "out"),
                "--",
                "/bin/true",
            ]

            result = AFLNetAdapter().prepare_and_run(config, [])

            self.assertEqual(result.mode, "timed-out")
            self.assertEqual(result.exit_code, 124)
            self.assertTrue(result.notes)

    def test_live_aflnet_requires_configured_input_and_output_options(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root, dry_run=False, binary="/bin/true")

            result = AFLNetAdapter().prepare_and_run(config, [])

            self.assertEqual(result.mode, "error")
            self.assertIn("-i <input_corpus_dir>", "\n".join(result.notes))
            self.assertIn("-o <output_dir>", "\n".join(result.notes))

    def test_crash_readme_is_not_reported_as_finding(self) -> None:
        with TemporaryDirectory() as tmp:
            crash_dir = Path(tmp) / "replayable-crashes"
            crash_dir.mkdir()
            (crash_dir / "README.txt").write_text("metadata", encoding="utf-8")
            self.assertEqual(_list_findings(Path(tmp), "crashes"), [])
            (crash_dir / "id:000001,sig:11").write_bytes(b"crash")
            self.assertEqual(_list_findings(Path(tmp), "crashes"), ["id:000001,sig:11"])

    def test_dynamic_analyzer_reads_aflnet_outputs(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "aflnet"
            (output / "queue").mkdir(parents=True)
            (output / "queue" / "id:000000,orig:id_000000_seed.raw").write_bytes(b"USER\r\n")
            (output / "replayable-crashes").mkdir()
            (output / "replayable-crashes" / "id:000001,sig:11").write_bytes(b"crash")
            (output / "fuzzer_stats").write_text("execs_done : 10\nunique_crashes : 1\n", encoding="utf-8")
            (output / "plot_data").write_text("# header\n1,0,0,1,0,0,1.0%,1,0,1,25.0,2,1\n", encoding="utf-8")
            (output / "ipsm.dot").write_text("digraph { START -> READY; }\n", encoding="utf-8")
            result = AFLNetDynamicAnalyzer().analyze(
                fuzz_result=type(
                    "Result",
                    (),
                    {
                        "mode": "executed",
                        "output_dir": str(output),
                    },
                )()
            )

            self.assertEqual(result["queue_count"], 1)
            self.assertEqual(result["crash_count"], 1)
            self.assertEqual(result["fuzzer_stats"]["execs_done"], "10")
            self.assertEqual(result["latest_plot"]["ipsm_edges"], "1")
            self.assertIn("crashes_present", result["health_signals"])

    def test_monitor_agent_generates_breakthrough_seed_when_coverage_stagnates(self) -> None:
        class FakeMonitorLLM:
            is_offline = False
            provider = "fake"
            model = "monitor"

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
                    text=json.dumps(
                        {
                            "bottleneck_summary": "No IPSM edge growth; try an authenticated data path.",
                            "seed_candidates": [
                                {
                                    "conflict_id": "conflict",
                                    "messages": ["USER", "PASS", "TYPE", "PORT", "RETR"],
                                    "rationale": "Exercise the guarded data transfer branch after login.",
                                    "expected_new_coverage": "authenticated RETR data connection handling",
                                }
                            ],
                        }
                    ),
                    provider="fake",
                    model="monitor",
                )

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root, dry_run=False)
            config.monitor_agent.interval_seconds = 0.01
            config.monitor_agent.stagnation_seconds = 0.01
            config.monitor_agent.min_exec_delta = 0
            dynamic = {
                "stats_present": True,
                "fuzzer_stats": {
                    "execs_done": "100",
                    "execs_per_sec": "50.0",
                    "paths_total": "1",
                    "last_path": "1",
                    "bitmap_cvg": "1.0%",
                },
                "ipsm": {"nodes": 1, "edges": 0},
                "queue_count": 1,
                "queue_files": [],
                "health_signals": ["no_ipsm_edges"],
            }
            path = PlannedStatePath(
                "conflict",
                ["START", "AUTHENTICATED", "DATA"],
                ["USER", "PASS", "RETR"],
                required_guards=["authenticated data connection"],
                mutation_points=[2],
            )
            conflict = Conflict(
                kind="fsm_divergence",
                priority="P0",
                state="DATA",
                transition=None,
                description="guarded data path",
                expected_path=["START", "AUTHENTICATED", "DATA"],
                fuzzing_strategy="exercise authenticated data transfer",
                id="conflict",
            )
            result = FuzzResult(
                mode="running",
                command=["/bin/true"],
                corpus_dir=str(root / "in"),
                dictionary_path=str(root / "dict"),
                output_dir=str(root / "out"),
            )
            llm = FakeMonitorLLM()
            agent = MonitorAgent(llm)

            first = agent.observe(config, result, dynamic, [path], [conflict], force=True)
            self.assertEqual(first["status"], "improving")
            import time

            time.sleep(0.02)
            second = agent.observe(config, result, dynamic, [path], [conflict], force=True)

            self.assertEqual(second["status"], "stagnant")
            self.assertTrue(second["generated_seeds"])
            self.assertEqual(second["generated_seeds"][0]["source"], "llm_monitor_analysis")
            self.assertEqual(second["llm_analysis"]["provider"], "fake")
            self.assertEqual(llm.schema_name, "protolens_monitor_seed_candidates")
            self.assertEqual(llm.response_schema["required"], ["bottleneck_summary", "seed_candidates"])
            seed_path = Path(second["generated_seeds"][0]["path"])
            payload = seed_path.read_bytes()
            self.assertIn(b"USER anonymous\r\n", payload)
            self.assertIn(b"PASS protolens@example.com\r\n", payload)
            self.assertIn(b"TYPE I\r\n", payload)
            self.assertIn(b"PORT 127,0,0,1,7,138\r\n", payload)
            self.assertIn(b"RETR protolens.txt\r\n", payload)
            conversations = agent.drain_llm_conversations()
            self.assertEqual(len(conversations), 1)
            self.assertIn("live AFLNet feedback", conversations[0]["system"])

    def test_monitor_agent_deduplicates_repeated_llm_seed_payloads(self) -> None:
        class RepeatingMonitorLLM:
            is_offline = False
            provider = "fake"
            model = "monitor"

            def __init__(self) -> None:
                self.calls = 0

            def chat_json(
                self,
                *,
                system: str,
                user: str,
                response_schema: dict | None = None,
                schema_name: str = "",
            ) -> LLMResponse:
                self.calls += 1
                return LLMResponse(
                    text=json.dumps(
                        {
                            "bottleneck_summary": "Same stalled IPSM signature.",
                            "seed_candidates": [
                                {
                                    "conflict_id": "conflict",
                                    "messages": ["USER", "PASS", "TYPE", "PORT", "RETR"],
                                    "rationale": f"attempt {self.calls} with different wording",
                                    "expected_new_coverage": "authenticated RETR data connection handling",
                                }
                            ],
                        }
                    ),
                    provider="fake",
                    model="monitor",
                )

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root, dry_run=False)
            config.monitor_agent.interval_seconds = 0.01
            config.monitor_agent.stagnation_seconds = 0.01
            config.monitor_agent.min_exec_delta = 0
            config.monitor_agent.max_llm_calls_per_stagnation_signature = 2
            dynamic = {
                "stats_present": True,
                "fuzzer_stats": {
                    "execs_done": "100",
                    "execs_per_sec": "50.0",
                    "paths_total": "1",
                    "last_path": "1",
                    "bitmap_cvg": "1.0%",
                },
                "ipsm": {"nodes": 1, "edges": 0},
                "queue_count": 1,
                "queue_files": [],
                "health_signals": ["no_ipsm_edges"],
            }
            path = PlannedStatePath(
                "conflict",
                ["START", "AUTHENTICATED", "DATA"],
                ["USER", "PASS", "RETR"],
                required_guards=["authenticated data connection"],
                mutation_points=[2],
            )
            conflict = Conflict(
                kind="fsm_divergence",
                priority="P0",
                state="DATA",
                transition=None,
                description="guarded data path",
                expected_path=["START", "AUTHENTICATED", "DATA"],
                fuzzing_strategy="exercise authenticated data transfer",
                id="conflict",
            )
            result = FuzzResult(
                mode="running",
                command=["/bin/true"],
                corpus_dir=str(root / "in"),
                dictionary_path=str(root / "dict"),
                output_dir=str(root / "out"),
            )
            llm = RepeatingMonitorLLM()
            agent = MonitorAgent(llm)
            import time

            self.assertEqual(agent.observe(config, result, dynamic, [path], [conflict], force=True)["status"], "improving")
            time.sleep(0.02)
            second = agent.observe(config, result, dynamic, [path], [conflict], force=True)
            time.sleep(0.02)
            third = agent.observe(config, result, dynamic, [path], [conflict], force=True)

            self.assertEqual(second["status"], "stagnant")
            self.assertEqual(third["status"], "stagnant_no_seed")
            self.assertEqual(third["skipped_candidates"][0]["reason"], "duplicate_monitor_seed")
            self.assertEqual(llm.calls, 2)
            seed_files = list((config.run_dir / "monitor_import_queue").glob("id:*src:protolens_monitor*"))
            self.assertEqual(len(seed_files), 1)
            manifest = json.loads((config.run_dir / "monitor_seed_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["seed_count"], 1)
            self.assertEqual(len(manifest["payload_sha256s"]), 1)

    def test_monitor_agent_uses_persisted_manifest_to_suppress_repeat_llm_calls(self) -> None:
        class CountingMonitorLLM:
            is_offline = False
            provider = "fake"
            model = "monitor"

            def __init__(self) -> None:
                self.calls = 0

            def chat_json(
                self,
                *,
                system: str,
                user: str,
                response_schema: dict | None = None,
                schema_name: str = "",
            ) -> LLMResponse:
                self.calls += 1
                return LLMResponse(
                    text=json.dumps(
                        {
                            "bottleneck_summary": "Same stalled IPSM signature.",
                            "seed_candidates": [
                                {
                                    "conflict_id": "conflict",
                                    "messages": ["USER", "PASS", "RETR"],
                                    "rationale": "first persisted attempt",
                                    "expected_new_coverage": "authenticated RETR data connection handling",
                                }
                            ],
                        }
                    ),
                    provider="fake",
                    model="monitor",
                )

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root, dry_run=False)
            dynamic = {
                "stats_present": True,
                "fuzzer_stats": {
                    "execs_done": "100",
                    "execs_per_sec": "50.0",
                    "paths_total": "1",
                    "last_path": "1",
                    "bitmap_cvg": "1.0%",
                },
                "ipsm": {"nodes": 1, "edges": 0},
                "queue_count": 1,
                "queue_files": [],
                "health_signals": ["no_ipsm_edges"],
            }
            path = PlannedStatePath(
                "conflict",
                ["START", "AUTHENTICATED", "DATA"],
                ["USER", "PASS", "RETR"],
                required_guards=["authenticated data connection"],
                mutation_points=[2],
            )
            conflict = Conflict(
                kind="fsm_divergence",
                priority="P0",
                state="DATA",
                transition=None,
                description="guarded data path",
                expected_path=["START", "AUTHENTICATED", "DATA"],
                fuzzing_strategy="exercise authenticated data transfer",
                id="conflict",
            )
            result = FuzzResult(
                mode="running",
                command=["/bin/true"],
                corpus_dir=str(root / "in"),
                dictionary_path=str(root / "dict"),
                output_dir=str(root / "out"),
            )
            llm = CountingMonitorLLM()
            first_agent = MonitorAgent(llm)
            import time

            self.assertEqual(first_agent.observe(config, result, dynamic, [path], [conflict], force=True)["status"], "improving")
            time.sleep(0.02)
            self.assertEqual(first_agent.observe(config, result, dynamic, [path], [conflict], force=True)["status"], "stagnant")

            restarted_agent = MonitorAgent(llm)
            self.assertEqual(
                restarted_agent.observe(config, result, dynamic, [path], [conflict], force=True)["status"],
                "improving",
            )
            time.sleep(0.02)
            suppressed = restarted_agent.observe(config, result, dynamic, [path], [conflict], force=True)

            self.assertEqual(suppressed["status"], "stagnant_llm_suppressed")
            self.assertEqual(suppressed["llm_calls_for_signature"], 1)
            self.assertEqual(llm.calls, 1)

    def test_monitor_agent_separates_llm_failure_retries_from_success_budget(self) -> None:
        class FailingMonitorLLM:
            is_offline = False
            provider = "fake"
            model = "monitor"

            def __init__(self) -> None:
                self.calls = 0

            def chat_json(
                self,
                *,
                system: str,
                user: str,
                response_schema: dict | None = None,
                schema_name: str = "",
            ) -> LLMResponse:
                self.calls += 1
                raise RuntimeError("temporary network failure")

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root, dry_run=False)
            config.monitor_agent.llm_failure_backoff_seconds = 60
            dynamic = {
                "stats_present": True,
                "fuzzer_stats": {
                    "execs_done": "100",
                    "execs_per_sec": "50.0",
                    "paths_total": "1",
                    "last_path": "1",
                    "bitmap_cvg": "1.0%",
                },
                "ipsm": {"nodes": 1, "edges": 0},
                "queue_count": 1,
                "queue_files": [],
                "health_signals": ["no_ipsm_edges"],
            }
            path = PlannedStatePath("conflict", ["START"], ["USER"], mutation_points=[0])
            conflict = Conflict(
                kind="fsm_divergence",
                priority="P1",
                state="START",
                transition=None,
                description="guarded path",
                expected_path=["START"],
                fuzzing_strategy="retry monitor llm",
                id="conflict",
            )
            result = FuzzResult(
                mode="running",
                command=["/bin/true"],
                corpus_dir=str(root / "in"),
                dictionary_path=str(root / "dict"),
                output_dir=str(root / "out"),
            )
            llm = FailingMonitorLLM()
            agent = MonitorAgent(llm)
            import time

            self.assertEqual(agent.observe(config, result, dynamic, [path], [conflict], force=True)["status"], "improving")
            time.sleep(0.02)
            failed = agent.observe(config, result, dynamic, [path], [conflict], force=True)
            backed_off = agent.observe(config, result, dynamic, [path], [conflict], force=True)
            manifest = json.loads((config.run_dir / "monitor_seed_manifest.json").read_text(encoding="utf-8"))

            self.assertEqual(failed["status"], "llm_failed")
            self.assertEqual(backed_off["status"], "stagnant_llm_backoff")
            self.assertEqual(llm.calls, 1)
            self.assertEqual(list(manifest["coverage_llm_calls"].values()), [])
            self.assertEqual(list(manifest["coverage_llm_failures"].values()), [1])

    def test_monitor_agent_does_not_generate_seed_without_llm(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config(root, dry_run=False)
            config.monitor_agent.interval_seconds = 0.01
            config.monitor_agent.stagnation_seconds = 0.01
            config.monitor_agent.min_exec_delta = 0
            dynamic = {
                "stats_present": True,
                "fuzzer_stats": {
                    "execs_done": "100",
                    "execs_per_sec": "50.0",
                    "paths_total": "1",
                    "last_path": "1",
                    "bitmap_cvg": "1.0%",
                },
                "ipsm": {"nodes": 1, "edges": 0},
                "queue_count": 1,
                "queue_files": [],
                "health_signals": ["no_ipsm_edges"],
            }
            path = PlannedStatePath(
                "conflict",
                ["START", "AUTHENTICATED", "DATA"],
                ["USER", "PASS", "RETR"],
                required_guards=["authenticated data connection"],
                mutation_points=[2],
            )
            conflict = Conflict(
                kind="fsm_divergence",
                priority="P0",
                state="DATA",
                transition=None,
                description="guarded data path",
                expected_path=["START", "AUTHENTICATED", "DATA"],
                fuzzing_strategy="exercise authenticated data transfer",
                id="conflict",
            )
            result = FuzzResult(
                mode="running",
                command=["/bin/true"],
                corpus_dir=str(root / "in"),
                dictionary_path=str(root / "dict"),
                output_dir=str(root / "out"),
            )
            agent = MonitorAgent()

            self.assertEqual(agent.observe(config, result, dynamic, [path], [conflict], force=True)["status"], "improving")
            import time

            time.sleep(0.02)
            second = agent.observe(config, result, dynamic, [path], [conflict], force=True)

            self.assertEqual(second["status"], "llm_failed")
            self.assertFalse(second["generated_seeds"])

    def test_state_mapper_links_planned_path_to_ipsm_labels(self) -> None:
        dynamic = {
            "ipsm": {"node_labels": ["START", "READY"], "edges": 1},
            "queue_files": ["id:000000,orig:id_000000_conflict.raw"],
        }
        paths = [PlannedStatePath("conflict", ["START", "READY"], ["USER"])]

        result = AFLNetStateMapper().map(dynamic, paths)

        self.assertEqual(result["items"][0]["status"], "observed")
        self.assertEqual(result["items"][0]["matched_states"][0]["fsm_state"], "START")

    def test_transport_harness_is_explicitly_disabled_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            config = _config(Path(tmp))
            manifest = {"actions": [{"conflict_id": "c1", "messages": ["TCP_RESET"]}]}

            result = TransportAwareHarness().execute(config, manifest)

            self.assertFalse(result["executed"])


class LLMCompatibilityTest(unittest.TestCase):
    def test_web_research_without_output_is_finalized_by_a_second_structured_call(self) -> None:
        requests: list[dict[str, object]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                requests.append(json.loads(self.rfile.read(length)))
                if len(requests) == 1:
                    payload = {
                        "status": "incomplete",
                        "incomplete_details": {"reason": "max_output_tokens"},
                        "usage": {
                            "output_tokens": 12000,
                            "output_tokens_details": {"reasoning_tokens": 11900},
                        },
                        "output": [
                            {
                                "type": "reasoning",
                                "status": "completed",
                                "encrypted_content": "encrypted-research-context",
                                "content": [{"type": "reasoning_text", "text": "RFC research complete."}],
                            },
                            {
                                "type": "web_search_call",
                                "status": "completed",
                                "action": {
                                    "sources": [
                                        {"type": "url", "url": "https://www.rfc-editor.org/rfc/rfc1.html"}
                                    ]
                                },
                            },
                        ],
                    }
                else:
                    payload = {
                        "status": "completed",
                        "output": [
                            {
                                "type": "message",
                                "status": "completed",
                                "content": [{"type": "output_text", "text": '{"ok":true}'}],
                            }
                        ],
                    }
                response = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = LLMClient(
                provider="openai-compatible",
                model="local-model",
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
                retries=0,
            )
            response = client.responses_json(
                system="system",
                user="user",
                response_schema={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["ok"],
                    "properties": {"ok": {"type": "boolean"}},
                },
                schema_name="web_finalize",
                web_search=True,
                allowed_domains=["rfc-editor.org"],
                max_tool_calls=4,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(response.text, '{"ok":true}')
        self.assertEqual(len(requests), 2)
        self.assertIn("tools", requests[0])
        self.assertNotIn("tools", requests[1])
        self.assertEqual(requests[0]["max_output_tokens"], 2000)
        self.assertEqual(requests[1]["max_output_tokens"], 24000)
        self.assertIn("reasoning.encrypted_content", requests[0]["include"])
        self.assertIsInstance(requests[1]["input"], list)
        continued_input = requests[1]["input"]
        self.assertEqual(continued_input[0]["content"][0]["text"], "user")
        self.assertEqual(continued_input[1]["encrypted_content"], "encrypted-research-context")
        self.assertEqual(continued_input[2]["type"], "web_search_call")
        self.assertIn("emit the complete JSON", continued_input[-1]["content"][0]["text"])
        self.assertTrue(response.raw["protolens_web_research_finalized"])
        self.assertTrue(any(item.get("type") == "web_search_call" for item in response.raw["output"]))

    def test_non_web_incomplete_response_retries_with_a_larger_output_budget(self) -> None:
        requests: list[dict[str, object]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                requests.append(json.loads(self.rfile.read(length)))
                if len(requests) == 1:
                    payload = {
                        "status": "incomplete",
                        "incomplete_details": {"reason": "max_output_tokens"},
                        "usage": {"output_tokens": 12000},
                        "output": [],
                    }
                else:
                    payload = {
                        "status": "completed",
                        "output": [
                            {
                                "type": "message",
                                "status": "completed",
                                "content": [{"type": "output_text", "text": '{"ok":true}'}],
                            }
                        ],
                    }
                response = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = LLMClient(
                provider="openai-compatible",
                model="local-model",
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
                max_tokens=12000,
                retries=1,
            )
            response = client.responses_json(
                system="system",
                user="user",
                response_schema={"type": "object"},
                schema_name="adaptive_budget",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(response.text, '{"ok":true}')
        self.assertEqual([item["max_output_tokens"] for item in requests], [12000, 24000])

    def test_fsm_recorder_preserves_incomplete_response_details(self) -> None:
        raw = {
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
            "usage": {"output_tokens": 12000},
            "output": [],
        }

        class IncompleteClient:
            retries = 0
            provider = "fake"
            model = "incomplete-model"

            def responses_json(self, **kwargs: object) -> object:
                raise IncompleteLLMResponse(raw)

        recorder = LLMConversationRecorder("test", IncompleteClient())
        with self.assertRaises(IncompleteLLMResponse):
            recorder.call_chat(
                system="system",
                payload={"protocol": "ftp"},
                schema={"type": "object"},
                schema_name="incomplete_record",
            )

        records = recorder.drain_conversations()
        self.assertEqual(records[0]["response"]["raw"]["incomplete_details"]["reason"], "max_output_tokens")
        self.assertEqual(records[0]["response"]["raw"]["usage"]["output_tokens"], 12000)

    def test_fsm_recorder_retries_when_required_fsm_key_is_missing(self) -> None:
        class SchemaRetryClient:
            is_offline = False
            retries = 1
            provider = "fake"
            model = "schema-retry"

            def __init__(self) -> None:
                self.calls = 0

            def responses_json(self, **kwargs: object) -> object:
                self.calls += 1
                text = "{}" if self.calls == 1 else '{"fsm":{}}'
                return type(
                    "Response",
                    (),
                    {"text": text, "provider": self.provider, "model": self.model, "raw": {}},
                )()

        client = SchemaRetryClient()
        recorder = LLMConversationRecorder("test", client)
        result = recorder.call_chat(
            system="system",
            payload={"task": "test"},
            schema={
                "type": "object",
                "additionalProperties": False,
                "required": ["fsm"],
                "properties": {"fsm": {"type": "object"}},
            },
            schema_name="required_fsm",
        )

        self.assertEqual(result, {"fsm": {}})
        self.assertEqual(client.calls, 2)
        conversations = recorder.drain_conversations()
        self.assertEqual(conversations[0]["final_status"], "retrying")
        self.assertIn("missing required keys", conversations[0]["error"]["message"])
        self.assertEqual(conversations[1]["final_status"], "success")

    def test_responses_api_does_not_treat_reasoning_as_final_output(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                self.rfile.read(length)
                response = json.dumps(
                    {
                        "status": "completed",
                        "output": [
                            {
                                "type": "reasoning",
                                "status": "completed",
                                "content": [{"type": "reasoning_text", "text": "Let me search first. {}"}],
                            },
                            {"type": "web_search_call", "status": "failed"},
                        ],
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = LLMClient(
                provider="openai-compatible",
                model="local-model",
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
                retries=0,
            )
            with self.assertRaisesRegex(RuntimeError, "empty response"):
                client.responses_json(
                    system="system",
                    user="user",
                    response_schema={"type": "object"},
                    schema_name="test",
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_responses_api_enables_web_search_and_strict_schema(self) -> None:
        received: dict[str, object] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                received["path"] = self.path
                received["body"] = json.loads(self.rfile.read(length))
                response = json.dumps(
                    {
                        "output": [
                            {"type": "web_search_call", "status": "completed"},
                            {
                                "type": "message",
                                "content": [{"type": "output_text", "text": '{"ok":true}'}],
                            },
                        ]
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = LLMClient(
                provider="openai-compatible",
                model="local-model",
                base_url=f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                retries=0,
            )
            response = client.responses_json(
                system="system",
                user="user",
                response_schema={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["ok"],
                    "properties": {"ok": {"type": "boolean"}},
                },
                schema_name="test_schema",
                web_search=True,
                allowed_domains=["rfc-editor.org"],
                max_tool_calls=4,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(response.text, '{"ok":true}')
        self.assertEqual(received["path"], "/v1/responses")
        body = received["body"]
        self.assertEqual(body["tool_choice"], "required")
        self.assertEqual(body["max_tool_calls"], 4)
        self.assertFalse(body["parallel_tool_calls"])
        self.assertEqual(body["tools"][0]["filters"]["allowed_domains"], ["rfc-editor.org"])
        self.assertEqual(body["text"]["format"]["type"], "json_schema")

    def test_local_compatible_endpoint_supports_headers_and_no_response_format(self) -> None:
        received: dict[str, object] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - HTTP handler API 固定命名
                length = int(self.headers["Content-Length"])
                received["path"] = self.path
                received["header"] = self.headers.get("X-ProtoLens-Test")
                received["body"] = json.loads(self.rfile.read(length))
                response = json.dumps({"choices": [{"message": {"content": '{"findings": []}'}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = LLMClient(
                provider="openai-compatible",
                model="local-model",
                base_url=f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                response_format="none",
                extra_headers={"X-ProtoLens-Test": "enabled"},
                retries=0,
            )
            response = client.chat_json(system="system", user="user")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(response.text, '{"findings": []}')
        self.assertEqual(received["path"], "/v1/chat/completions")
        self.assertEqual(received["header"], "enabled")
        self.assertNotIn("response_format", received["body"])

    def test_llm_client_accepts_content_parts(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - HTTP handler API 固定命名
                response = json.dumps(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": [
                                        {"type": "text", "text": '{"findings": []}'},
                                    ]
                                }
                            }
                        ]
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = LLMClient(
                provider="openai-compatible",
                model="local-model",
                base_url=f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                retries=0,
            )
            response = client.chat_json(system="system", user="user")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(response.text, '{"findings": []}')

    def test_llm_client_retries_without_response_format_after_empty_response(self) -> None:
        requests: list[dict[str, object]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - HTTP handler API 固定命名
                length = int(self.headers["Content-Length"])
                body = json.loads(self.rfile.read(length))
                requests.append(body)
                if "response_format" in body:
                    payload = {"choices": [{"message": {"content": ""}}]}
                else:
                    payload = {"choices": [{"message": {"content": '{"findings": []}'}}]}
                response = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = LLMClient(
                provider="openai-compatible",
                model="local-model",
                base_url=f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                retries=0,
            )
            response = client.chat_json(system="system", user="user")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(response.text, '{"findings": []}')
        self.assertEqual(len(requests), 2)
        self.assertIn("response_format", requests[0])
        self.assertNotIn("response_format", requests[1])


if __name__ == "__main__":
    unittest.main()
