from dataclasses import asdict
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import json

from protolens.config import ProtoLensConfig
from protolens.fsm.fsm_model import Conflict, FuzzResult, PlannedStatePath, ProtocolFSM, State, StateTransition
from protolens.fuzzer.path_calibrator import PathCalibrator, _ResponseReader
from protolens.fuzzer.path_planner import PathPlanner
from protolens.fuzzer.state_aware_synthesizer import StateAwareTestSynthesizer
from protolens.pipeline import ProtoLensPipeline
from protolens.tools.corpus_encoder import CorpusEncoder


class CalibrationTests(unittest.TestCase):
    def config(self, root: Path, port: int) -> ProtoLensConfig:
        return ProtoLensConfig.from_dict({
            "protocol": "rtsp", "target_name": "calibration-test", "source_root": str(root),
            "run_dir": str(root / "run"), "host": "127.0.0.1", "port": port,
            "aflnet": {"dry_run": False, "cmd": ["afl-fuzz", "--", sys.executable,
                         str(Path(__file__).with_name("calibration_target.py")), str(port)]},
            "path_calibration": {"enabled": True, "timeout_seconds": 0.3, "startup_seconds": 2},
        })

    def paths(self):
        fsm = ProtocolFSM(protocol="rtsp", initial_state="START",
                          states={name: State(name) for name in ("START", "MID", "READY", "END")},
                          transitions=[StateTransition("START", "READY", "BAD"),
                                       StateTransition("START", "MID", "GOOD"),
                                       StateTransition("MID", "READY", "NEXT"),
                                       StateTransition("READY", "END", "FINISH")])
        conflict = Conflict(kind="test", priority="P1", state="READY", transition="FINISH -> END",
                            description="test", expected_path=[], fuzzing_strategy="test")
        return PathPlanner().plan(fsm, [conflict]), conflict

    def test_candidates_are_not_execution_proofs(self):
        paths, _ = self.paths()
        self.assertEqual([p.messages for p in paths], [["BAD", "FINISH"], ["GOOD", "NEXT", "FINISH"]])
        self.assertNotEqual(paths[0].candidate_id, paths[1].candidate_id)
        self.assertTrue(all(p.calibration["status"] == "candidate" for p in paths))
        self.assertEqual(PlannedStatePath.from_dict(asdict(paths[0])), paths[0])

    def test_real_execution_selects_longer_accepted_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = self.config(Path(tmp), port)
            paths, conflict = self.paths()
            report = PathCalibrator().calibrate(config, paths)
            self.assertEqual(report["probe_count"], 2)
            self.assertEqual(paths[0].calibration["status"], "rejected")
            self.assertEqual(paths[0].calibration["failure_index"], 0)
            self.assertEqual(paths[1].calibration["status"], "response_accepted")
            self.assertEqual(paths[1].calibration["accepted_prefix_length"], 3)
            self.assertFalse(paths[1].calibration["state_verified"])
            selected = PathCalibrator.select(paths)
            self.assertEqual(selected, [paths[1]])
            seeds = StateAwareTestSynthesizer().synthesize(selected, [conflict], "rtsp")
            self.assertEqual(seeds[0].messages, ["GOOD", "NEXT", "FINISH"])
            self.assertEqual(seeds[0].source_candidate_id, paths[1].candidate_id)
            # Managed targets have been reaped and their listening socket released.
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", port))

    def test_calibrator_binds_rtsp_session_from_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = self.config(Path(tmp), port)
            path = PlannedStatePath("conflict", ["START", "READY"], ["SETUP /media", "PLAY /media"])

            report = PathCalibrator().calibrate(config, [path])

            self.assertEqual(report["items"][0]["status"], "response_accepted")
            self.assertEqual(report["items"][0]["response_bindings"]["session"], "CALIB123")
            self.assertEqual(path.messages[1], "PLAY /media --session=CALIB123")
            self.assertEqual(report["items"][0]["events"][1]["bound_message"], "PLAY /media --session=CALIB123")

    def test_disconnect_retains_only_observed_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            config = self.config(Path(tmp), port)
            path = PlannedStatePath("test", ["A", "B", "C"], ["GOOD", "CLOSE"])
            PathCalibrator().calibrate(config, [path])
            self.assertEqual(path.calibration["status"], "inconclusive")
            self.assertEqual(path.calibration["accepted_prefix_length"], 1)

    def test_dry_run_and_busy_port_never_verify_paths(self):
        with tempfile.TemporaryDirectory() as tmp, socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            config = self.config(Path(tmp), listener.getsockname()[1])
            paths, _ = self.paths()
            config.aflnet.dry_run = True
            self.assertEqual(PathCalibrator().calibrate(config, paths)["probe_count"], 0)
            self.assertTrue(all(p.calibration["status"] == "candidate" for p in paths))
            config.aflnet.dry_run = False
            PathCalibrator().calibrate(config, paths[:1])
            self.assertEqual(paths[0].calibration["status"], "inconclusive")
            self.assertIn("occupied", paths[0].calibration["reason"])

    def test_fragmented_multiline_reply_and_truncated_body(self):
        left, right = socket.socketpair()
        with left, right:
            def send():
                for part in (b"220-Hello\r", b"\nintermediate\r\n220 Ready\r\n", b"331 Password\r\n"):
                    right.sendall(part)
            thread = threading.Thread(target=send)
            thread.start()
            reader = _ResponseReader(left, 0.5)
            self.assertEqual(reader.read("ftp"), 220)
            self.assertEqual(reader.read("ftp"), 331)
            thread.join()
        left, right = socket.socketpair()
        with left, right:
            right.sendall(b"RTSP/1.0 200 OK\r\nContent-Length: 8\r\n\r\nshort")
            right.shutdown(socket.SHUT_WR)
            with self.assertRaisesRegex(ValueError, "complete response"):
                _ResponseReader(left, 0.5).read("rtsp")

    def test_search_and_probe_budgets(self):
        paths, _ = self.paths()
        with tempfile.TemporaryDirectory() as tmp:
            config = self.config(Path(tmp), 12345)
            config.path_calibration.max_probes = 1
            class CountingCalibrator(PathCalibrator):
                def _probe(self, *args):
                    return self._unobserved("inconclusive", "test")
            report = CountingCalibrator().calibrate(config, paths)
            self.assertEqual(report["probe_count"], 1)
            self.assertEqual(paths[1].calibration["status"], "candidate")
            config.path_calibration.timeout_seconds = float("nan")
            with self.assertRaises(ValueError):
                config.validate()

    def test_pipeline_prepares_selected_path_and_persists_lineage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = self.config(root, port)
            paths, conflict = self.paths()
            pipeline = ProtoLensPipeline(config)
            def prepare(config, selected, seed_intents=None):
                self.assertEqual(selected[0].messages, ["GOOD", "NEXT", "FINISH"])
                self.assertTrue((config.run_dir / "path_calibration.json").exists())
                CorpusEncoder().write_seed_intents(seed_intents, root / "corpus", "rtsp",
                                                  seed_manifest_path=config.run_dir / "seed_manifest.json")
                return FuzzResult("dry-run", [], str(root / "corpus"), str(root / "dict"), str(root / "out"))
            # Only AFLNet execution is stubbed; managed target probes use real TCP.
            with patch.object(pipeline.path_planner, "plan", return_value=paths), \
                 patch.object(pipeline.path_aware_fuzzer, "prepare", new=prepare):
                pipeline.synthesize_and_fuzz(None, [conflict])
            before = json.loads((config.run_dir / "candidate_paths.json").read_text())
            after = json.loads((config.run_dir / "calibrated_paths.json").read_text())
            manifest = json.loads((config.run_dir / "seed_manifest.json").read_text())
            self.assertTrue(all(p["calibration"]["status"] == "candidate" for p in before))
            self.assertEqual(after[0]["calibration"]["status"], "rejected")
            self.assertTrue(all(s["source_candidate_id"] == paths[1].candidate_id for s in manifest["entries"]))

    def test_search_bounds_and_self_loop(self):
        fsm = ProtocolFSM(protocol="rtsp", initial_state="A", states={s: State(s) for s in ("A", "B", "C")},
                          transitions=[StateTransition("A", "A", "LOGIN"), StateTransition("A", "B", "GO"),
                                       StateTransition("B", "C", "END")])
        conflict = Conflict("test", "P1", "C", None, "", [], "")
        paths = PathPlanner(max_candidates=3).plan(fsm, [conflict])
        self.assertEqual([p.messages for p in paths], [["GO", "END"], ["LOGIN", "GO", "END"]])
        depth_limited = PathPlanner(max_depth=1).plan(fsm, [conflict])[0]
        expansion_limited = PathPlanner(max_expansions=1).plan(fsm, [conflict])[0]
        self.assertFalse(depth_limited.reachable)
        self.assertTrue(depth_limited.candidate_id.startswith("path_"))
        self.assertEqual(depth_limited.calibration["status"], "not_executable")
        self.assertFalse(expansion_limited.reachable)


if __name__ == "__main__":
    unittest.main()
