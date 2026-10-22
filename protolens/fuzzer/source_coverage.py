"""Replay each new queue entry against an isolated gcov-instrumented target."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import fcntl
import gzip
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import threading
import time

from protolens.config import ProtoLensConfig
from protolens.fuzzer.coverage_report import CoverageHTTPServer, write_view
from protolens.tools.wire_protocols import split_wire_messages
from protolens.utils.artifact_store import ArtifactStore


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _summary(files: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for category in ("lines", "branches", "functions"):
        counts = [value if category == "lines" else value["count"]
                  for file in files.values() for value in file[category].values()]
        hit = sum(count > 0 for count in counts)
        result[category] = {"hit": hit, "total": len(counts),
                            "percent": round(100 * hit / len(counts), 3) if counts else 0.0}
    return result


def _merge(destination: dict[str, Any], source: dict[str, Any]) -> None:
    for name, file in source.items():
        target = destination.setdefault(name, {"lines": {}, "branches": {}, "functions": {}})
        for line, count in file["lines"].items():
            target["lines"][line] = target["lines"].get(line, 0) + count
        for category in ("branches", "functions"):
            for key, value in file[category].items():
                if key not in target[category]:
                    target[category][key] = dict(value)
                else:
                    target[category][key]["count"] += value["count"]


class SourceCoverageCollector:
    def __init__(self, config: ProtoLensConfig, output_dir: Path) -> None:
        self.config = config
        self.settings = config.source_coverage
        self.output_dir = Path(output_dir)
        self.root = config.run_dir / "source_coverage"
        self.store = ArtifactStore(self.root)
        self.public = ArtifactStore(self.root / "html")
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.http: CoverageHTTPServer | None = None
        self.lock = None
        self.seen: dict[str, tuple[int, int]] = {}
        self.completed_stamps: dict[str, tuple[int, int]] = {}
        self.notes: list[Path] = []
        self.state: dict[str, Any] = {}
        self.error: str | None = None
        self._gcov_format = "json"

    def initialize(self) -> None:
        if self.lock is not None:
            return
        self.config.validate()
        if not self.settings.enabled:
            raise ValueError("source_coverage.enabled must be true")
        try:
            self.lock = (self.root / "collector.lock").open("a")
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not self.settings.source_root.is_dir() or not self.settings.build_root.is_dir():
                raise ValueError("source coverage source_root and build_root must exist")
            self.notes = sorted(self.settings.build_root.rglob("*.gcno"))
            if not self.notes:
                raise ValueError("source_coverage.build_root contains no .gcno files")
            if not shutil.which(self.settings.gcov_binary):
                raise ValueError(f"gcov executable not found: {self.settings.gcov_binary}")
            executable = shutil.which(self.settings.target_cmd[0], path=self.settings.env.get("PATH"))
            if not executable:
                raise ValueError(f"coverage target executable not found: {self.settings.target_cmd[0]}")
            signature = hashlib.sha256(json.dumps({
                "target": self.settings.target_cmd, "source_root": str(self.settings.source_root),
                "target_sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
                "output_dir": str(self.output_dir.resolve()),
                "cwd": str(self.settings.cwd), "env": self.settings.env,
                "host": self.settings.host, "port": self.settings.port,
                "protocol": self.config.protocol, "gcov": self.settings.gcov_binary,
                "notes": [(str(p), hashlib.sha256(p.read_bytes()).hexdigest()) for p in self.notes],
            }, sort_keys=True).encode()).hexdigest()
            checkpoint = self.root / "checkpoint.json"
            if checkpoint.exists():
                self.state = self.store.read_json("checkpoint.json")
                if self.state["build_signature"] != signature:
                    raise ValueError("coverage build/config changed; use a new run_dir to avoid mixing coverage")
            else:
                baseline = {}
                with TemporaryDirectory(dir=self.root, prefix="baseline-") as work:
                    for note in self.notes:
                        _merge(baseline, self._read_unit(note, Path(work)))
                if not baseline:
                    raise ValueError("gcov found no source files under source_coverage.source_root")
                self.state = {"build_signature": signature, "files": baseline, "cases": {}, "history": []}
                self.store.write_json("checkpoint.json", self.state)
            sources = {}
            for name in self.state["files"]:
                path = (self.settings.source_root / name).resolve()
                path.relative_to(self.settings.source_root)
                try:
                    sources[name] = path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    sources[name] = []
            if (self.public.root / "sources.json").is_file() and self.public.read_json("sources.json") != sources:
                raise ValueError("coverage source text changed; use a new run_dir for matching source and coverage")
            self.public.write_json("sources.json", sources)
            write_view(self.public.root)
            self._publish()
            self._status("ready", pending=0)
        except BaseException:
            self.close()
            raise

    def _read_unit(self, note: Path, work: Path) -> dict[str, Any]:
        """Read one copied .gcno alongside its independently relocated .gcda."""
        unit = hashlib.sha256(str(note).encode()).hexdigest()[:16]
        mirrored = work / str(note.resolve()).lstrip("/")
        mirrored.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(note, mirrored)
        generated = work / "json" / unit
        generated.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, **self.settings.env, "LC_ALL": "C"}

        def invoke(format_option: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                [self.settings.gcov_binary, format_option, "--branch-probabilities",
                 "--branch-counts", str(mirrored)], cwd=generated, env=env,
                capture_output=True, text=True, timeout=self.settings.replay_timeout_seconds + 30,
            )

        option = "--json-format" if self._gcov_format == "json" else "--intermediate-format"
        run = invoke(option)
        diagnostic = (run.stderr + run.stdout).lower()
        if (run.returncode and self._gcov_format == "json" and "json-format" in diagnostic
                and any(message in diagnostic for message in ("unrecognized option", "unknown option",
                                                               "unsupported option"))):
            # GCC before 9 emits machine-readable text instead of JSON. Keep using
            # the configured gcov so its version still matches the target's gcno.
            self._gcov_format = "intermediate"
            run = invoke("--intermediate-format")
        if run.returncode:
            raise RuntimeError(f"gcov failed for {note}: {run.stderr[-2000:]}")
        if self._gcov_format == "intermediate":
            return self._read_intermediate_reports(note, generated, unit)
        reports = list(generated.glob("*.gcov.json.gz"))
        if not reports:
            raise RuntimeError(f"gcov produced no JSON for {note}; use a matching GCC/gcov version with JSON support")
        result: dict[str, Any] = {}
        for report in reports:
            with gzip.open(report, "rt", encoding="utf-8") as stream:
                data = json.load(stream)
            for file in data["files"]:
                source = Path(file["file"])
                if not source.is_absolute():
                    source = Path(data["current_working_directory"]) / source
                try:
                    name = source.resolve().relative_to(self.settings.source_root).as_posix()
                except ValueError:
                    continue
                item = {"lines": {}, "branches": {}, "functions": {}}
                for line_index, line in enumerate(file["lines"]):
                    number = str(line["line_number"])
                    item["lines"][number] = item["lines"].get(number, 0) + line["count"]
                    for index, branch in enumerate(line.get("branches", [])):
                        # Preserve separate translation-unit branches (e.g. header templates).
                        key = f"{unit}:{line_index}:{number}:{index}"
                        item["branches"][key] = {"line": line["line_number"], "count": branch["count"],
                                                  "throw": branch.get("throw", False)}
                for function in file.get("functions", []):
                    key = f"{unit}:{function['name']}:{function['start_line']}"
                    item["functions"][key] = {"name": function.get("demangled_name", function["name"]),
                                               "line": function["start_line"], "count": function["execution_count"]}
                _merge(result, {name: item})
        return result

    def _read_intermediate_reports(self, note: Path, generated: Path, unit: str) -> dict[str, Any]:
        """Read GCC 4.9–8 intermediate output without requiring source text in cwd.

        Legacy branches expose taken/not-taken, not execution frequencies. Their
        counts therefore accumulate replay hits; coverage hit/total stays exact.
        Format: https://gcc.gnu.org/onlinedocs/gcc-8.5.0/gcc/Invoking-Gcov.html
        """
        reports = sorted(generated.glob("*.gcov"))
        if not reports:
            raise RuntimeError(f"gcov produced no intermediate report for {note}")
        result: dict[str, Any] = {}
        source_root = self.settings.source_root.resolve()
        for report_index, report in enumerate(reports):
            item = None
            with report.open(encoding="utf-8", errors="replace") as stream:
                for record_index, record in enumerate(stream):
                    tag, separator, value = record.rstrip("\r\n").partition(":")
                    if not separator:
                        continue
                    if tag == "file":
                        item = None
                        source = Path(value)
                        # Older gcno files do not carry the compilation cwd. The
                        # object directory is the usual base (including live555);
                        # also support builds relative to the configured roots.
                        candidates = [source] if source.is_absolute() else [
                            base / source for base in dict.fromkeys(
                                (note.parent, self.settings.cwd or source_root, source_root)
                            )
                        ]
                        for candidate in candidates:
                            try:
                                name = candidate.resolve().relative_to(source_root).as_posix()
                            except ValueError:
                                continue
                            if candidate.is_file():
                                item = result.setdefault(name, {"lines": {}, "branches": {}, "functions": {}})
                                break
                    elif item is not None:
                        try:
                            if tag == "lcount":
                                fields = value.split(",")
                                number, count = str(int(fields[0])), int(fields[1])
                                item["lines"][number] = item["lines"].get(number, 0) + count
                            elif tag == "function":
                                # GCC 8 adds end_line before execution_count.
                                fields = value.split(",", 3)
                                if len(fields) == 4 and fields[2].lstrip("-").isdigit():
                                    start, _, count, name = fields
                                else:
                                    start, count, name = value.split(",", 2)
                                key = f"{unit}:{name}:{int(start)}"
                                function = item["functions"].setdefault(
                                    key, {"name": name, "line": int(start), "count": 0})
                                function["count"] += int(count)
                            elif tag == "branch":
                                number, state = value.split(",", 1)
                                if state not in {"taken", "nottaken", "notexec"}:
                                    raise ValueError(f"unknown branch state {state!r}")
                                key = f"{unit}:legacy:{report_index}:{record_index}"
                                item["branches"][key] = {
                                    "line": int(number), "count": int(state == "taken"),
                                    "count_semantics": "replays_with_branch_taken",
                                }
                        except (ValueError, IndexError) as exc:
                            raise RuntimeError(
                                f"invalid gcov intermediate record in {report}:{record_index + 1}: {record.rstrip()}"
                            ) from exc
        return result

    def _replay(self, payload: bytes, work: Path) -> dict[str, Any]:
        cfg = self.settings
        kind = socket.SOCK_DGRAM if self.config.network_transport == "udp" else socket.SOCK_STREAM
        # Refuse an occupied coverage port instead of accidentally replaying against AFLNet.
        with socket.socket(socket.AF_INET, kind) as reservation:
            reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            reservation.bind((cfg.host, cfg.port))
        env = os.environ.copy()
        env.update(cfg.env)
        env.update(GCOV_PREFIX=str(work.resolve()), GCOV_PREFIX_STRIP="0")
        target = None
        replay_error = ""
        sent = 0
        with (work / "target.log").open("wb") as log:
            try:
                target = subprocess.Popen(cfg.target_cmd, cwd=cfg.cwd or cfg.source_root,
                                          env=env, start_new_session=True, stdout=log, stderr=log)
                time.sleep(cfg.startup_seconds)
                deadline = time.monotonic() + cfg.replay_timeout_seconds
                connection = None
                while connection is None:
                    if target.poll() is not None:
                        raise RuntimeError(f"coverage target exited before replay: {target.returncode}")
                    try:
                        if kind == socket.SOCK_DGRAM:
                            connection = socket.socket(socket.AF_INET, kind)
                            connection.connect((cfg.host, cfg.port))
                        else:
                            connection = socket.create_connection((cfg.host, cfg.port), timeout=0.2)
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("coverage target did not become ready")
                        time.sleep(0.02)
                with connection:
                    for message in split_wire_messages(payload, self.config.protocol):
                        if time.monotonic() >= deadline:
                            raise TimeoutError("coverage replay timed out")
                        connection.settimeout(min(0.1, max(0.001, deadline - time.monotonic())))
                        connection.sendall(message)
                        sent += 1
                        try:
                            while connection.recv(65536):
                                if time.monotonic() >= deadline:
                                    break
                        except socket.timeout:
                            pass
            except (OSError, RuntimeError, TimeoutError) as exc:
                replay_error = str(exc)
            finally:
                if target:
                    try:
                        if target.poll() is None:
                            os.killpg(target.pid, getattr(signal, cfg.shutdown_signal))
                        target.wait(timeout=cfg.shutdown_seconds)
                    except subprocess.TimeoutExpired:
                        replay_error = replay_error or "coverage target did not exit and flush gcov data"
                    finally:
                        # Clean up any child processes even if the session leader exited.
                        try:
                            os.killpg(target.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        target.wait()
        if replay_error:
            raise RuntimeError(replay_error)
        touched = [note for note in self.notes if (work / str(note.resolve()).lstrip("/")).with_suffix(".gcda").is_file()]
        if not touched:
            raise RuntimeError("no relocated .gcda data: target must flush gcov on exit; check shutdown_signal and build paths")
        files = {}
        for note in touched:
            _merge(files, self._read_unit(note, work))
        return {"files": files, "messages_sent": sent, "target_exit_code": target.returncode,
                "gcda_files": len(touched)}

    def scan_once(self, *, force: bool = False) -> int:
        """Wait for stable queue files; a new filename is collected even for identical bytes."""
        candidates = []
        for path in sorted((self.output_dir / "queue").glob("*")):
            if path.is_symlink() or not path.is_file() or path.name.startswith("."):
                continue
            try:
                st = path.stat()
            except FileNotFoundError:
                continue
            stamp = (st.st_size, st.st_mtime_ns)
            stable = self.seen.get(path.name) == stamp
            self.seen[path.name] = stamp
            if not stamp[0] or not (force or stable):
                continue
            if self.completed_stamps.get(path.name) == stamp:
                continue
            try:
                payload = path.read_bytes()
                after = path.stat()
            except FileNotFoundError:
                continue
            if (after.st_size, after.st_mtime_ns) != stamp:
                continue
            key = hashlib.sha256(path.name.encode() + b"\0" + payload).hexdigest()
            if key not in self.state["cases"]:
                candidates.append((path, payload, key, stamp))
            else:
                self.completed_stamps[path.name] = stamp
        self._status("collecting" if candidates else "watching", pending=len(candidates))
        for index, (path, payload, key, stamp) in enumerate(candidates):
            if self.stop_event.is_set() and not force:
                break
            self._status("collecting", pending=len(candidates) - index, seed_file=path.name)
            self.collect_case(path.name, payload, key)
            self.completed_stamps[path.name] = stamp
        return len(candidates)

    def collect_case(self, seed_file: str, payload: bytes, key: str) -> None:
        before = _summary(self.state["files"])
        record: dict[str, Any] = {"seed_file": seed_file, "payload_sha256": hashlib.sha256(payload).hexdigest(),
                                  "key": key, "sequence": len(self.state["history"]) + 1,
                                  "completed_at": _now(), "status": "collected"}
        next_files = deepcopy(self.state["files"])
        started = time.monotonic()
        try:
            with TemporaryDirectory(dir=self.root, prefix="replay-") as work:
                replay = self._replay(payload, Path(work))
                _merge(next_files, replay.pop("files"))
                record.update(replay)
        except Exception as exc:
            record.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        record["completed_at"] = _now()
        record["summary"] = _summary(next_files)
        record["delta"] = {name: record["summary"][name]["hit"] - before[name]["hit"] for name in before}
        relative = f"snapshots/{len(self.state['history']) + 1:06d}-{key[:12]}"
        record["report"] = relative + "/index.html"
        snapshot = {**record, "files": self._with_summaries(next_files)}
        self.public.write_json(relative + "/coverage.json", snapshot)
        write_view(self.public.root, snapshot=self.public.path(relative))
        self.state["files"] = next_files
        self.state["cases"][key] = record
        self.state["history"].append(record)
        self.store.write_json("checkpoint.json", self.state)
        self._publish()

    @staticmethod
    def _with_summaries(files: dict[str, Any]) -> dict[str, Any]:
        return {name: {**file, "summary": _summary({name: file})} for name, file in files.items()}

    def _publish(self) -> None:
        history = self.state["history"]
        self.public.write_json("history.json", history)
        latest = history[-1] if history else {"summary": _summary(self.state["files"]), "delta": {}}
        self.public.write_json("latest.json", {**latest, "files": self._with_summaries(self.state["files"])})
        regions = []
        for name, file in self.state["files"].items():
            missed_lines = [int(line) for line, count in file["lines"].items() if count == 0]
            missed_branches = sorted({b["line"] for b in file["branches"].values() if b["count"] == 0})
            locations = sorted(set(missed_lines + missed_branches))
            if locations:
                try:
                    source = (self.settings.source_root / name).read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    source = []
                line = locations[0]
                regions.append({"file": name, "uncovered_lines": sorted(missed_lines)[:40],
                                "uncovered_branch_lines": missed_branches[:40],
                                "uncovered_functions": [f["name"] for f in file["functions"].values() if f["count"] == 0][:10],
                                "source_excerpt": "\n".join(f"{i+1}: {source[i]}" for i in range(max(0, line-4), min(len(source), line+4))),
                                "missing_count": len(locations)})
        regions.sort(key=lambda region: (-len(region["uncovered_branch_lines"]), -region["missing_count"], region["file"]))
        self.store.write_json("feedback.json", {"present": True, "basis": "independent gcov target; line/branch coverage, not AFL bitmap edges",
                             "source_root": str(self.settings.source_root), "summary": _summary(self.state["files"]),
                             "processed_count": len(history), "failed_count": sum(h["status"] == "failed" for h in history),
                             "updated_at": _now(), "uncovered_regions": regions[:self.settings.max_monitor_regions],
                             "recent_cases": history[-12:]})

    def _status(self, status: str, **fields: Any) -> None:
        self.public.write_json("status.json", {"status": status, "updated_at": _now(), **fields})

    def start(self) -> None:
        self.initialize()
        try:
            if self.settings.http_port:
                self.http = CoverageHTTPServer(self.public.root, self.settings.http_host, self.settings.http_port)
                self.http.start()
            self.thread = threading.Thread(target=self._watch, name="protolens-gcov", daemon=True)
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def _watch(self) -> None:
        try:
            while not self.stop_event.is_set():
                self.scan_once()
                self.stop_event.wait(self.settings.poll_seconds)
        except Exception as exc:
            self.error = str(exc)
            self._status("failed", error=str(exc))

    def close(self, *, drain: bool = False) -> None:
        self.stop_event.set()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join()
            self.thread = None
        try:
            if drain and self.state:
                self.scan_once(force=True)
                self._status("failed" if self.error else "complete", pending=0, error=self.error)
            elif self.state and self.lock:
                try:
                    status = self.public.read_json("status.json")
                except (OSError, ValueError):
                    status = {}
                if status.get("status") != "failed":
                    self._status("stopped", pending=status.get("pending", 0))
        finally:
            if self.http:
                self.http.close()
                self.http = None
            if self.lock:
                self.lock.close()
                self.lock = None


def coverage_feedback(config: ProtoLensConfig) -> dict[str, Any]:
    if not config.source_coverage.enabled:
        return {"present": False}
    root = config.run_dir / "source_coverage"
    try:
        feedback = json.loads((root / "feedback.json").read_text())
        feedback["collector"] = json.loads((root / "html/status.json").read_text())
        return feedback
    except (OSError, ValueError):
        return {"present": False, "reason": "coverage collector has not published data"}
