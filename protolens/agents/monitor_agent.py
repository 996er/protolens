from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import hashlib
import json
import re
import time

from protolens.config import ProtoLensConfig
from protolens.fsm.fsm_model import Conflict, FuzzResult, PlannedStatePath, stable_id
from protolens.tools.corpus_encoder import CorpusEncoder
from protolens.utils.client_messages import client_seed_message
from protolens.utils.llm_client import LLMClient


@dataclass
class _CoveragePoint:
    signature: tuple[Any, ...]
    execs_done: int
    observed_at: float


class MonitorAgent:
    """Runtime coverage-stagnation monitor for a live AFLNet campaign."""

    name = "monitor_agent"

    def __init__(self, llm_client: LLMClient | None = None, encoder: CorpusEncoder | None = None) -> None:
        self.llm_client = llm_client or LLMClient()
        self.encoder = encoder or CorpusEncoder()
        self._last_check_at = 0.0
        self._last_improvement: _CoveragePoint | None = None
        self._event_counter = 0
        self._generated_keys: set[str] = set()
        self._generated_payload_hashes: set[str] = set()
        self._coverage_llm_calls: dict[str, int] = {}
        self._coverage_llm_failures: dict[str, int] = {}
        self._coverage_llm_retry_after: dict[str, float] = {}
        self._manifest_seeds: list[dict[str, Any]] = []
        self._manifest_loaded = False
        self._decisions: list[dict[str, Any]] = []
        self._llm_conversations: list[dict[str, Any]] = []

    def import_dir(self, config: ProtoLensConfig) -> Path:
        return config.monitor_agent.import_dir or (config.run_dir / "monitor_import_queue")

    def manifest_path(self, config: ProtoLensConfig) -> Path:
        return config.run_dir / "monitor_seed_manifest.json"

    def observe(
        self,
        config: ProtoLensConfig,
        fuzz_result: FuzzResult,
        dynamic: dict[str, Any],
        planned_paths: list[PlannedStatePath],
        conflicts: list[Conflict],
        *,
        force: bool = False,
        seed_feedback: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        now = time.monotonic()
        monitor_config = config.monitor_agent
        if not monitor_config.enabled:
            return self._record({"status": "disabled", "reason": "monitor_agent.enabled is false"})
        if config.aflnet.dry_run or fuzz_result.mode not in {"running", "timed-out", "executed"}:
            return self._record(
                {
                    "status": "inactive",
                    "reason": f"campaign phase is {fuzz_result.mode}; live monitoring requires a running AFLNet campaign",
                }
            )
        if not force and now - self._last_check_at < monitor_config.interval_seconds:
            return None
        self._last_check_at = now

        snapshot = _coverage_snapshot(dynamic)
        if not snapshot["stats_present"]:
            return self._record(
                {
                    "status": "waiting_for_stats",
                    "reason": "AFLNet fuzzer_stats is not present yet",
                    "coverage_snapshot": snapshot,
                }
            )

        signature = _coverage_signature(snapshot)
        execs_done = int(snapshot["execs_done"])
        if self._last_improvement is None or signature != self._last_improvement.signature:
            self._last_improvement = _CoveragePoint(signature=signature, execs_done=execs_done, observed_at=now)
            return self._record(
                {
                    "status": "improving",
                    "reason": "coverage or AFLNet state signature changed since the previous monitor sample",
                    "coverage_snapshot": snapshot,
                }
            )

        stagnant_for = now - self._last_improvement.observed_at
        exec_delta = max(0, execs_done - self._last_improvement.execs_done)
        if stagnant_for < monitor_config.stagnation_seconds:
            return self._record(
                {
                    "status": "not_stagnant",
                    "reason": "coverage signature is stable but the stagnation window has not elapsed",
                    "coverage_snapshot": snapshot,
                    "stagnant_for_seconds": round(stagnant_for, 3),
                }
            )
        if exec_delta < monitor_config.min_exec_delta and _as_float(snapshot["execs_per_sec"]) > 0:
            return self._record(
                {
                    "status": "warming_up",
                    "reason": "coverage is stable, but too few executions have run since the last improvement",
                    "coverage_snapshot": snapshot,
                    "exec_delta_since_improvement": exec_delta,
                }
            )

        self._load_seed_manifest(config)
        self._refresh_seed_receipts(config, dynamic)
        signature_key = _signature_key(signature)
        if (
            self._coverage_llm_calls.get(signature_key, 0)
            >= monitor_config.max_llm_calls_per_stagnation_signature
        ):
            return self._record(
                {
                    "status": "stagnant_llm_suppressed",
                    "reason": "coverage signature is unchanged and this stagnation signature already reached its LLM-call budget",
                    "coverage_snapshot": snapshot,
                    "coverage_signature_key": signature_key,
                    "stagnant_for_seconds": round(stagnant_for, 3),
                    "exec_delta_since_improvement": exec_delta,
                    "import_dir": str(self.import_dir(config)),
                    "generated_seeds": [],
                    "bottleneck": _bottleneck(dynamic, planned_paths),
                    "llm_calls_for_signature": self._coverage_llm_calls.get(signature_key, 0),
                }
            )
        retry_after = self._coverage_llm_retry_after.get(signature_key, 0.0)
        if retry_after > now:
            return self._record(
                {
                    "status": "stagnant_llm_backoff",
                    "reason": "previous monitor LLM analysis failed; retry is delayed by backoff",
                    "coverage_snapshot": snapshot,
                    "coverage_signature_key": signature_key,
                    "stagnant_for_seconds": round(stagnant_for, 3),
                    "exec_delta_since_improvement": exec_delta,
                    "import_dir": str(self.import_dir(config)),
                    "generated_seeds": [],
                    "bottleneck": _bottleneck(dynamic, planned_paths),
                    "llm_failures_for_signature": self._coverage_llm_failures.get(signature_key, 0),
                    "retry_after_monotonic": round(retry_after, 6),
                }
            )
        if (
            self._coverage_llm_failures.get(signature_key, 0)
            >= monitor_config.max_llm_failures_per_stagnation_signature
        ):
            return self._record(
                {
                    "status": "stagnant_llm_failure_suppressed",
                    "reason": "this stagnation signature reached its monitor LLM failure retry budget",
                    "coverage_snapshot": snapshot,
                    "coverage_signature_key": signature_key,
                    "stagnant_for_seconds": round(stagnant_for, 3),
                    "exec_delta_since_improvement": exec_delta,
                    "import_dir": str(self.import_dir(config)),
                    "generated_seeds": [],
                    "bottleneck": _bottleneck(dynamic, planned_paths),
                    "llm_failures_for_signature": self._coverage_llm_failures.get(signature_key, 0),
                }
            )
        self._write_seed_manifest(config)

        analysis = self._analyze_bottleneck_with_llm(
            config,
            fuzz_result,
            dynamic,
            planned_paths,
            conflicts,
            seed_feedback,
        )
        if not analysis.get("ok"):
            failures = self._coverage_llm_failures.get(signature_key, 0) + 1
            self._coverage_llm_failures[signature_key] = failures
            self._coverage_llm_retry_after[signature_key] = now + monitor_config.llm_failure_backoff_seconds * (2 ** (failures - 1))
            self._write_seed_manifest(config)
            return self._record(
                {
                    "status": "llm_failed",
                    "reason": "coverage is stagnant, but monitor LLM analysis failed",
                    "coverage_snapshot": snapshot,
                    "coverage_signature_key": signature_key,
                    "stagnant_for_seconds": round(stagnant_for, 3),
                    "exec_delta_since_improvement": exec_delta,
                    "import_dir": str(self.import_dir(config)),
                    "generated_seeds": [],
                    "bottleneck": _bottleneck(dynamic, planned_paths),
                    "llm_error": analysis.get("error", "unknown LLM failure"),
                    "llm_failures_for_signature": failures,
                    "retry_after_monotonic": round(self._coverage_llm_retry_after[signature_key], 6),
                }
            )

        self._coverage_llm_calls[signature_key] = self._coverage_llm_calls.get(signature_key, 0) + 1
        self._coverage_llm_failures.pop(signature_key, None)
        self._coverage_llm_retry_after.pop(signature_key, None)
        seeds, skipped = self._write_llm_breakthrough_seeds(config, planned_paths, conflicts, analysis, dynamic)
        decision = {
            "status": "stagnant" if seeds else "stagnant_no_seed",
            "reason": (
                "coverage signature is stagnant; LLM generated breakthrough seeds for AFLNet live import"
                if seeds
                else "coverage signature is stagnant, but the monitor LLM returned no non-duplicate valid seed candidates"
            ),
            "coverage_snapshot": snapshot,
            "coverage_signature_key": signature_key,
            "stagnant_for_seconds": round(stagnant_for, 3),
            "exec_delta_since_improvement": exec_delta,
            "import_dir": str(self.import_dir(config)),
            "generated_seeds": seeds,
            "skipped_candidates": skipped,
            "bottleneck": _bottleneck(dynamic, planned_paths),
            "llm_analysis": {
                "provider": analysis.get("provider", ""),
                "model": analysis.get("model", ""),
                "bottleneck_summary": analysis.get("bottleneck_summary", ""),
                "candidate_count": len(analysis.get("seed_candidates", [])),
            },
        }
        if seeds:
            self._last_improvement = _CoveragePoint(signature=signature, execs_done=execs_done, observed_at=now)
        return self._record(decision)

    def report(self) -> dict[str, Any]:
        return {
            "format": "protolens.monitor_agent_report.v1",
            "decisions": list(self._decisions[-200:]),
        }

    def drain_llm_conversations(self) -> list[dict[str, Any]]:
        conversations = list(self._llm_conversations)
        self._llm_conversations.clear()
        return conversations

    def _record(self, decision: dict[str, Any]) -> dict[str, Any]:
        item = {
            "format": "protolens.monitor_agent_decision.v1",
            "agent": self.name,
            "event_index": len(self._decisions),
            "observed_at_monotonic": round(time.monotonic(), 6),
            **decision,
        }
        self._decisions.append(item)
        return item

    def _analyze_bottleneck_with_llm(
        self,
        config: ProtoLensConfig,
        fuzz_result: FuzzResult,
        dynamic: dict[str, Any],
        planned_paths: list[PlannedStatePath],
        conflicts: list[Conflict],
        seed_feedback: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.llm_client.is_offline:
            return {"ok": False, "error": "monitor_agent requires an online LLM provider for stagnant coverage analysis"}

        payload = {
            "task": (
                "Analyze why the AFLNet campaign is coverage-stagnant and return concrete protocol "
                "seed candidates likely to break strong state guards. Mutate only the verified execution frontier "
                "reconstructed from AFLNet IPSM/queue feedback. Use only client-sendable protocol messages. "
                "Do not include transport actions such as TCP reset, half-close, or TLS renegotiation."
            ),
            "protocol": config.protocol,
            "target_name": config.target_name,
            "fuzz_result": {
                "mode": fuzz_result.mode,
                "output_dir": fuzz_result.output_dir,
                "crashes": fuzz_result.crashes[:20],
                "hangs": fuzz_result.hangs[:20],
            },
            "dynamic_feedback": _compact_dynamic(dynamic),
            "execution_frontier": _execution_frontier_context(dynamic),
            "planned_paths": _planned_path_context(planned_paths, config.protocol),
            "conflicts": _conflict_context(conflicts),
            "seed_feedback": _seed_feedback_context(seed_feedback),
            "monitor_seed_feedback": _monitor_seed_feedback_context(self._load_seed_manifest(config)),
            "frontier_feedback": _frontier_feedback_context(
                self._load_seed_manifest(config),
                config.monitor_agent.frontier_failure_threshold,
            ),
            "heuristic_seed_templates": _heuristic_seed_templates(planned_paths, config.protocol),
            "previous_monitor_seeds": _previous_seed_context(self._load_seed_manifest(config)),
            "required_output": {
                "bottleneck_summary": "short explanation grounded in the dynamic feedback",
                "seed_candidates": [
                    {
                        "conflict_id": "id from planned_paths",
                        "candidate_id": "candidate_id from planned_paths; prefer this over conflict_id when present",
                        "frontier_queue_id": "queue_id from execution_frontier.candidates when available",
                        "messages": ["small mutation of a verified execution_frontier command sequence"],
                        "rationale": "why this sequence may reach a stronger guarded state",
                        "expected_new_coverage": "state/guard/branch expected to be exercised",
                    }
                ],
                "raw_payloads": (
                    "For FTP, use raw:<escaped bytes> or raw-b64:<base64 bytes> when the test requires missing "
                    "arguments, unusual whitespace, command fragmentation, or binary prefixes. Plain FTP command "
                    "messages may be normalized by ProtoLens."
                ),
            },
        }
        system = (
            "You are ProtoLens MonitorAgent. You analyze live AFLNet feedback for stateful protocol fuzzing. "
            "Return strict JSON only. Seed candidates must be executable AFLNet client seed streams after "
            "ProtoLens encodes each message; do not claim coverage is achieved until AFLNet observes it."
        )
        user = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        conversation: dict[str, Any] = {
            "agent": self.name,
            "provider": getattr(self.llm_client, "provider", ""),
            "model": getattr(self.llm_client, "model", ""),
            "system": system,
            "user": user,
            "schema_name": "protolens_monitor_seed_candidates",
            "json_schema": MONITOR_ANALYSIS_SCHEMA,
        }
        try:
            response = self.llm_client.chat_json(
                system=system,
                user=user,
                response_schema=MONITOR_ANALYSIS_SCHEMA,
                schema_name="protolens_monitor_seed_candidates",
            )
            conversation["response"] = {
                "text": response.text,
                "provider": response.provider,
                "model": response.model,
                "raw": response.raw,
            }
            data = _load_json_object(response.text)
            analysis = _validate_monitor_analysis(data)
            conversation["parsed_candidates"] = len(analysis["seed_candidates"])
            self._llm_conversations.append(conversation)
            return {
                "ok": True,
                "provider": response.provider,
                "model": response.model,
                **analysis,
            }
        except Exception as exc:
            conversation["error"] = {"type": type(exc).__name__, "message": str(exc)}
            self._llm_conversations.append(conversation)
            return {"ok": False, "error": str(exc)}

    def _write_llm_breakthrough_seeds(
        self,
        config: ProtoLensConfig,
        planned_paths: list[PlannedStatePath],
        conflicts: list[Conflict],
        analysis: dict[str, Any],
        dynamic: dict[str, Any] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        self._load_seed_manifest(config)
        import_dir = self.import_dir(config)
        import_dir.mkdir(parents=True, exist_ok=True)
        (import_dir / ".processed").mkdir(exist_ok=True)
        conflict_index = {conflict.id: conflict for conflict in conflicts}
        path_by_candidate = {path.candidate_id: path for path in planned_paths if path.candidate_id}
        paths_by_conflict: dict[str, list[PlannedStatePath]] = {}
        for path in planned_paths:
            paths_by_conflict.setdefault(path.conflict_id, []).append(path)
        written: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for candidate in analysis.get("seed_candidates", []):
            conflict_id = str(candidate["conflict_id"])
            candidate_id = str(candidate.get("candidate_id", "")).strip()
            path = _select_candidate_path(candidate_id, conflict_id, path_by_candidate, paths_by_conflict)
            if path is None:
                skipped.append(
                    {
                        "conflict_id": conflict_id,
                        "candidate_id": candidate_id,
                        "reason": "unknown, ambiguous, or unreachable candidate path",
                    }
                )
                continue
            messages = [_candidate_message_text(item) for item in candidate["messages"]]
            messages = [message for message in (_client_seed_message(message, config.protocol) for message in messages) if message]
            if not messages:
                skipped.append({"conflict_id": conflict_id, "candidate_id": candidate_id, "reason": "empty client-sendable message sequence"})
                continue
            frontier_match = _frontier_match(messages, dynamic)
            if frontier_match is not None and not frontier_match.get("matched"):
                skipped.append(
                    {
                        "conflict_id": conflict_id,
                        "candidate_id": candidate_id,
                        "reason": "outside_verified_execution_frontier",
                        "candidate_commands": frontier_match.get("candidate_commands", []),
                        "required_frontier_examples": frontier_match.get("frontier_examples", []),
                    }
                )
                continue
            frontier_key = _candidate_frontier_key(candidate, messages, frontier_match)
            bucket = _frontier_bucket_status(
                self._manifest_seeds,
                frontier_key,
                config.monitor_agent.frontier_failure_threshold,
            )
            if bucket.get("suppressed"):
                skipped.append(
                    {
                        "conflict_id": conflict_id,
                        "candidate_id": candidate_id,
                        "reason": "frontier_bucket_suppressed",
                        "frontier_key": frontier_key,
                        "failed_without_new_coverage": bucket.get("failed_without_new_coverage", 0),
                        "failure_threshold": bucket.get("failure_threshold", 0),
                    }
                )
                continue
            canonical_key = _candidate_key(path.candidate_id or conflict_id, messages)
            payload_path = PlannedStatePath(
                conflict_id=f"{conflict_id}.monitor",
                states=list(path.states),
                messages=messages,
                required_guards=list(path.required_guards),
                mutation_points=list(path.mutation_points),
                reachable=True,
                reason=str(candidate.get("rationale", "")),
            )
            payload = self.encoder.payload_for_path(payload_path, config.protocol)
            if not payload:
                skipped.append({"conflict_id": conflict_id, "candidate_id": candidate_id, "reason": "protocol encoder produced an empty payload"})
                continue
            payload_sha256 = hashlib.sha256(payload).hexdigest()
            if canonical_key in self._generated_keys or payload_sha256 in self._generated_payload_hashes:
                skipped.append(
                    {
                        "conflict_id": conflict_id,
                        "candidate_id": candidate_id,
                        "reason": "duplicate_monitor_seed",
                        "canonical_key": canonical_key,
                        "payload_sha256": payload_sha256,
                    }
                )
                continue
            self._event_counter += 1
            name = f"id:{self._event_counter:06d},src:protolens_monitor,{canonical_key[:60]}"
            seed_path = import_dir / name
            tmp_path = import_dir / f".{name}.tmp"
            tmp_path.write_bytes(payload)
            tmp_path.replace(seed_path)
            self._generated_keys.add(canonical_key)
            self._generated_payload_hashes.add(payload_sha256)
            conflict = conflict_index.get(conflict_id)
            seed_record = {
                "path": str(seed_path),
                "bytes": len(payload),
                "payload_sha256": payload_sha256,
                "canonical_key": canonical_key,
                "conflict_id": conflict_id,
                "source_candidate_id": path.candidate_id,
                "frontier_key": frontier_key,
                "frontier_queue_id": str(candidate.get("frontier_queue_id", "")).strip(),
                "frontier_commands": frontier_match.get("frontier_commands", []) if isinstance(frontier_match, dict) else [],
                "priority": conflict.priority if conflict else "P2",
                "states": path.states,
                "messages": messages,
                "required_guards": path.required_guards,
                "mutation_points": path.mutation_points,
                "reason": str(candidate.get("rationale", "")),
                "expected_new_coverage": str(candidate.get("expected_new_coverage", "")),
                "source": "llm_monitor_analysis",
                "execution_receipt": {"processed": False, "outcome": "pending_import"},
                "coverage_semantics": (
                    "imported as a candidate; AFLNet save_if_interesting decides whether it produced real new coverage"
                ),
            }
            written.append(seed_record)
            self._manifest_seeds.append(seed_record)
            self._manifest_seeds = _dedupe_seed_records(self._manifest_seeds)
            self._write_seed_manifest(config)
            if len(written) >= config.monitor_agent.max_seed_batch:
                return written, skipped
        self._write_seed_manifest(config)
        return written, skipped

    def _load_seed_manifest(self, config: ProtoLensConfig) -> dict[str, Any]:
        if self._manifest_loaded:
            return self._seed_manifest(config)
        path = self.manifest_path(config)
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            raw_seeds = data.get("seeds", []) if isinstance(data, dict) else []
            self._manifest_seeds = [item for item in raw_seeds if isinstance(item, dict)]
            for item in self._manifest_seeds:
                if not isinstance(item, dict):
                    continue
                canonical_key = str(item.get("canonical_key", "")).strip()
                payload_sha256 = str(item.get("payload_sha256", "")).strip()
                if canonical_key:
                    self._generated_keys.add(canonical_key)
                if payload_sha256:
                    self._generated_payload_hashes.add(payload_sha256)
                self._event_counter = max(self._event_counter, _event_index_from_path(item.get("path")))
            calls = data.get("coverage_llm_calls", {}) if isinstance(data, dict) else {}
            if isinstance(calls, dict):
                self._coverage_llm_calls.update({str(key): _as_int(value) for key, value in calls.items()})
            failures = data.get("coverage_llm_failures", {}) if isinstance(data, dict) else {}
            if isinstance(failures, dict):
                self._coverage_llm_failures.update({str(key): _as_int(value) for key, value in failures.items()})
            retry_after = data.get("coverage_llm_retry_after", {}) if isinstance(data, dict) else {}
            if isinstance(retry_after, dict):
                self._coverage_llm_retry_after.update({str(key): _as_float(value) for key, value in retry_after.items()})
        self._manifest_loaded = True
        self._scan_existing_import_seeds(config)
        return self._seed_manifest(config)

    def _seed_manifest(self, config: ProtoLensConfig) -> dict[str, Any]:
        self._refresh_seed_receipts(config, None)
        return {
            "format": "protolens.monitor_seed_manifest.v1",
            "seed_count": len(self._manifest_seeds),
            "canonical_keys": sorted(self._generated_keys),
            "payload_sha256s": sorted(self._generated_payload_hashes),
            "coverage_llm_calls": dict(sorted(self._coverage_llm_calls.items())),
            "coverage_llm_failures": dict(sorted(self._coverage_llm_failures.items())),
            "coverage_llm_retry_after": dict(sorted(self._coverage_llm_retry_after.items())),
            "seeds": list(self._manifest_seeds),
        }

    def _write_seed_manifest(self, config: ProtoLensConfig) -> None:
        self._refresh_seed_receipts(config, None)
        path = self.manifest_path(config)
        path.parent.mkdir(parents=True, exist_ok=True)
        seed_by_hash = {
            str(item.get("payload_sha256")): item
            for item in self._manifest_seeds
            if isinstance(item, dict) and item.get("payload_sha256")
        }
        for seed_path in sorted(self.import_dir(config).glob("id:*src:protolens_monitor*")):
            if not seed_path.is_file():
                continue
            try:
                payload_sha256 = hashlib.sha256(seed_path.read_bytes()).hexdigest()
            except OSError:
                continue
            canonical_key = _canonical_key_from_seed_name(seed_path.name)
            if canonical_key:
                self._generated_keys.add(canonical_key)
            self._generated_payload_hashes.add(payload_sha256)
            self._event_counter = max(self._event_counter, _event_index_from_path(seed_path.name))
            seed_by_hash.setdefault(
                payload_sha256,
                {
                    "path": str(seed_path),
                    "payload_sha256": payload_sha256,
                    "canonical_key": canonical_key,
                    "source": "existing_monitor_import_queue",
                },
            )
        manifest = {
            "format": "protolens.monitor_seed_manifest.v1",
            "seed_count": len(seed_by_hash),
            "canonical_keys": sorted(self._generated_keys),
            "payload_sha256s": sorted(self._generated_payload_hashes),
            "coverage_llm_calls": dict(sorted(self._coverage_llm_calls.items())),
            "coverage_llm_failures": dict(sorted(self._coverage_llm_failures.items())),
            "coverage_llm_retry_after": dict(sorted(self._coverage_llm_retry_after.items())),
            "seeds": sorted(seed_by_hash.values(), key=lambda item: str(item.get("path", ""))),
        }
        self._manifest_seeds = list(manifest["seeds"])
        tmp_path = path.with_name(f".{path.name}.tmp")
        tmp_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp_path.replace(path)

    def _refresh_seed_receipts(self, config: ProtoLensConfig, dynamic: dict[str, Any] | None) -> None:
        if not self._manifest_seeds:
            return
        import_dir = self.import_dir(config)
        processed_dir = import_dir / ".processed"
        queue_files = [str(item) for item in dynamic.get("queue_files", [])] if isinstance(dynamic, dict) else []
        for seed in self._manifest_seeds:
            if not isinstance(seed, dict):
                continue
            seed_name = Path(str(seed.get("path", ""))).name
            if not seed_name:
                continue
            receipt = dict(seed.get("execution_receipt", {})) if isinstance(seed.get("execution_receipt"), dict) else {}
            marker = processed_dir / seed_name
            if marker.is_file():
                receipt.update(_read_processed_receipt(marker))
                receipt["processed"] = True
            else:
                receipt.setdefault("processed", False)
            queue_matches = _monitor_queue_matches(seed, queue_files)
            if queue_matches:
                receipt["queue_files"] = queue_matches[:10]
            saved = bool(receipt.get("saved_interesting")) or bool(queue_matches)
            receipt["saved_interesting"] = saved
            receipt["outcome"] = _receipt_outcome(receipt)
            seed["execution_receipt"] = receipt

    def _scan_existing_import_seeds(self, config: ProtoLensConfig) -> None:
        import_dir = self.import_dir(config)
        if not import_dir.exists():
            self._manifest_seeds = _dedupe_seed_records(self._manifest_seeds)
            return
        known_hashes = {
            str(item.get("payload_sha256"))
            for item in self._manifest_seeds
            if isinstance(item, dict) and item.get("payload_sha256")
        }
        for seed_path in sorted(import_dir.glob("id:*src:protolens_monitor*")):
            if not seed_path.is_file():
                continue
            try:
                payload_sha256 = hashlib.sha256(seed_path.read_bytes()).hexdigest()
            except OSError:
                continue
            canonical_key = _canonical_key_from_seed_name(seed_path.name)
            if canonical_key:
                self._generated_keys.add(canonical_key)
            self._generated_payload_hashes.add(payload_sha256)
            self._event_counter = max(self._event_counter, _event_index_from_path(seed_path.name))
            if payload_sha256 in known_hashes:
                continue
            known_hashes.add(payload_sha256)
            self._manifest_seeds.append(
                {
                    "path": str(seed_path),
                    "payload_sha256": payload_sha256,
                    "canonical_key": canonical_key,
                    "source": "existing_monitor_import_queue",
                }
            )
        self._manifest_seeds = _dedupe_seed_records(self._manifest_seeds)


MONITOR_ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["bottleneck_summary", "seed_candidates"],
    "properties": {
        "bottleneck_summary": {"type": "string", "minLength": 1},
        "seed_candidates": {
            "type": "array",
            "maxItems": 16,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["conflict_id", "messages", "rationale", "expected_new_coverage"],
                "properties": {
                    "conflict_id": {"type": "string", "minLength": 1},
                    "candidate_id": {"type": "string"},
                    "frontier_queue_id": {"type": "string"},
                    "messages": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 32,
                        "items": {"type": "string", "minLength": 1},
                    },
                    "rationale": {"type": "string", "minLength": 1},
                    "expected_new_coverage": {"type": "string", "minLength": 1},
                },
            },
        },
    },
}


def _load_json_object(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise
        data = json.loads(match.group(0))
    if not isinstance(data, dict):
        raise ValueError("monitor LLM output must be a JSON object")
    return data


def _validate_monitor_analysis(data: dict[str, Any]) -> dict[str, Any]:
    summary = str(data.get("bottleneck_summary", "")).strip()
    if not summary:
        raise ValueError("monitor LLM output requires bottleneck_summary")
    raw_candidates = data.get("seed_candidates")
    if not isinstance(raw_candidates, list):
        raise ValueError("monitor LLM output requires seed_candidates array")
    candidates: list[dict[str, Any]] = []
    for item in raw_candidates[:16]:
        if not isinstance(item, dict):
            raise ValueError("monitor seed candidate must be an object")
        conflict_id = str(item.get("conflict_id", "")).strip()
        messages = [_candidate_message_text(value) for value in item.get("messages", [])]
        messages = [message for message in messages if message]
        rationale = str(item.get("rationale", "")).strip()
        expected = str(item.get("expected_new_coverage", "")).strip()
        if not conflict_id or not messages or not rationale or not expected:
            raise ValueError("monitor seed candidate requires conflict_id, messages, rationale, and expected_new_coverage")
        if any(_looks_like_transport_action(message) for message in messages):
            raise ValueError("monitor seed candidate contains a transport action that AFLNet seed cannot encode")
        candidates.append(
            {
                "conflict_id": conflict_id,
                "candidate_id": str(item.get("candidate_id", "")).strip(),
                "frontier_queue_id": str(item.get("frontier_queue_id", "")).strip(),
                "messages": messages[:32],
                "rationale": rationale,
                "expected_new_coverage": expected,
            }
        )
    return {"bottleneck_summary": summary, "seed_candidates": candidates}


def _compact_dynamic(dynamic: dict[str, Any]) -> dict[str, Any]:
    return {
        "stats_present": dynamic.get("stats_present", False),
        "fuzzer_stats": dynamic.get("fuzzer_stats", {}),
        "latest_plot": dynamic.get("latest_plot", {}),
        "ipsm": dynamic.get("ipsm", {}),
        "execution_fsm": _execution_fsm_summary(dynamic.get("execution_fsm", {})),
        "queue_count": dynamic.get("queue_count", 0),
        "queue_files": list(dynamic.get("queue_files", []))[:50],
        "crash_count": dynamic.get("crash_count", 0),
        "hang_count": dynamic.get("hang_count", 0),
        "health_signals": list(dynamic.get("health_signals", [])),
    }


def _execution_fsm_summary(execution_fsm: Any) -> dict[str, Any]:
    if not isinstance(execution_fsm, dict):
        return {"present": False}
    frontier = execution_fsm.get("frontier", {}) if isinstance(execution_fsm.get("frontier"), dict) else {}
    return {
        "present": bool(execution_fsm.get("states") or frontier.get("candidates")),
        "format": execution_fsm.get("format", ""),
        "source": execution_fsm.get("source", ""),
        "state_count": execution_fsm.get("state_count", 0),
        "edge_count": execution_fsm.get("edge_count", 0),
        "frontier_candidate_count": frontier.get("candidate_count", 0),
    }


def _execution_frontier_context(dynamic: dict[str, Any]) -> dict[str, Any]:
    execution_fsm = dynamic.get("execution_fsm", {}) if isinstance(dynamic, dict) else {}
    if not isinstance(execution_fsm, dict):
        return {"present": False, "candidates": [], "verified_prefixes": []}
    frontier = execution_fsm.get("frontier", {}) if isinstance(execution_fsm.get("frontier"), dict) else {}
    candidates = []
    for candidate in frontier.get("candidates", [])[:40]:
        if not isinstance(candidate, dict):
            continue
        candidates.append(
            {
                "queue_id": candidate.get("queue_id", ""),
                "queue_file": candidate.get("queue_file", ""),
                "has_new_coverage": candidate.get("has_new_coverage", False),
                "command_sequence": list(candidate.get("command_sequence", []))[:24],
                "messages": list(candidate.get("messages", []))[:12],
                "mutation_scope": candidate.get("mutation_scope", "small_local_mutation_on_verified_prefix"),
            }
        )
    return {
        "present": bool(candidates),
        "policy": frontier.get("policy", "mutate only verified queue prefixes"),
        "verified_prefixes": list(frontier.get("verified_prefixes", []))[:80],
        "candidates": candidates,
    }


def _planned_path_context(planned_paths: list[PlannedStatePath], protocol: str) -> list[dict[str, Any]]:
    context: list[dict[str, Any]] = []
    for path in planned_paths[:120]:
        client_messages = [message for message in (_client_seed_message(message, protocol) for message in path.messages) if message]
        filtered = [message for message in path.messages if not _client_message(message, protocol)]
        context.append(
            {
                "conflict_id": path.conflict_id,
                "candidate_id": path.candidate_id,
                "states": path.states,
                "messages": client_messages,
                "filtered_non_client_messages": filtered,
                "transition_ids": path.transition_ids,
                "required_guards": path.required_guards,
                "mutation_points": path.mutation_points,
                "reachable": path.reachable and bool(client_messages),
                "reason": path.reason,
                "calibration": path.calibration,
            }
        )
    return context


def _conflict_context(conflicts: list[Conflict]) -> list[dict[str, Any]]:
    return [
        {
            "id": conflict.id,
            "kind": conflict.kind,
            "priority": conflict.priority,
            "state": conflict.state,
            "transition": conflict.transition,
            "description": conflict.description,
            "expected_path": conflict.expected_path,
            "fuzzing_strategy": conflict.fuzzing_strategy,
            "risk_score": conflict.risk_score,
        }
        for conflict in conflicts[:120]
    ]


def _heuristic_seed_templates(planned_paths: list[PlannedStatePath], protocol: str) -> list[dict[str, Any]]:
    templates: list[dict[str, Any]] = []
    for path in planned_paths:
        if not path.reachable or not path.messages:
            continue
        for variant in _path_variants(path, protocol):
            templates.append(
                {
                    "conflict_id": path.conflict_id,
                    "candidate_id": path.candidate_id,
                    "messages": variant["messages"],
                    "reason": variant["reason"],
                    "required_guards": path.required_guards,
                    "mutation_points": path.mutation_points,
                }
            )
            if len(templates) >= 80:
                return templates
    return templates


def _looks_like_transport_action(message: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", message.lower()).strip("_")
    return any(
        token in normalized
        for token in (
            "tcp_reset",
            "rst",
            "half_close",
            "shutdown_wr",
            "tls_renegotiation",
            "renegotiate_tls",
            "close_socket",
        )
    )


def _signature_key(signature: tuple[Any, ...]) -> str:
    payload = json.dumps(list(signature), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sig_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def _candidate_key(conflict_id: str, messages: list[str]) -> str:
    normalized_messages = [_normalize_seed_message(message) for message in messages]
    payload = json.dumps(
        {"conflict_id": conflict_id.strip(), "messages": normalized_messages},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    label = "_".join(message.split()[0].upper() for message in normalized_messages if message.split())
    return stable_id(f"seed_{digest}", conflict_id, label)


def _select_candidate_path(
    candidate_id: str,
    conflict_id: str,
    path_by_candidate: dict[str, PlannedStatePath],
    paths_by_conflict: dict[str, list[PlannedStatePath]],
) -> PlannedStatePath | None:
    if candidate_id:
        path = path_by_candidate.get(candidate_id)
        return path if path is not None and path.reachable else None
    reachable = [path for path in paths_by_conflict.get(conflict_id, []) if path.reachable]
    if len(reachable) == 1:
        return reachable[0]
    return None


def _normalize_seed_message(message: str) -> str:
    if _is_raw_seed_message(message):
        return str(message)
    normalized = " ".join(str(message).strip().split())
    if not normalized:
        return ""
    parts = normalized.split(" ", 1)
    command = parts[0].upper()
    return command if len(parts) == 1 else f"{command} {parts[1]}"


def _candidate_message_text(value: Any) -> str:
    text = str(value)
    return text if _is_raw_seed_message(text) else text.strip()


def _is_raw_seed_message(message: str) -> bool:
    lowered = str(message).lower()
    return lowered.startswith("raw:") or lowered.startswith("raw-b64:") or lowered.startswith("base64:")


def _previous_seed_context(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    seeds = manifest.get("seeds", []) if isinstance(manifest, dict) else []
    context: list[dict[str, Any]] = []
    for seed in seeds[-40:]:
        if not isinstance(seed, dict):
            continue
        context.append(
            {
                "conflict_id": seed.get("conflict_id", ""),
                "source_candidate_id": seed.get("source_candidate_id", ""),
                "canonical_key": seed.get("canonical_key", ""),
                "payload_sha256": seed.get("payload_sha256", ""),
                "messages": list(seed.get("messages", []))[:16] if isinstance(seed.get("messages"), list) else [],
                "expected_new_coverage": seed.get("expected_new_coverage", ""),
                "execution_receipt": _compact_receipt(seed.get("execution_receipt")),
            }
        )
    return context


def _monitor_seed_feedback_context(manifest: dict[str, Any]) -> dict[str, Any]:
    seeds = [seed for seed in manifest.get("seeds", []) if isinstance(seed, dict)] if isinstance(manifest, dict) else []
    processed = [seed for seed in seeds if isinstance(seed.get("execution_receipt"), dict) and seed["execution_receipt"].get("processed")]
    saved = [seed for seed in seeds if isinstance(seed.get("execution_receipt"), dict) and seed["execution_receipt"].get("saved_interesting")]
    pending = [seed for seed in seeds if seed not in processed]
    failed = [
        seed
        for seed in processed
        if isinstance(seed.get("execution_receipt"), dict) and not seed["execution_receipt"].get("saved_interesting")
    ]
    return {
        "present": bool(seeds),
        "seed_count": len(seeds),
        "processed_count": len(processed),
        "saved_interesting_count": len(saved),
        "pending_count": len(pending),
        "recent_saved": [_monitor_seed_sample(seed) for seed in saved[-12:]],
        "recent_processed_without_new_coverage": [_monitor_seed_sample(seed) for seed in failed[-12:]],
        "recent_pending": [_monitor_seed_sample(seed) for seed in pending[-12:]],
    }


def _frontier_feedback_context(manifest: dict[str, Any], failure_threshold: int) -> dict[str, Any]:
    seeds = [seed for seed in manifest.get("seeds", []) if isinstance(seed, dict)] if isinstance(manifest, dict) else []
    buckets: dict[str, dict[str, Any]] = {}
    for seed in seeds:
        key = str(seed.get("frontier_key", "") or "").strip()
        if not key:
            messages = list(seed.get("messages", [])) if isinstance(seed.get("messages"), list) else []
            key = _frontier_key_from_messages(messages)
        if not key:
            continue
        bucket = buckets.setdefault(
            key,
            {
                "frontier_key": key,
                "seed_count": 0,
                "processed_count": 0,
                "saved_interesting_count": 0,
                "failed_without_new_coverage": 0,
                "pending_count": 0,
                "suppressed": False,
                "failure_threshold": failure_threshold,
                "recent_messages": [],
            },
        )
        bucket["seed_count"] += 1
        receipt = seed.get("execution_receipt") if isinstance(seed.get("execution_receipt"), dict) else {}
        if receipt.get("processed"):
            bucket["processed_count"] += 1
            if receipt.get("saved_interesting"):
                bucket["saved_interesting_count"] += 1
            else:
                bucket["failed_without_new_coverage"] += 1
        else:
            bucket["pending_count"] += 1
        messages = list(seed.get("messages", []))[:12] if isinstance(seed.get("messages"), list) else []
        if messages:
            bucket["recent_messages"] = messages
    for bucket in buckets.values():
        bucket["suppressed"] = (
            bucket["saved_interesting_count"] == 0
            and bucket["failed_without_new_coverage"] >= failure_threshold
        )
    ordered = sorted(
        buckets.values(),
        key=lambda item: (
            not bool(item["suppressed"]),
            -int(item["failed_without_new_coverage"]),
            str(item["frontier_key"]),
        ),
    )
    return {
        "present": bool(ordered),
        "failure_threshold": failure_threshold,
        "bucket_count": len(ordered),
        "suppressed_count": sum(1 for item in ordered if item["suppressed"]),
        "buckets": ordered[:40],
        "policy": "do not generate more seeds for a frontier bucket after repeated processed_no_new_coverage receipts",
    }


def _monitor_seed_sample(seed: dict[str, Any]) -> dict[str, Any]:
    return {
        "conflict_id": seed.get("conflict_id", ""),
        "source_candidate_id": seed.get("source_candidate_id", ""),
        "frontier_key": seed.get("frontier_key", ""),
        "canonical_key": seed.get("canonical_key", ""),
        "messages": list(seed.get("messages", []))[:12] if isinstance(seed.get("messages"), list) else [],
        "expected_new_coverage": seed.get("expected_new_coverage", ""),
        "execution_receipt": _compact_receipt(seed.get("execution_receipt")),
    }


def _compact_receipt(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        return {"processed": False, "outcome": "pending_import"}
    keys = (
        "processed",
        "executed",
        "saved_interesting",
        "outcome",
        "fault",
        "queued_before",
        "queued_after",
        "region_count",
        "messages_sent",
        "queue_files",
    )
    return {key: receipt[key] for key in keys if key in receipt}


def _frontier_bucket_status(seeds: list[dict[str, Any]], frontier_key: str, failure_threshold: int) -> dict[str, Any]:
    if not frontier_key:
        return {"frontier_key": "", "suppressed": False, "failure_threshold": failure_threshold}
    manifest = {"seeds": seeds}
    for bucket in _frontier_feedback_context(manifest, failure_threshold).get("buckets", []):
        if bucket.get("frontier_key") == frontier_key:
            return bucket
    return {
        "frontier_key": frontier_key,
        "seed_count": 0,
        "processed_count": 0,
        "saved_interesting_count": 0,
        "failed_without_new_coverage": 0,
        "pending_count": 0,
        "suppressed": False,
        "failure_threshold": failure_threshold,
    }


def _candidate_frontier_key(candidate: dict[str, Any], messages: list[str], frontier_match: dict[str, Any] | None) -> str:
    queue_id = str(candidate.get("frontier_queue_id", "") or "").strip()
    if queue_id:
        return "queue:" + queue_id
    if isinstance(frontier_match, dict):
        commands = [str(item).upper() for item in frontier_match.get("frontier_commands", []) if str(item)]
        if commands:
            return "cmd:" + "/".join(commands[:6])
    return _frontier_key_from_messages(messages)


def _frontier_key_from_messages(messages: list[str]) -> str:
    commands = [_message_method(message) for message in messages]
    commands = [command for command in commands if command]
    if not commands:
        return ""
    return "cmd:" + "/".join(commands[:6])


def _seed_feedback_context(seed_feedback: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(seed_feedback, dict):
        return {"present": False}
    items = [item for item in seed_feedback.get("items", []) if isinstance(item, dict)]
    unobserved = [
        {
            "seed_id": item.get("seed_id", ""),
            "conflict_id": item.get("conflict_id", ""),
            "variant": item.get("variant", ""),
            "objective": item.get("objective", ""),
        }
        for item in items
        if item.get("status") == "unobserved"
    ][:40]
    observed = [
        {
            "seed_id": item.get("seed_id", ""),
            "conflict_id": item.get("conflict_id", ""),
            "variant": item.get("variant", ""),
            "status": item.get("status", ""),
        }
        for item in items
        if item.get("status") != "unobserved"
    ][:40]
    return {
        "present": bool(seed_feedback.get("seed_manifest_present")),
        "seed_count": seed_feedback.get("seed_count", 0),
        "observed_count": seed_feedback.get("observed_count", 0),
        "by_variant": seed_feedback.get("by_variant", [])[:20],
        "by_conflict": seed_feedback.get("by_conflict", [])[:20],
        "observed_seed_samples": observed,
        "unobserved_seed_samples": unobserved,
    }


def _canonical_key_from_seed_name(name: str) -> str:
    marker = "src:protolens_monitor,"
    if marker not in name:
        return ""
    return name.split(marker, 1)[1].strip()


def _event_index_from_path(path: Any) -> int:
    match = re.search(r"id:(\d+)", str(path))
    return int(match.group(1)) if match else 0


def _read_processed_receipt(marker: Path) -> dict[str, Any]:
    try:
        text = marker.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return {"processed": True}
    if not text:
        return {"processed": True}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"processed": True, "raw_marker": text[:200]}
    if not isinstance(data, dict):
        return {"processed": True}
    data["processed"] = True
    return data


def _monitor_queue_matches(seed: dict[str, Any], queue_files: list[str]) -> list[str]:
    if not queue_files:
        return []
    seed_path = Path(str(seed.get("path", ""))).name
    event_index = _event_index_from_path(seed_path)
    tokens = {
        str(seed.get("payload_sha256", ""))[:16],
        str(seed.get("canonical_key", ""))[:32],
    }
    if event_index:
        tokens.add(f"sync:protolens_monitor,src:{event_index:06d}")
    if seed_path:
        tokens.add(seed_path)
    tokens = {token for token in tokens if token}
    return [name for name in queue_files if any(token in name for token in tokens)]


def _receipt_outcome(receipt: dict[str, Any]) -> str:
    if receipt.get("saved_interesting"):
        return "saved_interesting"
    if not receipt.get("processed"):
        return "pending_import"
    if not receipt.get("executed", True):
        return "processed_not_executed"
    fault = receipt.get("fault")
    if fault not in (None, 0, "0"):
        return f"executed_fault_{fault}_no_new_coverage"
    return "executed_no_new_coverage"


def _dedupe_seed_records(seeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    seen_keys: set[str] = set()
    for seed in seeds:
        if not isinstance(seed, dict):
            continue
        payload_sha256 = str(seed.get("payload_sha256", "")).strip()
        canonical_key = str(seed.get("canonical_key", "")).strip()
        if payload_sha256 and payload_sha256 in seen_hashes:
            continue
        if not payload_sha256 and canonical_key and canonical_key in seen_keys:
            continue
        if payload_sha256:
            seen_hashes.add(payload_sha256)
        if canonical_key:
            seen_keys.add(canonical_key)
        result.append(seed)
    return result


def _coverage_snapshot(dynamic: dict[str, Any]) -> dict[str, Any]:
    stats = dynamic.get("fuzzer_stats", {}) if isinstance(dynamic.get("fuzzer_stats"), dict) else {}
    latest = dynamic.get("latest_plot", {}) if isinstance(dynamic.get("latest_plot"), dict) else {}
    ipsm = dynamic.get("ipsm", {}) if isinstance(dynamic.get("ipsm"), dict) else {}
    return {
        "stats_present": bool(dynamic.get("stats_present") or stats),
        "execs_done": _as_int(stats.get("execs_done") or latest.get("total_execs") or 0),
        "execs_per_sec": str(stats.get("execs_per_sec") or latest.get("execs_per_sec") or ""),
        "paths_total": _as_int(stats.get("paths_total") or latest.get("paths_total") or dynamic.get("queue_count") or 0),
        "last_path": _as_int(stats.get("last_path") or 0),
        "bitmap_cvg": str(stats.get("bitmap_cvg") or latest.get("bitmap_cvg") or ""),
        "ipsm_nodes": _as_int(ipsm.get("nodes") or latest.get("ipsm_nodes") or 0),
        "ipsm_edges": _as_int(ipsm.get("edges") or latest.get("ipsm_edges") or 0),
        "queue_count": _as_int(dynamic.get("queue_count") or 0),
        "crash_count": _as_int(dynamic.get("crash_count") or 0),
        "hang_count": _as_int(dynamic.get("hang_count") or 0),
        "health_signals": list(dynamic.get("health_signals", [])),
    }


def _coverage_signature(snapshot: dict[str, Any]) -> tuple[Any, ...]:
    return (
        snapshot["paths_total"],
        snapshot["last_path"],
        snapshot["bitmap_cvg"],
        snapshot["ipsm_nodes"],
        snapshot["ipsm_edges"],
        snapshot["queue_count"],
        snapshot["crash_count"],
        snapshot["hang_count"],
    )


def _path_priority(path: PlannedStatePath, conflict: Conflict | None, dynamic: dict[str, Any]) -> int:
    priority = {"P0": 400, "P1": 250, "P2": 100}.get(conflict.priority if conflict else "P2", 100)
    score = priority + 50 * len(path.required_guards) + 35 * len(set(path.mutation_points))
    queue_names = " ".join(str(item) for item in dynamic.get("queue_files", []))
    if path.conflict_id[:24] not in queue_names:
        score += 80
    return score


def _path_variants(path: PlannedStatePath, protocol: str) -> list[dict[str, Any]]:
    messages = [message for message in (_client_seed_message(message, protocol) for message in path.messages) if message]
    if not messages:
        return []
    guards = " ".join(path.required_guards).lower()
    variants: list[dict[str, Any]] = []
    prefix = _guard_prefix(protocol, guards)
    if prefix:
        variants.append(
            {
                "messages": _dedupe_sequence(prefix + messages),
                "reason": "prepend protocol prerequisites derived from required_guards",
            }
        )
    for command in _guard_commands(protocol, guards):
        index = path.mutation_points[-1] if path.mutation_points else len(messages) - 1
        index = max(0, min(index, len(messages) - 1))
        mutated = list(messages)
        mutated[index] = command
        variants.append(
            {
                "messages": _dedupe_sequence((prefix or []) + mutated),
                "reason": f"replace guarded mutation point with {command!r}",
            }
        )
        variants.append(
            {
                "messages": _dedupe_sequence((prefix or []) + messages[: index + 1] + [command] + messages[index + 1 :]),
                "reason": f"insert guard-derived command {command!r} at mutation point",
            }
        )
    if not variants and path.required_guards:
        variants.append({"messages": messages, "reason": "retry reachable guarded path without structural mutation"})
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for variant in variants:
        key = tuple(variant["messages"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(variant)
    return unique


def _guard_prefix(protocol: str, guards: str) -> list[str]:
    if protocol.lower() == "ftp":
        prefix: list[str] = []
        if any(token in guards for token in ("auth", "login", "authenticated", "user", "password")):
            prefix.extend(["USER", "PASS"])
        if any(token in guards for token in ("tls", "ssl", "secure", "encrypted", "pbsz", "prot")):
            prefix.extend(["AUTH", "PBSZ", "PROT"])
        if any(token in guards for token in ("data", "passive", "active", "transfer", "retr", "stor", "list")):
            prefix.extend(["TYPE", "PORT"])
        return prefix
    if protocol.lower() == "rtsp":
        prefix = ["OPTIONS"]
        if any(token in guards for token in ("session", "setup", "transport")):
            prefix.append("SETUP")
        return prefix
    if protocol.lower() == "smtp":
        prefix = ["EHLO"]
        if any(token in guards for token in ("mail", "sender", "recipient", "data")):
            prefix.extend(["MAIL", "RCPT"])
        return prefix
    return []


def _guard_commands(protocol: str, guards: str) -> list[str]:
    protocol_commands = {
        "ftp": ["USER", "PASS", "AUTH", "PBSZ", "PROT", "TYPE", "PORT", "PASV", "LIST", "RETR", "STOR", "CWD"],
        "rtsp": ["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN", "GET_PARAMETER"],
        "smtp": ["EHLO", "MAIL", "RCPT", "DATA", "RSET", "QUIT"],
        "http": ["GET", "HEAD", "POST", "OPTIONS"],
    }
    commands = protocol_commands.get(protocol.lower(), [])
    selected = [command for command in commands if command.lower() in guards]
    for token in re.findall(r"\b[A-Z][A-Z0-9_-]{1,15}\b", guards.upper()):
        if token not in selected:
            selected.append(token)
    return selected[:8]


def _client_message(message: str, protocol: str) -> bool:
    return _client_seed_message(message, protocol) is not None


def _client_seed_message(message: str, protocol: str) -> str | None:
    return client_seed_message(message, protocol)


def _frontier_match(messages: list[str], dynamic: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(dynamic, dict):
        return None
    execution_fsm = dynamic.get("execution_fsm", {})
    if not isinstance(execution_fsm, dict):
        return None
    frontier = execution_fsm.get("frontier", {})
    if not isinstance(frontier, dict):
        return None
    frontier_sequences = _frontier_command_sequences(frontier)
    if not frontier_sequences:
        return None
    candidate_commands = [_message_method(message) for message in messages]
    candidate_commands = [command for command in candidate_commands if command]
    if not candidate_commands:
        return {
            "matched": False,
            "candidate_commands": [],
            "frontier_examples": frontier_sequences[:5],
        }
    for sequence in frontier_sequences:
        required = min(2, len(sequence), len(candidate_commands))
        if required <= 0:
            continue
        if candidate_commands[:required] == sequence[:required]:
            return {
                "matched": True,
                "candidate_commands": candidate_commands,
                "frontier_commands": sequence,
                "matched_prefix_length": required,
            }
    return {
        "matched": False,
        "candidate_commands": candidate_commands,
        "frontier_examples": frontier_sequences[:5],
    }


def _frontier_command_sequences(frontier: dict[str, Any]) -> list[list[str]]:
    sequences: list[list[str]] = []
    for candidate in frontier.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        commands = [str(item).upper() for item in candidate.get("command_sequence", []) if str(item)]
        if commands:
            sequences.append(commands)
    for prefix in frontier.get("verified_prefixes", []):
        if not isinstance(prefix, dict):
            continue
        commands = [str(item).upper() for item in prefix.get("commands", []) if str(item)]
        if commands:
            sequences.append(commands)
    unique: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for sequence in sequences:
        key = tuple(sequence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(sequence)
    return unique


def _message_method(message: str) -> str:
    text = str(message).strip()
    if not text:
        return ""
    if text.lower().startswith(("raw:", "raw-b64:", "base64:")):
        return "RAW"
    return text.split()[0].upper().rstrip(":") if text.split() else ""


def _dedupe_sequence(messages: list[str]) -> list[str]:
    result: list[str] = []
    for message in messages:
        if result and result[-1].split()[0].upper() == message.split()[0].upper():
            continue
        result.append(message)
    return result


def _bottleneck(dynamic: dict[str, Any], planned_paths: list[PlannedStatePath]) -> dict[str, Any]:
    guarded = [path for path in planned_paths if path.reachable and path.required_guards]
    queue_files = " ".join(str(item) for item in dynamic.get("queue_files", []))
    unobserved = [
        path.conflict_id
        for path in guarded
        if path.conflict_id[:24] not in queue_files
    ]
    return {
        "guarded_reachable_paths": len(guarded),
        "unobserved_guarded_conflicts": unobserved[:50],
        "health_signals": list(dynamic.get("health_signals", [])),
    }


def _as_int(value: Any) -> int:
    try:
        return int(float(str(value).strip().strip("%")))
    except (TypeError, ValueError):
        return 0


def _as_float(value: Any) -> float:
    try:
        return float(str(value).strip().strip("%"))
    except (TypeError, ValueError):
        return 0.0
