from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import os
import re
import shutil
import signal
import subprocess
import time
from typing import Any

from protolens.config import ProtoLensConfig
from protolens.fsm.fsm_model import Conflict, FuzzResult, PlannedStatePath

PLOT_FIELDS = [
    "unix_time",
    "cycles_done",
    "cur_path",
    "paths_total",
    "paths_not_fuzzed",
    "favored_not_fuzzed",
    "bitmap_cvg",
    "unique_crashes",
    "unique_hangs",
    "max_depth",
    "execs_per_sec",
    "ipsm_nodes",
    "ipsm_edges",
]


class AFLNetDynamicAnalyzer:
    """Read real AFLNet campaign outputs without inventing missing coverage data."""

    def analyze(self, fuzz_result: FuzzResult) -> dict[str, Any]:
        output_dir = Path(fuzz_result.output_dir)
        stats = _read_fuzzer_stats(output_dir / "fuzzer_stats")
        plot_rows = _read_plot_data(output_dir / "plot_data")
        last_plot = plot_rows[-1] if plot_rows else {}
        queue = _list_files(output_dir / "queue")
        crashes = _list_files(output_dir / "replayable-crashes") or _list_files(output_dir / "crashes")
        hangs = _list_files(output_dir / "replayable-hangs") or _list_files(output_dir / "hangs")
        ipsm = _read_ipsm(output_dir / "ipsm.dot")
        health = _health_signals(fuzz_result, stats, last_plot, queue, crashes, hangs, ipsm)
        return {
            "format": "protolens.aflnet_dynamic_analysis.v1",
            "mode": fuzz_result.mode,
            "output_dir": str(output_dir),
            "stats_present": bool(stats),
            "plot_data_present": bool(plot_rows),
            "fuzzer_stats": stats,
            "latest_plot": last_plot,
            "ipsm": ipsm,
            "queue_files": queue[:200],
            "queue_count": len(queue),
            "crash_files": crashes[:200],
            "crash_count": len(crashes),
            "hang_files": hangs[:200],
            "hang_count": len(hangs),
            "health_signals": health,
        }


class AFLNetStateMapper:
    """Map planned FSM paths to AFLNet-observed IPSM labels and queue files when evidence exists."""

    def map(self, dynamic: dict[str, Any], planned_paths: list[PlannedStatePath]) -> dict[str, Any]:
        ipsm = dynamic.get("ipsm", {})
        labels = [str(item) for item in ipsm.get("node_labels", [])]
        label_index = {_normalize_label(label): label for label in labels}
        queue_files = [str(item) for item in dynamic.get("queue_files", [])]
        items: list[dict[str, Any]] = []
        for index, path in enumerate(planned_paths):
            matched_states = []
            for state in path.states:
                normalized = _normalize_label(state)
                if normalized in label_index:
                    matched_states.append({"fsm_state": state, "ipsm_label": label_index[normalized]})
            seed_prefix = f"id_{index:06d}_"
            queue_matches = [name for name in queue_files if seed_prefix in name or path.conflict_id[:24] in name]
            items.append(
                {
                    "conflict_id": path.conflict_id,
                    "candidate_id": path.candidate_id,
                    "path_calibration": path.calibration,
                    "reachable": path.reachable,
                    "status": "observed" if matched_states or queue_matches else "unobserved",
                    "matched_states": matched_states,
                    "queue_files": queue_matches[:20],
                }
            )
        return {
            "format": "protolens.aflnet_state_mapping.v1",
            "based_on_ipsm": bool(labels),
            "items": items,
        }


class SeedFeedbackAnalyzer:
    """Attribute AFLNet output artifacts back to ProtoLens seed intents."""

    def analyze(self, dynamic: dict[str, Any], seed_manifest: dict[str, Any] | None) -> dict[str, Any]:
        entries = seed_manifest.get("entries", []) if isinstance(seed_manifest, dict) else []
        queue_files = _artifact_names(dynamic, "queue_files", ("queue",))
        crash_files = _artifact_names(dynamic, "crash_files", ("replayable-crashes", "crashes"))
        hang_files = _artifact_names(dynamic, "hang_files", ("replayable-hangs", "hangs"))
        lineage = _build_queue_lineage(queue_files, entries)
        crash_by_seed = _artifact_matches_by_seed(crash_files, lineage)
        hang_by_seed = _artifact_matches_by_seed(hang_files, lineage)
        global_state_observation = _global_state_observation(dynamic)
        items: list[dict[str, Any]] = []
        for seed in entries:
            if not isinstance(seed, dict):
                continue
            seed_file = str(seed.get("seed_file", ""))
            seed_id = str(seed.get("seed_id", ""))
            conflict_id = str(seed.get("conflict_id", ""))
            queue_matches = lineage["queue_files_by_seed"].get(seed_id, [])
            direct_queue_ids = lineage["direct_queue_ids_by_seed"].get(seed_id, [])
            queue_ids = lineage["queue_ids_by_seed"].get(seed_id, [])
            derived_queue_ids = [queue_id for queue_id in queue_ids if queue_id not in set(direct_queue_ids)]
            crash_matches = crash_by_seed.get(seed_id, [])
            hang_matches = hang_by_seed.get(seed_id, [])
            global_state_overlap = _matched_states(dynamic, seed)
            matched_states = global_state_overlap if queue_matches or crash_matches or hang_matches else []
            status = _seed_status(queue_matches, crash_matches, hang_matches)
            items.append(
                {
                    "seed_id": seed_id,
                    "source_candidate_id": seed.get("source_candidate_id", ""),
                    "seed_file": seed_file,
                    "conflict_id": conflict_id,
                    "family_id": seed.get("family_id", ""),
                    "variant": seed.get("variant", ""),
                    "objective": seed.get("objective", ""),
                    "payload_sha256": seed.get("payload_sha256", ""),
                    "queued_by_aflnet": bool(queue_matches),
                    "queue_ids": queue_ids,
                    "direct_queue_ids": direct_queue_ids,
                    "derived_queue_ids": derived_queue_ids,
                    "queue_matches": queue_matches[:20],
                    "crash_matches": crash_matches[:20],
                    "hang_matches": hang_matches[:20],
                    "matched_states": matched_states,
                    "global_state_overlap": global_state_overlap,
                    "status": status,
                    "coverage_attribution": (
                        "attributed only through exact AFL/AFLNet orig:<seed_file> queue IDs and src:<queue_id> "
                        "descendant lineage; global IPSM labels are recorded separately and never mark a seed observed"
                    ),
                    "attribution_basis": "exact_orig_or_queue_src_lineage",
                    "priority": seed.get("priority", 100),
                    "mutation_points": seed.get("mutation_points", []),
                    "byte_ranges": seed.get("byte_ranges", []),
                    "expected_feedback": seed.get("expected_feedback", []),
                    "coalesced_intents": list(seed.get("coalesced_intents", [])),
                }
            )
        return {
            "format": "protolens.seed_feedback.v2",
            "seed_manifest_present": isinstance(seed_manifest, dict) and bool(entries),
            "dynamic_basis_present": bool(dynamic.get("stats_present") or dynamic.get("plot_data_present")),
            "seed_count": len(items),
            "observed_count": sum(1 for item in items if item["status"] != "unobserved"),
            "queue_lineage": lineage["report"],
            "global_state_observation": global_state_observation,
            "by_variant": _group_feedback(items, "variant"),
            "by_conflict": _group_feedback(items, "conflict_id"),
            "items": items,
        }


class ClosedLoopReplanner:
    """Produce a next-round plan from dynamic coverage and response-state observations."""

    def plan(
        self,
        dynamic: dict[str, Any],
        planned_paths: list[PlannedStatePath],
        conflicts: list[Conflict],
        seed_feedback: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        actions: list[dict[str, Any]] = []
        if dynamic.get("crash_count", 0):
            actions.append(
                {
                    "priority": "P0",
                    "action": "replay_crashes",
                    "reason": "AFLNet reported replayable crash files; confirm before filing vulnerabilities.",
                    "inputs": dynamic.get("crash_files", []),
                }
            )
        if "no_stats" in dynamic.get("health_signals", []):
            actions.append(
                {
                    "priority": "P1",
                    "action": "fix_campaign_startup",
                    "reason": "No AFLNet fuzzer_stats was observed; inspect the configured aflnet.cmd and target startup.",
                }
            )
        ipsm = dynamic.get("ipsm", {})
        if not ipsm.get("edges"):
            actions.append(
                {
                    "priority": "P1",
                    "action": "expand_state_reaching_prefixes",
                    "reason": "No AFLNet IPSM edges were observed; prioritize seeds with shorter guards and earlier mutation points.",
                }
            )
        latest = dynamic.get("latest_plot", {})
        if _as_float(latest.get("execs_per_sec")) == 0 and dynamic.get("mode") not in {"dry-run", "error"}:
            actions.append(
                {
                    "priority": "P2",
                    "action": "reduce_timeout_or_target_latency",
                    "reason": "The latest plot_data row reports zero executions per second.",
                }
            )
        path_priorities = []
        for path in planned_paths:
            if not path.reachable:
                continue
            score = 100 + 35 * len(set(path.mutation_points)) + 20 * len(path.required_guards)
            if any(conflict.id == path.conflict_id and conflict.priority == "P0" for conflict in conflicts):
                score += 60
            path_priorities.append(
                {
                    "conflict_id": path.conflict_id,
                    "score": min(500, score),
                    "mutation_points": sorted(set(path.mutation_points)),
                    "messages": path.messages,
                    "states": path.states,
                }
            )
        path_priorities.sort(key=lambda item: item["score"], reverse=True)
        seed_actions, seed_priorities = _seed_replanning(seed_feedback)
        return {
            "format": "protolens.closed_loop_replanning.v1",
            "based_on_dynamic_output": bool(dynamic.get("stats_present") or dynamic.get("plot_data_present")),
            "actions": actions,
            "next_round_path_priorities": path_priorities[:100],
            "seed_feedback_present": bool(seed_feedback and seed_feedback.get("seed_manifest_present")),
            "seed_actions": seed_actions,
            "next_round_seed_priorities": seed_priorities[:100],
        }


class CrashReplayVerifier:
    """Replay real AFLNet crash artifacts and only confirm observable target termination."""

    def verify(self, config: ProtoLensConfig, fuzz_result: FuzzResult, max_crashes: int = 3) -> dict[str, Any]:
        crash_files = _crash_paths(Path(fuzz_result.output_dir))
        if not crash_files:
            return {
                "format": "protolens.crash_replay.v1",
                "items": [],
                "notes": ["no crash files were present"],
            }
        replay_binary = _resolve_replay_binary(config)
        target_command = _target_command(config.aflnet.cmd)
        if not replay_binary:
            return {
                "format": "protolens.crash_replay.v1",
                "items": [],
                "notes": ["aflnet-replay binary was not found; no crash was confirmed"],
                "crash_files": [str(path) for path in crash_files],
            }
        if not target_command:
            return {
                "format": "protolens.crash_replay.v1",
                "items": [],
                "notes": ["aflnet.cmd does not contain a target command after '--'; no crash was confirmed"],
                "crash_files": [str(path) for path in crash_files],
            }
        items = []
        for crash_path in crash_files[:max_crashes]:
            result = self._replay_one(config, replay_binary, target_command, crash_path)
            if result["confirmed"]:
                result["minimization"] = self._minimize(config, replay_binary, target_command, crash_path)
            else:
                result["minimization"] = {
                    "attempted": False,
                    "minimized": False,
                    "reason": "crash was not confirmed under replay",
                }
            items.append(result)
        return {
            "format": "protolens.crash_replay.v1",
            "items": items,
            "notes": ["confirmed=true requires observable non-zero target termination during replay"],
        }

    def _replay_one(
        self,
        config: ProtoLensConfig,
        replay_binary: str,
        target_command: list[str],
        crash_path: Path,
    ) -> dict[str, Any]:
        return _run_replay(config, replay_binary, target_command, crash_path)

    def _minimize(
        self,
        config: ProtoLensConfig,
        replay_binary: str,
        target_command: list[str],
        crash_path: Path,
    ) -> dict[str, Any]:
        payload = crash_path.read_bytes()
        chunks = _split_seed_messages(payload, config.protocol)
        if len(chunks) <= 1 or len(chunks) > 24:
            return {
                "attempted": False,
                "minimized": False,
                "reason": "seed message count is not suitable for bounded deletion minimization",
                "original_size": len(payload),
            }
        kept = list(chunks)
        with TemporaryDirectory(prefix="protolens-min-") as tmp:
            tmp_path = Path(tmp) / crash_path.name
            changed = True
            while changed and len(kept) > 1:
                changed = False
                for index in range(len(kept)):
                    candidate = kept[:index] + kept[index + 1 :]
                    tmp_path.write_bytes(b"".join(candidate))
                    replay = _run_replay(config, replay_binary, target_command, tmp_path)
                    if replay["confirmed"]:
                        kept = candidate
                        changed = True
                        break
            minimized_payload = b"".join(kept)
            minimized = len(minimized_payload) < len(payload)
            out_path = crash_path.with_suffix(crash_path.suffix + ".protolens-min")
            if minimized:
                out_path.write_bytes(minimized_payload)
            return {
                "attempted": True,
                "minimized": minimized,
                "original_size": len(payload),
                "minimized_size": len(minimized_payload),
                "output": str(out_path) if minimized else "",
            }


def _run_replay(
    config: ProtoLensConfig,
    replay_binary: str,
    target_command: list[str],
    seed_path: Path,
) -> dict[str, Any]:
    target = None
    try:
        target = subprocess.Popen(
            target_command,
            cwd=str(config.source_root),
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(min(5.0, max(0.05, config.aflnet.timeout_ms / 1000.0)))
        replay_command = [
            replay_binary,
            str(seed_path),
            config.protocol.upper(),
            str(config.port),
            str(max(1000, config.aflnet.timeout_ms * 1000)),
            str(max(1, config.aflnet.timeout_ms)),
        ]
        replay = subprocess.run(
            replay_command,
            cwd=str(config.source_root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(5, config.aflnet.timeout_ms // 1000 + 5),
            check=False,
        )
        time.sleep(0.2)
        target_returncode = target.poll()
        confirmed = target_returncode is not None and target_returncode != 0
        return {
            "crash_file": str(seed_path),
            "replay_command": replay_command,
            "replay_exit_code": replay.returncode,
            "target_exit_code": target_returncode,
            "confirmed": confirmed,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "crash_file": str(seed_path),
            "confirmed": False,
            "error": str(exc),
        }
    finally:
        if target and target.poll() is None:
            try:
                os.killpg(target.pid, signal.SIGTERM)
                target.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(target.pid, signal.SIGKILL)
                except OSError:
                    pass


def _read_fuzzer_stats(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    stats: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stats[key.strip()] = value.strip()
    return stats


def _read_plot_data(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    rows: list[dict[str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        values = [item.strip() for item in line.split(",")]
        rows.append({field: values[index] for index, field in enumerate(PLOT_FIELDS) if index < len(values)})
    return rows


def _read_ipsm(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"present": False, "nodes": 0, "edges": 0}
    text = path.read_text(encoding="utf-8", errors="replace")
    edge_pairs = [
        (match.group("source"), match.group("target"))
        for match in re.finditer(r"\b(?P<source>[A-Za-z0-9_.:-]+)\s*->\s*(?P<target>[A-Za-z0-9_.:-]+)", text)
    ]
    labels = {
        _strip_dot_quotes(match.group("label"))
        for match in re.finditer(r"\blabel\s*=\s*(?P<label>\"[^\"]+\"|[A-Za-z0-9_.:-]+)", text)
    }
    for source, target in edge_pairs:
        labels.add(source)
        labels.add(target)
    nodes = len(labels)
    edges = len(edge_pairs)
    return {
        "present": True,
        "nodes": nodes,
        "edges": edges,
        "node_labels": sorted(labels),
        "edge_pairs": [[source, target] for source, target in edge_pairs[:500]],
    }


def _health_signals(
    fuzz_result: FuzzResult,
    stats: dict[str, str],
    latest: dict[str, str],
    queue: list[str],
    crashes: list[str],
    hangs: list[str],
    ipsm: dict[str, Any],
) -> list[str]:
    signals: list[str] = []
    if not stats:
        signals.append("no_stats")
    if fuzz_result.mode == "error":
        signals.append("campaign_error")
    if not queue and fuzz_result.mode not in {"dry-run", "error"}:
        signals.append("no_queue")
    if crashes:
        signals.append("crashes_present")
    if hangs:
        signals.append("hangs_present")
    if _as_float(latest.get("execs_per_sec")) == 0 and latest:
        signals.append("zero_execs_per_sec")
    if not ipsm.get("edges"):
        signals.append("no_ipsm_edges")
    return signals


def _list_files(path: Path) -> list[str]:
    if not path.exists():
        return []
    return sorted(
        item.name
        for item in path.iterdir()
        if item.is_file() and not item.name.startswith((".", "README"))
    )


def _artifact_names(dynamic: dict[str, Any], key: str, directories: tuple[str, ...]) -> list[str]:
    output_dir_value = str(dynamic.get("output_dir", "")).strip()
    if output_dir_value:
        output_dir = Path(output_dir_value).expanduser()
        for directory in directories:
            names = _list_files(output_dir / directory)
            if names:
                return names
    return [str(item) for item in dynamic.get(key, [])]


def _build_queue_lineage(queue_files: list[str], entries: list[Any]) -> dict[str, Any]:
    seed_by_file = {
        str(seed.get("seed_file", "")): str(seed.get("seed_id", ""))
        for seed in entries
        if isinstance(seed, dict) and seed.get("seed_file") and seed.get("seed_id")
    }
    nodes: dict[str, dict[str, Any]] = {}
    queue_files_by_seed: dict[str, list[str]] = {}
    direct_queue_ids_by_seed: dict[str, list[str]] = {}
    queue_ids_by_seed: dict[str, list[str]] = {}
    for name in queue_files:
        parsed = _parse_afl_artifact_name(name)
        queue_id = parsed.get("queue_id")
        if not queue_id:
            continue
        origin = str(parsed.get("origin_seed_file", ""))
        direct_seed_ids = [seed_by_file[origin]] if origin in seed_by_file else []
        nodes[queue_id] = {
            "queue_id": queue_id,
            "queue_file": name,
            "parent_queue_ids": list(parsed.get("parent_queue_ids", [])),
            "origin_seed_file": origin,
            "direct_seed_ids": direct_seed_ids,
            "root_seed_ids": set(direct_seed_ids),
        }
        for seed_id in direct_seed_ids:
            direct_queue_ids_by_seed.setdefault(seed_id, []).append(queue_id)

    changed = True
    while changed:
        changed = False
        for node in nodes.values():
            roots = set(node["root_seed_ids"])
            for parent_id in node["parent_queue_ids"]:
                parent = nodes.get(parent_id)
                if parent:
                    roots.update(parent["root_seed_ids"])
            if roots != node["root_seed_ids"]:
                node["root_seed_ids"] = roots
                changed = True

    unresolved: set[str] = set()
    report_nodes: list[dict[str, Any]] = []
    for queue_id, node in sorted(nodes.items()):
        roots = sorted(str(item) for item in node["root_seed_ids"])
        for parent_id in node["parent_queue_ids"]:
            if parent_id not in nodes:
                unresolved.add(parent_id)
        if not roots:
            continue
        for seed_id in roots:
            queue_ids_by_seed.setdefault(seed_id, []).append(queue_id)
            queue_files_by_seed.setdefault(seed_id, []).append(str(node["queue_file"]))
        report_nodes.append(
            {
                "queue_id": queue_id,
                "queue_file": node["queue_file"],
                "parent_queue_ids": node["parent_queue_ids"],
                "origin_seed_file": node["origin_seed_file"],
                "direct_seed_ids": node["direct_seed_ids"],
                "root_seed_ids": roots,
            }
        )
    return {
        "queue_files_by_seed": {key: _dedupe_strings(value) for key, value in queue_files_by_seed.items()},
        "direct_queue_ids_by_seed": {key: _dedupe_strings(value) for key, value in direct_queue_ids_by_seed.items()},
        "queue_ids_by_seed": {key: _dedupe_strings(value) for key, value in queue_ids_by_seed.items()},
        "seed_id_by_seed_file": seed_by_file,
        "nodes": nodes,
        "report": {
            "format": "protolens.afl_queue_lineage.v1",
            "queue_file_count": len(queue_files),
            "attributed_queue_count": len(report_nodes),
            "nodes": report_nodes,
            "unresolved_parent_queue_ids": sorted(unresolved),
        },
    }


def _artifact_matches_by_seed(files: list[str], lineage: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    nodes = lineage.get("nodes", {}) if isinstance(lineage.get("nodes"), dict) else {}
    for name in files:
        parsed = _parse_afl_artifact_name(name)
        seed_ids: set[str] = set()
        queue_id = parsed.get("queue_id")
        if queue_id in nodes:
            seed_ids.update(nodes[queue_id].get("root_seed_ids", set()))
        for parent_id in parsed.get("parent_queue_ids", []):
            if parent_id in nodes:
                seed_ids.update(nodes[parent_id].get("root_seed_ids", set()))
        origin = str(parsed.get("origin_seed_file", ""))
        seed_id_by_file = lineage.get("seed_id_by_seed_file", {})
        if origin and isinstance(seed_id_by_file, dict) and origin in seed_id_by_file:
            seed_ids.add(str(seed_id_by_file[origin]))
        for seed_id in seed_ids:
            result.setdefault(str(seed_id), []).append(name)
    return {key: _dedupe_strings(value) for key, value in result.items()}


def _parse_afl_artifact_name(name: str) -> dict[str, Any]:
    queue_match = re.search(r"(?:^|,)id:(\d+)", name)
    src_match = re.search(r"(?:^|,)src:(\d+(?:\+\d+)*)", name)
    orig_match = re.search(r"(?:^|,)orig:([^,]+)", name)
    return {
        "queue_id": _queue_id(queue_match.group(1)) if queue_match else "",
        "parent_queue_ids": [_queue_id(item) for item in src_match.group(1).split("+")] if src_match else [],
        "origin_seed_file": orig_match.group(1) if orig_match else "",
    }


def _queue_id(value: str) -> str:
    try:
        return f"{int(value):06d}"
    except ValueError:
        return str(value)


def _global_state_observation(dynamic: dict[str, Any]) -> dict[str, Any]:
    ipsm = dynamic.get("ipsm", {}) if isinstance(dynamic.get("ipsm"), dict) else {}
    return {
        "present": bool(ipsm.get("present") or ipsm.get("node_labels")),
        "node_count": int(ipsm.get("nodes") or len(ipsm.get("node_labels", [])) or 0),
        "edge_count": int(ipsm.get("edges") or len(ipsm.get("edge_pairs", [])) or 0),
        "node_labels": [str(item) for item in ipsm.get("node_labels", [])],
        "edge_pairs": list(ipsm.get("edge_pairs", [])),
        "scope": "campaign_global",
        "attribution_note": "IPSM labels are global campaign observations; they are not used as per-seed execution proof.",
    }


def _dedupe_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in values if str(item)))


def _matched_states(dynamic: dict[str, Any], seed: dict[str, Any]) -> list[dict[str, str]]:
    ipsm = dynamic.get("ipsm", {}) if isinstance(dynamic.get("ipsm"), dict) else {}
    labels = [str(item) for item in ipsm.get("node_labels", [])]
    label_index = {_normalize_label(label): label for label in labels}
    matched = []
    for state in seed.get("states", []):
        normalized = _normalize_label(str(state))
        if normalized in label_index:
            matched.append({"fsm_state": str(state), "ipsm_label": label_index[normalized]})
    return matched


def _seed_status(
    queue_matches: list[str],
    crash_matches: list[str],
    hang_matches: list[str],
) -> str:
    if crash_matches:
        return "crash_attributed"
    if hang_matches:
        return "hang_attributed"
    if queue_matches:
        return "queued_by_aflnet"
    return "unobserved"


def _group_feedback(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for item in items:
        label = str(item.get(key, "") or "<unknown>")
        group = groups.setdefault(
            label,
            {
                key: label,
                "seed_count": 0,
                "observed_count": 0,
                "queued_count": 0,
                "crash_count": 0,
                "hang_count": 0,
            },
        )
        group["seed_count"] += 1
        if item.get("status") != "unobserved":
            group["observed_count"] += 1
        if item.get("queued_by_aflnet"):
            group["queued_count"] += 1
        if item.get("crash_matches"):
            group["crash_count"] += 1
        if item.get("hang_matches"):
            group["hang_count"] += 1
    return sorted(groups.values(), key=lambda item: (-item["observed_count"], item[key]))


def _seed_replanning(seed_feedback: dict[str, Any] | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not seed_feedback or not seed_feedback.get("seed_manifest_present"):
        return [], []
    items = [item for item in seed_feedback.get("items", []) if isinstance(item, dict)]
    priorities: list[dict[str, Any]] = []
    variant_scores: dict[str, dict[str, int]] = {}
    for item in items:
        variant = str(item.get("variant", "") or "<unknown>")
        bucket = variant_scores.setdefault(variant, {"total": 0, "observed": 0})
        bucket["total"] += 1
        if item.get("status") != "unobserved":
            bucket["observed"] += 1
        score = int(item.get("priority") or 100)
        if item.get("status") in {"crash_attributed", "hang_attributed"}:
            score += 220
        elif item.get("queued_by_aflnet"):
            score += 80
        elif item.get("matched_states"):
            score += 40
        else:
            score -= 30
        priorities.append(
            {
                "seed_id": item.get("seed_id", ""),
                "seed_file": item.get("seed_file", ""),
                "conflict_id": item.get("conflict_id", ""),
                "variant": variant,
                "score": max(0, min(800, score)),
                "status": item.get("status", "unobserved"),
            }
        )
    priorities.sort(key=lambda item: (-int(item["score"]), str(item["seed_id"])))

    actions: list[dict[str, Any]] = []
    for variant, stats in sorted(variant_scores.items()):
        if stats["observed"]:
            actions.append(
                {
                    "priority": "P1",
                    "action": "expand_successful_seed_variant",
                    "variant": variant,
                    "reason": f"{stats['observed']}/{stats['total']} seed(s) for this variant were observed.",
                }
            )
        elif stats["total"] >= 2:
            actions.append(
                {
                    "priority": "P2",
                    "action": "suppress_ineffective_seed_variant",
                    "variant": variant,
                    "reason": f"0/{stats['total']} seed(s) for this variant were observed.",
                }
            )
    return actions, priorities


def _crash_paths(output_dir: Path) -> list[Path]:
    candidates = [output_dir / "replayable-crashes", output_dir / "crashes"]
    for directory in candidates:
        files = sorted(
            item
            for item in directory.iterdir()
            if directory.exists() and item.is_file() and not item.name.startswith((".", "README"))
        ) if directory.exists() else []
        if files:
            return files
    return []


def _resolve_replay_binary(config: ProtoLensConfig) -> str | None:
    names = ["aflnet-replay", "./aflnet-replay"]
    first = config.aflnet.cmd[0] if config.aflnet.cmd else config.aflnet.binary
    aflnet_path = Path(first).expanduser()
    if aflnet_path.name == "afl-fuzz":
        names.insert(0, str(aflnet_path.with_name("aflnet-replay")))
    for name in names:
        found = shutil.which(name)
        if found:
            return str(Path(found).resolve())
        path = Path(name).expanduser()
        candidates = [path] if path.is_absolute() else [Path.cwd() / path, config.source_root / path]
        for candidate in candidates:
            if candidate.is_file() and candidate.stat().st_mode & 0o111:
                return str(candidate.resolve())
    return None


def _target_command(cmd: list[str]) -> list[str]:
    if "--" not in cmd:
        return []
    separator = cmd.index("--")
    return [str(item) for item in cmd[separator + 1 :] if str(item)]


def _split_seed_messages(payload: bytes, protocol: str) -> list[bytes]:
    if protocol.lower() in {"rtsp", "http", "daap-http"}:
        return _split_keep_separator(payload, b"\r\n\r\n")
    return _split_keep_separator(payload, b"\r\n")


def _split_keep_separator(payload: bytes, separator: bytes) -> list[bytes]:
    parts = payload.split(separator)
    chunks = [part + separator for part in parts[:-1] if part]
    if parts[-1]:
        chunks.append(parts[-1])
    return chunks


def _as_float(value: Any) -> float:
    try:
        return float(str(value).strip("% "))
    except (TypeError, ValueError):
        return 0.0


def _strip_dot_quotes(value: str) -> str:
    return value.strip().strip('"')


def _normalize_label(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())
