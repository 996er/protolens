from __future__ import annotations

from argparse import ArgumentParser, Namespace
from pathlib import Path
import json
import sys
import traceback

from protolens.config import ProtoLensConfig
from protolens.fsm.fsm_model import Conflict, Divergence, ProtocolFSM
from protolens.pipeline import ProtoLensPipeline
from protolens.utils.artifact_store import ArtifactStore
from protolens.utils.logger import Logger


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.func(args)
    except Exception as exc:
        print(f"protolens: error: {exc}", file=sys.stderr)
        # debug 模式保留完整调用栈，普通模式只输出可读错误，避免污染 JSON stdout。
        if getattr(args, "debug", False):
            traceback.print_exc()
        return 1
    if result is not None:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(prog="protolens", description="Protocol state reasoning and AFLNet campaign preparation")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="create a run configuration")
    _add_debug_argument(init_parser)
    init_parser.add_argument("--protocol", required=True)
    init_parser.add_argument("--target", dest="target_name", required=True)
    init_parser.add_argument("--source", dest="source_root", required=True)
    init_parser.add_argument("--spec", dest="spec_paths", action="append", help="optional legacy RFC filename hint; not parsed locally")
    init_parser.add_argument("--rfc-query", dest="rfc_queries", action="append", help="query used by LLM web search for current RFCs")
    init_parser.add_argument("--out", dest="run_dir", required=True)
    init_parser.add_argument("--host", default="127.0.0.1")
    init_parser.add_argument("--port", type=int, default=0)
    init_parser.add_argument("--run-command", default="")
    init_parser.add_argument("--llm-provider", default="openai")
    init_parser.add_argument("--llm-model", default="gpt-5.4")
    init_parser.set_defaults(func=cmd_init)

    impl_parser = subparsers.add_parser("build-impl", help="extract implementation facts and build the implementation FSM")
    _add_fsm_stage_arguments(impl_parser)
    impl_parser.set_defaults(func=cmd_build_impl)

    spec_parser = subparsers.add_parser("build-spec", help="build the scoped specification FSM from RFC sources")
    _add_fsm_stage_arguments(spec_parser)
    spec_parser.set_defaults(func=cmd_build_spec)

    merge_parser = subparsers.add_parser("merge-fsm", help="merge completed specification and implementation FSM artifacts")
    _add_fsm_stage_arguments(merge_parser)
    merge_parser.set_defaults(func=cmd_merge_fsm)

    build_parser_ = subparsers.add_parser("build-fsm", help="resume all FSM stages in dependency order")
    _add_debug_argument(build_parser_)
    build_parser_.add_argument("--config", required=True)
    build_parser_.add_argument("--force", action="store_true", help="rebuild every FSM stage instead of using checkpoints")
    build_parser_.set_defaults(func=cmd_build_fsm)

    reason_parser = subparsers.add_parser("reason", help="run adversarial reasoning and conflict detection")
    _add_debug_argument(reason_parser)
    reason_parser.add_argument("--config", required=True)
    reason_parser.add_argument("--fsm", help="path to unified FSM JSON; defaults to run_dir/unified_fsm.json")
    reason_parser.add_argument("--divergences", help="path to divergences JSON; defaults to run_dir/divergences.json")
    reason_parser.set_defaults(func=cmd_reason)

    fuzz_parser = subparsers.add_parser("fuzz", help="plan paths and prepare or run AFLNet")
    _add_debug_argument(fuzz_parser)
    fuzz_parser.add_argument("--config", required=True)
    fuzz_parser.add_argument("--fsm", help="path to unified FSM JSON; defaults to run_dir/unified_fsm.json")
    fuzz_parser.add_argument("--conflicts", help="path to conflicts JSON; defaults to run_dir/conflicts.json")
    fuzz_parser.add_argument("--divergences", help="path to divergences JSON; defaults to run_dir/divergences.json")
    fuzz_parser.add_argument("--jobs", type=int, default=1, help="currently requires explicit parallel AFLNet commands in aflnet.cmd; only 1 is accepted")
    fuzz_parser.set_defaults(func=cmd_fuzz)

    run_parser = subparsers.add_parser("run", help="run the complete ProtoLens pipeline")
    _add_debug_argument(run_parser)
    run_parser.add_argument("--config", required=True)
    run_parser.add_argument("--force-fsm", action="store_true", help="rebuild every FSM stage before reasoning and fuzzing")
    run_parser.set_defaults(func=cmd_run)
    return parser


def _add_debug_argument(parser: ArgumentParser) -> None:
    parser.add_argument("--debug", action="store_true", help="enable debug logs on stderr and in run_dir/protolens.log")


def _add_fsm_stage_arguments(parser: ArgumentParser) -> None:
    _add_debug_argument(parser)
    parser.add_argument("--config", required=True)
    parser.add_argument("--force", action="store_true", help="ignore this stage's checkpoint and rebuild it")


def _logger_for(config: ProtoLensConfig, args: Namespace) -> Logger:
    debug_enabled = bool(getattr(args, "debug", False) or config.debug)
    return Logger(debug_enabled=debug_enabled, log_file=config.run_dir / "protolens.log")


def cmd_init(args: Namespace) -> dict[str, str]:
    run_dir = Path(args.run_dir).expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    config_path = run_dir / "config.json"
    data = {
        "protocol": args.protocol,
        "target_name": args.target_name,
        "spec_paths": [str(Path(item).expanduser().resolve()) for item in (args.spec_paths or [])],
        "source_root": str(Path(args.source_root).expanduser().resolve()),
        "entrypoints": [],
        "build_command": "",
        "run_command": args.run_command,
        "host": args.host,
        "port": args.port,
        "run_dir": str(run_dir),
        "debug": bool(args.debug),
        "aflnet": {
            "binary": str((Path.cwd() / "afl-fuzz").resolve()),
            "timeout_ms": 1000,
            "duration_seconds": 0,
            "dry_run": True,
        },
        "monitor_agent": {
            "enabled": True,
            "interval_seconds": 30.0,
            "stagnation_seconds": 300.0,
            "min_exec_delta": 1000,
            "max_seed_batch": 8,
            "max_llm_calls_per_stagnation_signature": 1,
        },
        "transport_harness": {
            "enabled": False,
            "timeout_seconds": 3.0,
            "use_tls": False,
            "verify_tls": False,
            "max_actions": 20,
        },
        "path_calibration": {
            "enabled": False,
            "max_candidates": 3,
            "max_depth": 16,
            "max_expansions": 2000,
            "timeout_seconds": 2.0,
            "startup_seconds": 3.0,
            "max_probes": 30,
        },
        "fsm_build": {
            "rfc_queries": args.rfc_queries or [],
            "rfc_analysis_scope": [
                "control connection lifecycle and states",
                "authentication and command sequencing",
                "data connection establishment",
                "TLS and protocol security extensions",
                "optional extensions evidenced as supported by the target implementation",
            ],
            "target_supported_extensions_only": True,
            "allowed_rfc_domains": ["rfc-editor.org", "datatracker.ietf.org", "ietf.org"],
            "chunk_chars": 80000,
            "max_file_bytes": 2000000,
            "max_web_search_calls": 8,
        },
        "llm": {
            "provider": args.llm_provider,
            "model": args.llm_model,
            "temperature": 0.0,
            "api_key_env": "OPENAI_API_KEY",
            "max_tokens": 24000,
            "retries": 2,
        },
    }
    config_path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"config": str(config_path), "run_dir": str(run_dir)}


def cmd_build_impl(args: Namespace) -> dict[str, object]:
    config = ProtoLensConfig.load(args.config)
    pipeline = ProtoLensPipeline(config, _logger_for(config, args))
    pipeline.init_run()
    fsm, reused = pipeline.build_implementation(force=args.force)
    return {
        "run_dir": str(config.run_dir),
        "stage": "implementation",
        "reused": reused,
        "states": len(fsm.states),
        "transitions": len(fsm.transitions),
        "transition_facts": str(config.run_dir / "implementation_transition_facts.json"),
        "evidence_table": str(config.run_dir / "implementation_evidence_table.json"),
    }


def cmd_build_spec(args: Namespace) -> dict[str, object]:
    config = ProtoLensConfig.load(args.config)
    pipeline = ProtoLensPipeline(config, _logger_for(config, args))
    pipeline.init_run()
    fsm, reused = pipeline.build_specification(force=args.force)
    return {
        "run_dir": str(config.run_dir),
        "stage": "specification",
        "reused": reused,
        "states": len(fsm.states),
        "transitions": len(fsm.transitions),
    }


def cmd_merge_fsm(args: Namespace) -> dict[str, object]:
    config = ProtoLensConfig.load(args.config)
    pipeline = ProtoLensPipeline(config, _logger_for(config, args))
    pipeline.init_run()
    unified, divergences, reused = pipeline.merge_fsms(force=args.force)
    return {
        "run_dir": str(config.run_dir),
        "stage": "merge",
        "reused": reused,
        "states": len(unified.states),
        "transitions": len(unified.transitions),
        "divergences": len(divergences),
    }


def cmd_build_fsm(args: Namespace) -> dict[str, object]:
    config = ProtoLensConfig.load(args.config)
    pipeline = ProtoLensPipeline(config, _logger_for(config, args))
    pipeline.init_run()
    _, _, unified, divergences = pipeline.build_fsm(force=args.force)
    return {
        "run_dir": str(config.run_dir),
        "states": len(unified.states),
        "transitions": len(unified.transitions),
        "divergences": len(divergences),
        "stage_reuse": dict(pipeline.stage_reuse),
    }


def cmd_reason(args: Namespace) -> dict[str, object]:
    config = ProtoLensConfig.load(args.config)
    store = ArtifactStore(config.run_dir)
    fsm = ProtocolFSM.from_dict(_read_json_arg(args.fsm, store, "unified_fsm.json"))
    divergences = [Divergence.from_dict(item) for item in _read_json_arg(args.divergences, store, "divergences.json")]
    pipeline = ProtoLensPipeline(config, _logger_for(config, args))
    directions, findings, conflicts = pipeline.reason(fsm, divergences)
    return {
        "run_dir": str(config.run_dir),
        "directions": len(directions),
        "findings": len(findings),
        "conflicts": len(conflicts),
    }


def cmd_fuzz(args: Namespace) -> dict[str, object]:
    if args.jobs != 1:
        raise ValueError("parallel jobs require explicit AFLNet parallelization in aflnet.cmd; ProtoLens will not synthesize alternate AFLNet commands")
    config = ProtoLensConfig.load(args.config)
    store = ArtifactStore(config.run_dir)
    fsm = ProtocolFSM.from_dict(_read_json_arg(args.fsm, store, "unified_fsm.json"))
    conflicts = [Conflict.from_dict(item) for item in _read_json_arg(args.conflicts, store, "conflicts.json")]
    pipeline = ProtoLensPipeline(config, _logger_for(config, args))
    paths, result = pipeline.synthesize_and_fuzz(fsm, conflicts)
    pipeline.write_report(fsm, [Divergence.from_dict(item) for item in _read_json_arg(args.divergences, store, "divergences.json")], conflicts, paths, result)
    return {
        "run_dir": str(config.run_dir),
        "planned_paths": len(paths),
        "fuzz_mode": result.mode,
        "command": result.command,
    }


def cmd_run(args: Namespace) -> dict[str, object]:
    config = ProtoLensConfig.load(args.config)
    pipeline = ProtoLensPipeline(config, _logger_for(config, args))
    return pipeline.run(force_fsm=args.force_fsm)


def _read_json_arg(path: str | None, store: ArtifactStore, default_name: str) -> object:
    if path:
        with Path(path).expanduser().resolve().open("r", encoding="utf-8") as handle:
            return json.load(handle)
    return store.read_json(default_name)


if __name__ == "__main__":
    raise SystemExit(main())
