from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import os
import json
import shlex
import shutil
import signal
import subprocess
import time
from typing import Callable

from protolens.config import ProtoLensConfig
from protolens.fsm.fsm_model import FuzzResult, PlannedStatePath, SeedIntent
from protolens.tools.corpus_encoder import CorpusEncoder

ProgressCallback = Callable[[FuzzResult], None]


class AFLNetAdapter:
    """准备 AFLNet 工件，并把执行状态统一转换为可审计的 FuzzResult。"""

    def __init__(self, encoder: CorpusEncoder | None = None) -> None:
        self.encoder = encoder or CorpusEncoder()

    def prepare(
        self,
        config: ProtoLensConfig,
        paths: list[PlannedStatePath],
        seed_intents: list[SeedIntent] | None = None,
    ) -> FuzzResult:
        command = self._build_command(config)
        command_options = _AFLNetCommandOptions.from_command(command, config.source_root)

        notes: list[str] = []
        if command_options.errors and not config.aflnet.dry_run:
            fallback_dictionary = config.run_dir / "dictionaries" / f"{config.protocol.lower()}.dict"
            return FuzzResult(
                mode="error",
                command=command,
                corpus_dir=str(command_options.corpus_dir or config.run_dir / "corpus-preview"),
                dictionary_path=str(command_options.dictionary_path or fallback_dictionary),
                output_dir=str(command_options.output_dir or config.run_dir / "aflnet-preview"),
                notes=command_options.errors,
            )

        corpus_dir = command_options.corpus_dir or config.run_dir / "corpus-preview"
        output_dir = command_options.output_dir or config.run_dir / "aflnet-preview"
        dictionary_path = (
            command_options.dictionary_path
            or config.run_dir / "dictionaries" / f"{config.protocol.lower()}.dict"
        )
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        if seed_intents is not None:
            seed_manifest = self.encoder.write_seed_intents(
                seed_intents,
                corpus_dir,
                config.protocol,
                managed_manifest=config.run_dir / "aflnet_corpus_manifest.json",
                seed_manifest_path=config.run_dir / "seed_manifest.json",
            )
            notes.append(
                "ProtoLens seed intents: "
                f"{seed_manifest['seed_count']} written, {seed_manifest['deduplicated_count']} duplicate payloads skipped"
            )
        else:
            self.encoder.write_corpus(
                paths,
                corpus_dir,
                config.protocol,
                managed_manifest=config.run_dir / "aflnet_corpus_manifest.json",
            )
            seed_manifest = {}
        dictionary_source = seed_intents if seed_intents is not None else paths
        if command_options.dictionary_path:
            self.encoder.write_dictionary(dictionary_source, dictionary_path, preserve_existing=True)
        else:
            self.encoder.write_dictionary(dictionary_source, dictionary_path)
            notes.append(
                "aflnet.cmd does not contain -x; "
                "ProtoLens wrote an audit dictionary that AFLNet will not consume."
            )
        if seed_intents is not None:
            schedule = self.encoder.write_seed_queue_schedule(
                seed_manifest,
                config.run_dir,
                replanning_plan=_read_replanning_plan(config.run_dir / "replanning_plan.json"),
            )
        else:
            schedule = self.encoder.write_queue_schedule(paths, corpus_dir, config.run_dir, config.protocol)
        schedule_tsv = str(schedule["tsv_path"])
        if config.monitor_agent.enabled:
            import_dir = _monitor_import_dir(config)
            import_dir.mkdir(parents=True, exist_ok=True)
            (import_dir / ".processed").mkdir(exist_ok=True)
            notes.append(f"ProtoLens monitor import dir: {import_dir}")
        binary = _resolve_binary(command[0], config.source_root)
        if binary:
            command[0] = binary
        notes.insert(0, f"AFLNet queue schedule: {schedule_tsv}")
        if config.aflnet.dry_run:
            return FuzzResult(
                mode="dry-run",
                command=command,
                corpus_dir=str(corpus_dir),
                dictionary_path=str(dictionary_path),
                output_dir=str(output_dir),
                notes=notes + ["AFLNet dry_run=true; command was prepared but not executed."],
            )

        if not binary:
            return FuzzResult(
                mode="error",
                command=command,
                corpus_dir=str(corpus_dir),
                dictionary_path=str(dictionary_path),
                output_dir=str(output_dir),
                exit_code=None,
                notes=notes + [f"AFLNet binary not found: {command[0]}"],
            )

        return FuzzResult(
            mode="prepared",
            command=command,
            corpus_dir=str(corpus_dir),
            dictionary_path=str(dictionary_path),
            output_dir=str(output_dir),
            notes=notes + ["AFLNet command prepared; execution has not started yet."],
        )

    def execute(
        self,
        config: ProtoLensConfig,
        prepared: FuzzResult,
        on_progress: ProgressCallback | None = None,
    ) -> FuzzResult:
        if prepared.mode != "prepared":
            return prepared

        build_error = _run_build_command(config)
        if build_error:
            return replace(
                prepared,
                mode="error",
                completed_at=_utc_now(),
                notes=_replace_terminal_note(prepared.notes, build_error),
            )

        command = list(prepared.command)
        process: subprocess.Popen[bytes] | None = None
        started_at = _utc_now()
        try:
            env = os.environ.copy()
            env["AFLNET_PROTO_SCHEDULE"] = _schedule_path_from_notes(prepared.notes)
            import_dir = _monitor_import_dir(config)
            if config.monitor_agent.enabled:
                import_dir.mkdir(parents=True, exist_ok=True)
                (import_dir / ".processed").mkdir(exist_ok=True)
                env["AFLNET_PROTOLENS_IMPORT_DIR"] = str(import_dir)
            process = subprocess.Popen(
                command,
                cwd=str(config.source_root),
                start_new_session=True,
                env=env,
            )
            running = replace(
                prepared,
                mode="running",
                process_id=process.pid,
                started_at=started_at,
                notes=_replace_terminal_note(prepared.notes, "AFLNet campaign is running."),
            )
            _emit_progress(on_progress, running)
            deadline = time.monotonic() + config.aflnet.duration_seconds if config.aflnet.duration_seconds else None
            while True:
                exit_code = process.poll()
                if exit_code is not None:
                    return _completed_result(running, "executed", exit_code, "AFLNet campaign exited.")
                if deadline is not None and time.monotonic() >= deadline:
                    _terminate_process_group(process)
                    return _completed_result(
                        running,
                        "timed-out",
                        124,
                        f"campaign stopped after {config.aflnet.duration_seconds} seconds",
                    )
                _emit_progress(on_progress, _refresh_running(running))
                if deadline is None:
                    time.sleep(5.0)
                else:
                    time.sleep(max(0.1, min(5.0, deadline - time.monotonic())))
        except KeyboardInterrupt:
            if process is not None:
                _terminate_process_group(process)
            return _completed_result(
                replace(
                    prepared,
                    mode="interrupted",
                    process_id=process.pid if process else None,
                    started_at=started_at,
                ),
                "interrupted",
                130,
                "campaign interrupted by user",
            )
        except OSError as exc:
            return replace(
                prepared,
                mode="error",
                completed_at=_utc_now(),
                notes=_replace_terminal_note(prepared.notes, f"failed to start AFLNet: {exc}"),
            )

    def prepare_and_run(
        self,
        config: ProtoLensConfig,
        paths: list[PlannedStatePath],
        seed_intents: list[SeedIntent] | None = None,
    ) -> FuzzResult:
        return self.execute(config, self.prepare(config, paths, seed_intents=seed_intents))

    def _build_command(self, config: ProtoLensConfig) -> list[str]:
        if not config.aflnet.cmd:
            raise ValueError("aflnet.cmd is required to run AFLNet")
        return list(config.aflnet.cmd)


class _AFLNetCommandOptions:
    def __init__(
        self,
        *,
        corpus_dir: Path | None,
        output_dir: Path | None,
        dictionary_path: Path | None,
        errors: list[str],
    ) -> None:
        self.corpus_dir = corpus_dir
        self.output_dir = output_dir
        self.dictionary_path = dictionary_path
        self.errors = errors

    @classmethod
    def from_command(cls, command: list[str], cwd: Path) -> "_AFLNetCommandOptions":
        errors: list[str] = []
        corpus_value = _single_option_value(command, "-i", errors)
        output_value = _single_option_value(command, "-o", errors)
        dictionary_value = _single_option_value(command, "-x", errors)
        if corpus_value is None:
            errors.append("aflnet.cmd must contain -i <input_corpus_dir>; ProtoLens will not inject it.")
        elif corpus_value == "-":
            errors.append("aflnet.cmd uses -i -; ProtoLens cannot write planned path seeds to stdin mode.")
        if output_value is None:
            errors.append("aflnet.cmd must contain -o <output_dir>; ProtoLens will not inject it.")
        return cls(
            corpus_dir=_resolve_command_path(corpus_value, cwd) if corpus_value and corpus_value != "-" else None,
            output_dir=_resolve_command_path(output_value, cwd) if output_value else None,
            dictionary_path=_resolve_command_path(dictionary_value, cwd) if dictionary_value else None,
            errors=errors,
        )


def _list_names(path: Path) -> list[str]:
    if not path.exists():
        return []
    return sorted(
        item.name
        for item in path.iterdir()
        if item.is_file() and not item.name.startswith((".", "README"))
    )


def _read_replanning_plan(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _list_findings(output_dir: Path, kind: str) -> list[str]:
    # AFLNet 使用 replayable-*，同时兼容传统 AFL 的 crashes/hangs 目录。
    names = _list_names(output_dir / f"replayable-{kind}")
    return names or _list_names(output_dir / kind)


def _single_option_value(command: list[str], flag: str, errors: list[str]) -> str | None:
    cutoff = command.index("--") if "--" in command else len(command)
    values: list[str] = []
    index = 0
    while index < cutoff:
        token = command[index]
        if token == flag:
            if index + 1 >= cutoff:
                errors.append(f"aflnet.cmd option {flag} requires a value")
            else:
                values.append(command[index + 1])
                index += 1
        elif token.startswith(flag) and token != flag:
            values.append(token[len(flag):])
        index += 1
    if len(values) > 1:
        errors.append(f"aflnet.cmd contains duplicate {flag} options")
    return values[-1] if values else None


def _resolve_command_path(value: str, cwd: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = cwd / path
    return path.resolve(strict=False)


def _resolve_binary(value: str, source_root: Path) -> str | None:
    direct = shutil.which(value)
    if direct:
        return str(Path(direct).resolve())
    path = Path(value).expanduser()
    candidates = [path] if path.is_absolute() else [Path.cwd() / path, source_root / path]
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_mode & 0o111:
            return str(candidate.resolve())
    return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit_progress(callback: ProgressCallback | None, result: FuzzResult) -> None:
    if callback is not None:
        callback(result)


def _refresh_running(result: FuzzResult) -> FuzzResult:
    return replace(
        result,
        crashes=_list_findings(Path(result.output_dir), "crashes"),
        hangs=_list_findings(Path(result.output_dir), "hangs"),
    )


def _completed_result(running: FuzzResult, mode: str, exit_code: int, note: str) -> FuzzResult:
    output_dir = Path(running.output_dir)
    return replace(
        running,
        mode=mode,
        exit_code=exit_code,
        crashes=_list_findings(output_dir, "crashes"),
        hangs=_list_findings(output_dir, "hangs"),
        completed_at=_utc_now(),
        notes=_replace_terminal_note(running.notes, note),
    )


def _replace_terminal_note(notes: list[str], note: str) -> list[str]:
    base = [
        item
        for item in notes
        if not item.startswith("AFLNet command prepared;") and item != "AFLNet campaign is running."
    ]
    return base + [note]


def _schedule_path_from_notes(notes: list[str]) -> str:
    prefix = "AFLNet queue schedule: "
    for note in notes:
        if note.startswith(prefix):
            return note[len(prefix):]
    return ""


def _monitor_import_dir(config: ProtoLensConfig) -> Path:
    return config.monitor_agent.import_dir or (config.run_dir / "monitor_import_queue")


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def _run_build_command(config: ProtoLensConfig) -> str | None:
    if not config.build_command.strip():
        return None
    try:
        completed = subprocess.run(
            shlex.split(config.build_command),
            cwd=str(config.source_root),
            check=False,
        )
    except (OSError, ValueError) as exc:
        return f"failed to start build command: {exc}"
    if completed.returncode != 0:
        return f"build command exited with status {completed.returncode}"
    return None
