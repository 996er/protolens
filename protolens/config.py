from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json
import math
import shlex


@dataclass
class AFLNetConfig:
    """AFLNet 执行参数。

    ``timeout_ms`` 为兼容既有配置保留，实际对应 AFLNet ``-D`` 的服务启动等待时间。
    """

    binary: str = "./afl-fuzz"
    timeout_ms: int = 1000
    duration_seconds: int = 0
    dry_run: bool = True
    cmd: list[str] = field(default_factory=list)
    extra_args: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, base_dir: Path | None = None) -> "AFLNetConfig":
        data = data or {}
        binary = str(data.get("binary", "./afl-fuzz"))
        binary_path = Path(binary).expanduser()
        if base_dir is not None and not binary_path.is_absolute() and binary_path.parent != Path("."):
            binary = str((base_dir / binary_path).resolve())
        cmd = _parse_cmd(data.get("cmd", []))
        if cmd and base_dir is not None:
            first = Path(cmd[0]).expanduser()
            if not first.is_absolute() and first.parent != Path("."):
                cmd[0] = str((base_dir / first).resolve())
        return cls(
            binary=binary,
            timeout_ms=int(data.get("timeout_ms", 1000)),
            duration_seconds=int(data.get("duration_seconds", 0)),
            dry_run=bool(data.get("dry_run", True)),
            cmd=cmd,
            extra_args=[str(item) for item in data.get("extra_args", [])],
        )


@dataclass
class AFLNetMonitorConfig:
    """Runtime AFLNet coverage-stagnation monitor controls."""

    enabled: bool = True
    interval_seconds: float = 30.0
    stagnation_seconds: float = 300.0
    min_exec_delta: int = 1000
    max_seed_batch: int = 8
    max_llm_calls_per_stagnation_signature: int = 1
    max_llm_failures_per_stagnation_signature: int = 3
    llm_failure_backoff_seconds: float = 120.0
    import_dir: Path | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, base_dir: Path | None = None) -> "AFLNetMonitorConfig":
        data = data or {}
        import_dir_value = data.get("import_dir")
        return cls(
            enabled=bool(data.get("enabled", True)),
            interval_seconds=float(data.get("interval_seconds", 30.0)),
            stagnation_seconds=float(data.get("stagnation_seconds", 300.0)),
            min_exec_delta=int(data.get("min_exec_delta", 1000)),
            max_seed_batch=int(data.get("max_seed_batch", 8)),
            max_llm_calls_per_stagnation_signature=int(
                data.get("max_llm_calls_per_stagnation_signature", 1)
            ),
            max_llm_failures_per_stagnation_signature=int(
                data.get("max_llm_failures_per_stagnation_signature", 3)
            ),
            llm_failure_backoff_seconds=float(data.get("llm_failure_backoff_seconds", 120.0)),
            import_dir=_resolve_path(base_dir or Path.cwd(), import_dir_value) if import_dir_value else None,
        )


@dataclass
class TransportHarnessConfig:
    """Socket-level executor for cross-layer actions that AFLNet seeds cannot encode."""

    enabled: bool = False
    timeout_seconds: float = 3.0
    use_tls: bool = False
    verify_tls: bool = False
    max_actions: int = 20

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "TransportHarnessConfig":
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", False)),
            timeout_seconds=float(data.get("timeout_seconds", 3.0)),
            use_tls=bool(data.get("use_tls", False)),
            verify_tls=bool(data.get("verify_tls", False)),
            max_actions=int(data.get("max_actions", 20)),
        )


@dataclass
class LLMConfig:
    """OpenAI Chat Completions 及其兼容服务的连接配置。"""

    provider: str = "offline"
    model: str = "rule-based"
    temperature: float = 0.0
    timeout_seconds: int = 60
    base_url: str | None = None
    api_key_env: str = "OPENAI_API_KEY"
    max_tokens: int = 2000
    retries: int = 2
    response_format: str = "auto"
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "LLMConfig":
        data = data or {}
        headers = data.get("extra_headers", {})
        if not isinstance(headers, dict):
            raise ValueError("llm.extra_headers must be a JSON object")
        return cls(
            provider=str(data.get("provider", "offline")),
            model=str(data.get("model", "rule-based")),
            temperature=float(data.get("temperature", 0.0)),
            timeout_seconds=int(data.get("timeout_seconds", 60)),
            base_url=data.get("base_url"),
            api_key_env=str(data.get("api_key_env", "OPENAI_API_KEY")),
            max_tokens=int(data.get("max_tokens", 2000)),
            retries=int(data.get("retries", 2)),
            response_format=str(data.get("response_format", "auto")),
            extra_headers={str(key): str(value) for key, value in headers.items()},
        )

    def to_json_dict(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        sensitive = {"authorization", "x-api-key", "api-key"}
        data["extra_headers"] = {
            key: "***" if key.lower() in sensitive else value
            for key, value in self.extra_headers.items()
        }
        return data


@dataclass
class FSMBuildConfig:
    """LLM-native FSM construction controls.

    Source files are only collected and chunked locally. All protocol semantics,
    state recovery, divergence analysis, and merging are delegated to the LLM.
    """

    rfc_queries: list[str] = field(default_factory=list)
    rfc_analysis_scope: list[str] = field(
        default_factory=lambda: [
            "control connection lifecycle and states",
            "authentication and command sequencing",
            "data connection establishment",
            "TLS and protocol security extensions",
            "optional extensions evidenced as supported by the target implementation",
        ]
    )
    target_supported_extensions_only: bool = True
    allowed_rfc_domains: list[str] = field(
        default_factory=lambda: ["rfc-editor.org", "datatracker.ietf.org", "ietf.org"]
    )
    source_extensions: list[str] = field(
        default_factory=lambda: [
            ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
            ".go", ".java", ".js", ".jsx", ".ts", ".tsx", ".py", ".rs",
            ".rb", ".php", ".swift", ".kt", ".kts", ".scala", ".cs",
            ".erl", ".ex", ".exs", ".lua", ".sh", ".proto", ".toml",
            ".yaml", ".yml", ".json", ".xml", ".ini", ".conf", ".cfg",
        ]
    )
    ignore_directories: list[str] = field(
        default_factory=lambda: [
            ".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__",
            "node_modules", "vendor", "dist", "build", "target", "coverage",
        ]
    )
    chunk_chars: int = 80000
    max_file_bytes: int = 2_000_000
    max_web_search_calls: int = 8

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "FSMBuildConfig":
        data = data or {}
        defaults = cls()
        return cls(
            rfc_queries=[str(item).strip() for item in data.get("rfc_queries", []) if str(item).strip()],
            rfc_analysis_scope=[
                str(item).strip()
                for item in data.get("rfc_analysis_scope", defaults.rfc_analysis_scope)
                if str(item).strip()
            ],
            target_supported_extensions_only=bool(
                data.get("target_supported_extensions_only", defaults.target_supported_extensions_only)
            ),
            allowed_rfc_domains=[
                str(item).lower().strip().lstrip(".")
                for item in data.get("allowed_rfc_domains", defaults.allowed_rfc_domains)
                if str(item).strip()
            ],
            source_extensions=[
                _normalize_extension(item)
                for item in data.get("source_extensions", defaults.source_extensions)
                if str(item).strip()
            ],
            ignore_directories=[
                str(item).strip()
                for item in data.get("ignore_directories", defaults.ignore_directories)
                if str(item).strip()
            ],
            chunk_chars=int(data.get("chunk_chars", defaults.chunk_chars)),
            max_file_bytes=int(data.get("max_file_bytes", defaults.max_file_bytes)),
            max_web_search_calls=int(data.get("max_web_search_calls", defaults.max_web_search_calls)),
        )


@dataclass
class PathCalibrationConfig:
    enabled: bool = False
    max_candidates: int = 3
    max_depth: int = 16
    max_expansions: int = 2000
    timeout_seconds: float = 2.0
    startup_seconds: float = 3.0
    max_probes: int = 30

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "PathCalibrationConfig":
        data = data or {}
        defaults = cls()
        return cls(
            enabled=bool(data.get("enabled", defaults.enabled)),
            max_candidates=int(data.get("max_candidates", defaults.max_candidates)),
            max_depth=int(data.get("max_depth", defaults.max_depth)),
            max_expansions=int(data.get("max_expansions", defaults.max_expansions)),
            timeout_seconds=float(data.get("timeout_seconds", defaults.timeout_seconds)),
            startup_seconds=float(data.get("startup_seconds", defaults.startup_seconds)),
            max_probes=int(data.get("max_probes", defaults.max_probes)),
        )


@dataclass
class ProtoLensConfig:
    protocol: str
    target_name: str
    spec_paths: list[Path]
    source_root: Path
    entrypoints: list[str]
    host: str
    port: int
    run_command: str = ""
    build_command: str = ""
    run_dir: Path = Path("runs/default")
    aflnet: AFLNetConfig = field(default_factory=AFLNetConfig)
    monitor_agent: AFLNetMonitorConfig = field(default_factory=AFLNetMonitorConfig)
    transport_harness: TransportHarnessConfig = field(default_factory=TransportHarnessConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    fsm_build: FSMBuildConfig = field(default_factory=FSMBuildConfig)
    path_calibration: PathCalibrationConfig = field(default_factory=PathCalibrationConfig)
    debug: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "ProtoLensConfig":
        config_path = Path(path).expanduser().resolve()
        with config_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("configuration root must be a JSON object")
        base_dir = config_path.parent
        return cls.from_dict(data, base_dir=base_dir)

    @classmethod
    def from_dict(cls, data: dict[str, Any], base_dir: Path | None = None) -> "ProtoLensConfig":
        base_dir = (base_dir or Path.cwd()).resolve()
        protocol = str(data["protocol"]).strip()
        target_name = str(data["target_name"]).strip()
        if not protocol or not target_name:
            raise ValueError("protocol and target_name must be non-empty")

        # spec_paths is retained as an optional query hint for old configurations.
        # FSM construction never parses these files locally.
        spec_paths = [_resolve_path(base_dir, item) for item in data.get("spec_paths", [])]

        run_dir_value = data.get("run_dir", f"runs/{protocol}-{target_name}")
        config = cls(
            protocol=protocol,
            target_name=target_name,
            spec_paths=spec_paths,
            source_root=_resolve_path(base_dir, data.get("source_root", ".")),
            entrypoints=[str(item) for item in data.get("entrypoints", [])],
            build_command=str(data.get("build_command", "")),
            run_command=str(data.get("run_command", "")),
            host=str(data.get("host", "127.0.0.1")),
            port=int(data.get("port", 0)),
            run_dir=_resolve_path(base_dir, run_dir_value),
            aflnet=AFLNetConfig.from_dict(data.get("aflnet"), base_dir=base_dir),
            monitor_agent=AFLNetMonitorConfig.from_dict(data.get("monitor_agent"), base_dir=base_dir),
            transport_harness=TransportHarnessConfig.from_dict(data.get("transport_harness")),
            llm=LLMConfig.from_dict(data.get("llm")),
            fsm_build=FSMBuildConfig.from_dict(data.get("fsm_build")),
            path_calibration=PathCalibrationConfig.from_dict(data.get("path_calibration")),
            debug=bool(data.get("debug", False)),
            raw=dict(data),
        )
        config.validate()
        return config

    def validate(self) -> None:
        """尽早拒绝会在长流程末端才暴露的无效配置。"""

        for name in ("max_candidates", "max_depth", "max_expansions", "max_probes", "timeout_seconds", "startup_seconds"):
            value = getattr(self.path_calibration, name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"path_calibration.{name} must be finite and positive")
        if not 0 <= self.port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        if not self.aflnet.dry_run and self.port == 0:
            raise ValueError("port must be between 1 and 65535 when AFLNet execution is enabled")
        if not self.aflnet.dry_run and not self.aflnet.cmd:
            raise ValueError("aflnet.cmd is required when aflnet.dry_run is false")
        if self.aflnet.timeout_ms < 0:
            raise ValueError("aflnet.timeout_ms must be non-negative")
        if self.aflnet.duration_seconds < 0:
            raise ValueError("aflnet.duration_seconds must be non-negative")
        if self.monitor_agent.interval_seconds <= 0:
            raise ValueError("monitor_agent.interval_seconds must be positive")
        if self.monitor_agent.stagnation_seconds < 0:
            raise ValueError("monitor_agent.stagnation_seconds must be non-negative")
        if self.monitor_agent.min_exec_delta < 0:
            raise ValueError("monitor_agent.min_exec_delta must be non-negative")
        if self.monitor_agent.max_seed_batch <= 0:
            raise ValueError("monitor_agent.max_seed_batch must be positive")
        if self.monitor_agent.max_llm_calls_per_stagnation_signature <= 0:
            raise ValueError("monitor_agent.max_llm_calls_per_stagnation_signature must be positive")
        if self.transport_harness.timeout_seconds <= 0:
            raise ValueError("transport_harness.timeout_seconds must be positive")
        if self.transport_harness.max_actions < 0:
            raise ValueError("transport_harness.max_actions must be non-negative")
        if self.llm.timeout_seconds <= 0:
            raise ValueError("llm.timeout_seconds must be positive")
        if self.llm.max_tokens <= 0:
            raise ValueError("llm.max_tokens must be positive")
        if self.llm.retries < 0:
            raise ValueError("llm.retries must be non-negative")
        providers = {"offline", "mock", "rule-based", "openai", "openai-compatible"}
        if self.llm.provider.lower().strip() not in providers:
            raise ValueError(f"unsupported llm.provider: {self.llm.provider!r}")
        formats = {"auto", "json_object", "json_schema", "none"}
        if self.llm.response_format.lower().strip() not in formats:
            raise ValueError(f"unsupported llm.response_format: {self.llm.response_format!r}")
        if self.fsm_build.chunk_chars < 8000:
            raise ValueError("fsm_build.chunk_chars must be at least 8000")
        if self.fsm_build.max_file_bytes <= 0:
            raise ValueError("fsm_build.max_file_bytes must be positive")
        if self.fsm_build.max_web_search_calls <= 0:
            raise ValueError("fsm_build.max_web_search_calls must be positive")
        if not self.fsm_build.allowed_rfc_domains:
            raise ValueError("fsm_build.allowed_rfc_domains must not be empty")
        if not self.fsm_build.rfc_analysis_scope:
            raise ValueError("fsm_build.rfc_analysis_scope must not be empty")
        if not self.fsm_build.source_extensions:
            raise ValueError("fsm_build.source_extensions must not be empty")

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "target_name": self.target_name,
            "spec_paths": [str(path) for path in self.spec_paths],
            "source_root": str(self.source_root),
            "entrypoints": self.entrypoints,
            "build_command": self.build_command,
            "run_command": self.run_command,
            "host": self.host,
            "port": self.port,
            "run_dir": str(self.run_dir),
            "aflnet": self.aflnet.__dict__,
            "monitor_agent": {
                **self.monitor_agent.__dict__,
                "import_dir": str(self.monitor_agent.import_dir) if self.monitor_agent.import_dir else None,
            },
            "transport_harness": self.transport_harness.__dict__,
            # 配置快照会进入 run_dir，必须先脱敏自定义认证 Header。
            "llm": self.llm.to_json_dict(),
            "fsm_build": self.fsm_build.__dict__,
            "path_calibration": self.path_calibration.__dict__,
            "debug": self.debug,
        }


def _resolve_path(base_dir: Path, value: Any) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _parse_cmd(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return shlex.split(value)
    if isinstance(value, list):
        return [str(item) for item in value]
    raise ValueError("aflnet.cmd must be a string or a JSON array")


def _normalize_extension(value: Any) -> str:
    extension = str(value).lower().strip()
    return extension if extension.startswith(".") else f".{extension}"
