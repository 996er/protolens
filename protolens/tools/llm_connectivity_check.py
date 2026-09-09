from __future__ import annotations

from argparse import ArgumentParser, Namespace
from dataclasses import replace
from pathlib import Path
from typing import Any
import json
import os
import sys
import time

from protolens.agents.monitor_agent import MONITOR_ANALYSIS_SCHEMA
from protolens.config import LLMConfig, ProtoLensConfig
from protolens.utils.llm_client import LLMClient


SIMPLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok", "mode"],
    "properties": {
        "ok": {"type": "boolean"},
        "mode": {"type": "string"},
    },
}


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    llm_config = _load_llm_config(args)
    report = {
        "format": "protolens.llm_connectivity_check.v1",
        "config": _config_snapshot(llm_config),
        "checks": [],
    }

    checks: list[dict[str, Any]] = report["checks"]
    checks.append(
        _run_check(
            "plain_chat_no_response_format",
            replace(llm_config, response_format="none"),
            system="Return JSON only.",
            user='Return exactly {"ok":true,"mode":"plain"}.',
            expected_mode="plain",
        )
    )
    checks.append(
        _run_check(
            "json_object_chat",
            replace(llm_config, response_format="json_object"),
            system="Return JSON only.",
            user='Return exactly {"ok":true,"mode":"json_object"}.',
            expected_mode="json_object",
        )
    )
    checks.append(
        _run_check(
            "json_schema_chat",
            replace(llm_config, response_format="json_schema"),
            system="Return JSON only.",
            user='Return exactly {"ok":true,"mode":"json_schema"}.',
            response_schema=SIMPLE_SCHEMA,
            schema_name="protolens_llm_connectivity",
            expected_mode="json_schema",
        )
    )
    checks.append(
        _run_check(
            "monitor_agent_schema_current_config",
            llm_config,
            system=(
                "You are ProtoLens MonitorAgent. Return strict JSON only. "
                "Do not claim real coverage was achieved."
            ),
            user=json.dumps(
                {
                    "task": "Connectivity check for MonitorAgent seed-candidate schema.",
                    "protocol": "ftp",
                    "dynamic_feedback": {
                        "stats_present": True,
                        "fuzzer_stats": {
                            "execs_done": "1000",
                            "execs_per_sec": "10.0",
                            "paths_total": "4",
                            "bitmap_cvg": "0.50%",
                        },
                        "health_signals": ["connectivity_test"],
                    },
                    "planned_paths": [
                        {
                            "conflict_id": "connectivity_conflict",
                            "states": ["START", "AUTHENTICATED", "DATA"],
                            "messages": ["USER", "PASS", "TYPE", "PORT", "RETR"],
                            "required_guards": ["authenticated data connection"],
                            "mutation_points": [4],
                            "reachable": True,
                        }
                    ],
                    "required_output": {
                        "bottleneck_summary": "short explanation",
                        "seed_candidates": [
                            {
                                "conflict_id": "connectivity_conflict",
                                "messages": ["USER", "PASS", "TYPE", "PORT", "RETR"],
                                "rationale": "why this may reach a guarded branch",
                                "expected_new_coverage": "expected branch, not confirmed coverage",
                            }
                        ],
                    },
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            response_schema=MONITOR_ANALYSIS_SCHEMA,
            schema_name="protolens_monitor_seed_candidates",
            validate_monitor=True,
        )
    )
    checks.append(
        _run_check(
            "monitor_agent_json_object_fallback",
            replace(llm_config, response_format="json_object"),
            system=(
                "You are ProtoLens MonitorAgent. Return strict JSON only. "
                "Do not claim real coverage was achieved."
            ),
            user='Return exactly {"bottleneck_summary":"connectivity ok","seed_candidates":[{"conflict_id":"connectivity_conflict","messages":["USER","PASS","TYPE","PORT","RETR"],"rationale":"schema-free json_object fallback","expected_new_coverage":"candidate only"}]}.',
            response_schema=MONITOR_ANALYSIS_SCHEMA,
            schema_name="protolens_monitor_seed_candidates",
            validate_monitor=True,
        )
    )

    monitor_check = _find_check(checks, "monitor_agent_schema_current_config")
    json_object_check = _find_check(checks, "monitor_agent_json_object_fallback")
    report["summary"] = _summary(monitor_check, json_object_check, llm_config)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["summary"]["monitor_agent_current_config_ready"] else 1


def _build_parser() -> ArgumentParser:
    parser = ArgumentParser(description="Test ProtoLens LLM connectivity and MonitorAgent schema support")
    parser.add_argument("--config", help="ProtoLens config.json to read llm settings from")
    parser.add_argument("--provider", help="override llm.provider")
    parser.add_argument("--model", help="override llm.model")
    parser.add_argument("--base-url", help="override llm.base_url")
    parser.add_argument("--api-key-env", help="override llm.api_key_env")
    parser.add_argument("--response-format", choices=["auto", "json_object", "json_schema", "none"], help="override llm.response_format")
    parser.add_argument("--timeout-seconds", type=int, help="override llm.timeout_seconds")
    parser.add_argument("--max-tokens", type=int, default=2000, help="max tokens used by this connectivity check")
    parser.add_argument("--retries", type=int, default=0, help="retries used by this connectivity check")
    return parser


def _load_llm_config(args: Namespace) -> LLMConfig:
    if args.config:
        llm_config = ProtoLensConfig.load(Path(args.config)).llm
    else:
        llm_config = LLMConfig(provider="openai-compatible", model=os.environ.get("OPENAI_MODEL", ""))
    if args.provider:
        llm_config = replace(llm_config, provider=args.provider)
    if args.model:
        llm_config = replace(llm_config, model=args.model)
    if args.base_url:
        llm_config = replace(llm_config, base_url=args.base_url)
    if args.api_key_env:
        llm_config = replace(llm_config, api_key_env=args.api_key_env)
    if args.response_format:
        llm_config = replace(llm_config, response_format=args.response_format)
    if args.timeout_seconds:
        llm_config = replace(llm_config, timeout_seconds=args.timeout_seconds)
    return replace(llm_config, max_tokens=args.max_tokens, retries=args.retries)


def _run_check(
    name: str,
    llm_config: LLMConfig,
    *,
    system: str,
    user: str,
    response_schema: dict[str, Any] | None = None,
    schema_name: str = "protolens_llm_connectivity",
    expected_mode: str | None = None,
    validate_monitor: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    client = LLMClient.from_config(llm_config)
    result: dict[str, Any] = {
        "name": name,
        "provider": client.provider,
        "model": client.model,
        "base_url": client.base_url,
        "response_format": client.response_format,
        "schema_name": schema_name if response_schema else None,
    }
    try:
        response = client.chat_json(
            system=system,
            user=user,
            response_schema=response_schema,
            schema_name=schema_name,
        )
        data = _json_object(response.text)
        if expected_mode is not None and data.get("mode") != expected_mode:
            raise ValueError(f"expected mode={expected_mode!r}, got {data.get('mode')!r}")
        if validate_monitor:
            _validate_monitor_object(data)
        result.update(
            {
                "ok": True,
                "latency_seconds": round(time.monotonic() - started, 3),
                "response_text": response.text[:1000],
                "parsed": data,
            }
        )
    except Exception as exc:
        result.update(
            {
                "ok": False,
                "latency_seconds": round(time.monotonic() - started, 3),
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
    return result


def _json_object(text: str) -> dict[str, Any]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("LLM response is not a JSON object")
    return data


def _validate_monitor_object(data: dict[str, Any]) -> None:
    if not isinstance(data.get("bottleneck_summary"), str) or not data["bottleneck_summary"].strip():
        raise ValueError("missing bottleneck_summary")
    candidates = data.get("seed_candidates")
    if not isinstance(candidates, list):
        raise ValueError("seed_candidates must be an array")
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("seed candidate must be an object")
        for key in ("conflict_id", "messages", "rationale", "expected_new_coverage"):
            if key not in candidate:
                raise ValueError(f"seed candidate missing {key}")
        if not isinstance(candidate["messages"], list) or not candidate["messages"]:
            raise ValueError("seed candidate messages must be a non-empty array")


def _find_check(checks: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for check in checks:
        if check["name"] == name:
            return check
    raise ValueError(f"internal error: missing check {name}")


def _summary(
    monitor_check: dict[str, Any],
    json_object_check: dict[str, Any],
    llm_config: LLMConfig,
) -> dict[str, Any]:
    hints: list[str] = []
    if not os.environ.get(llm_config.api_key_env, "") and not _is_local_url(llm_config.base_url or ""):
        hints.append(f"set {llm_config.api_key_env} or use a local base_url")
    if not monitor_check.get("ok") and json_object_check.get("ok"):
        hints.append("current provider likely rejects json_schema; set llm.response_format to json_object for MonitorAgent")
    if not monitor_check.get("ok") and "400" in str(monitor_check.get("error", "")):
        hints.append("inspect the HTTP 400 body above; common causes are unsupported response_format or wrong base_url/model")
    return {
        "monitor_agent_current_config_ready": bool(monitor_check.get("ok")),
        "json_object_fallback_ready": bool(json_object_check.get("ok")),
        "recommended_actions": hints,
    }


def _config_snapshot(llm_config: LLMConfig) -> dict[str, Any]:
    return {
        "provider": llm_config.provider,
        "model": llm_config.model,
        "base_url": llm_config.base_url,
        "api_key_env": llm_config.api_key_env,
        "api_key_present": bool(os.environ.get(llm_config.api_key_env, "")),
        "response_format": llm_config.response_format,
        "timeout_seconds": llm_config.timeout_seconds,
        "max_tokens": llm_config.max_tokens,
        "retries": llm_config.retries,
    }


def _is_local_url(url: str) -> bool:
    return url.startswith("http://127.0.0.1") or url.startswith("http://localhost") or url.startswith("http://0.0.0.0")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
