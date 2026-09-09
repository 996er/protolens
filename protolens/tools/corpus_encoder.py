from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json

from protolens.fsm.fsm_model import PlannedStatePath, SeedIntent


class CorpusEncoder:
    """把规划路径编码为 AFLNet seed 所需的原始协议请求序列。"""

    def write_corpus(
        self,
        paths: list[PlannedStatePath],
        corpus_dir: Path,
        protocol: str,
        *,
        managed_manifest: Path | None = None,
    ) -> list[Path]:
        corpus_dir.mkdir(parents=True, exist_ok=True)
        if managed_manifest is None:
            # 兼容历史调用：corpus 目录由 ProtoLens 独占时，可以清理旧生成文件。
            for stale in corpus_dir.glob("id_*.raw"):
                stale.unlink()
        else:
            _remove_manifest_entries(corpus_dir, managed_manifest)
        written: list[Path] = []
        for index, path in enumerate(paths):
            if not path.reachable or not path.messages:
                continue
            payload = self._payload_for_path(path, protocol)
            if not payload:
                continue
            out_path = corpus_dir / self.seed_name(index, path)
            out_path.write_bytes(payload)
            written.append(out_path)
        if not written:
            fallback = corpus_dir / "id_000000_fallback.raw"
            fallback.write_bytes(_fallback_request(protocol))
            written.append(fallback)
        if managed_manifest is not None:
            managed_manifest.parent.mkdir(parents=True, exist_ok=True)
            managed_manifest.write_text(
                json.dumps(
                    {"generated_files": [str(path.resolve()) for path in written]},
                    indent=2,
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )
        return written

    def write_seed_intents(
        self,
        intents: list[SeedIntent],
        corpus_dir: Path,
        protocol: str,
        *,
        managed_manifest: Path | None = None,
        seed_manifest_path: Path | None = None,
    ) -> dict[str, Any]:
        corpus_dir.mkdir(parents=True, exist_ok=True)
        if managed_manifest is None:
            for stale in corpus_dir.glob("id_*.raw"):
                stale.unlink()
        else:
            _remove_manifest_entries(corpus_dir, managed_manifest)

        entries: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        entry_by_payload: dict[str, dict[str, Any]] = {}
        generated_files: list[str] = []
        for intent in intents:
            if not intent.reachable or not intent.messages:
                skipped.append({"seed_id": intent.seed_id, "reason": "unreachable or empty messages"})
                continue
            payload, byte_ranges = self._payload_and_ranges(intent.messages, protocol, intent.mutation_points)
            if not payload:
                skipped.append({"seed_id": intent.seed_id, "reason": "protocol encoder produced an empty payload"})
                continue
            payload_sha256 = hashlib.sha256(payload).hexdigest()
            if payload_sha256 in entry_by_payload:
                physical = entry_by_payload[payload_sha256]
                coalesced = physical.setdefault("coalesced_intents", [])
                coalesced.append(_intent_audit_record(intent))
                skipped.append(
                    {
                        "seed_id": intent.seed_id,
                        "conflict_id": intent.conflict_id,
                        "family_id": intent.family_id,
                        "variant": intent.variant,
                        "objective": intent.objective,
                        "reason": "duplicate_payload_sha256",
                        "payload_sha256": payload_sha256,
                        "physical_seed_id": physical.get("seed_id", ""),
                        "physical_seed_file": physical.get("seed_file", ""),
                    }
                )
                continue
            seed_file = f"id_{len(entries):06d}_{intent.seed_id[:72]}.raw"
            out_path = corpus_dir / seed_file
            out_path.write_bytes(payload)
            generated_files.append(str(out_path.resolve()))
            entry = {
                "seed_id": intent.seed_id,
                "seed_file": seed_file,
                "path": str(out_path),
                "conflict_id": intent.conflict_id,
                "family_id": intent.family_id,
                "variant": intent.variant,
                "objective": intent.objective,
                "states": list(intent.states),
                "messages": list(intent.messages),
                "mutation_points": list(intent.mutation_points),
                "byte_ranges": byte_ranges,
                "required_guards": list(intent.required_guards),
                "expected_feedback": list(intent.expected_feedback),
                "priority": int(intent.priority),
                "payload_sha256": payload_sha256,
                "bytes": len(payload),
                "reachable": intent.reachable,
                "reason": intent.reason,
                "source_path_index": intent.source_path_index,
                "source_candidate_id": intent.source_candidate_id,
                "coalesced_intents": [_intent_audit_record(intent)],
            }
            entries.append(entry)
            entry_by_payload[payload_sha256] = entry

        if not entries:
            fallback = corpus_dir / "id_000000_fallback.raw"
            payload = _fallback_request(protocol)
            fallback.write_bytes(payload)
            generated_files.append(str(fallback.resolve()))
            entries.append(
                {
                    "seed_id": "fallback",
                    "seed_file": fallback.name,
                    "path": str(fallback),
                    "conflict_id": "fallback",
                    "family_id": "fallback",
                    "variant": "fallback_minimal_request",
                    "objective": "Keep AFLNet startable when no reachable seed intent exists.",
                    "states": [],
                    "messages": [],
                    "mutation_points": [],
                    "byte_ranges": [],
                    "required_guards": [],
                    "expected_feedback": ["campaign_startup"],
                    "priority": 100,
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "bytes": len(payload),
                    "reachable": True,
                    "reason": "no seed intents were encodable",
                    "source_path_index": None,
                    "source_candidate_id": "",
                    "coalesced_intents": [],
                }
            )

        manifest = {
            "format": "protolens.seed_manifest.v2",
            "protocol": protocol,
            "seed_count": len(entries),
            "intent_count": len([item for item in intents if item.reachable and item.messages]),
            "deduplicated_count": len([item for item in skipped if item.get("reason") == "duplicate_payload_sha256"]),
            "skipped": skipped,
            "entries": entries,
        }
        if managed_manifest is not None:
            managed_manifest.parent.mkdir(parents=True, exist_ok=True)
            managed_manifest.write_text(
                json.dumps({"generated_files": generated_files}, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        if seed_manifest_path is not None:
            seed_manifest_path.parent.mkdir(parents=True, exist_ok=True)
            seed_manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return manifest

    def write_dictionary(
        self,
        paths: list[PlannedStatePath] | list[SeedIntent],
        dictionary_path: Path,
        *,
        preserve_existing: bool = False,
    ) -> Path:
        dictionary_path.parent.mkdir(parents=True, exist_ok=True)
        tokens: set[str] = set()
        for path in paths:
            for message in path.messages:
                head = message.split()[0].upper() if message.split() else message.upper()
                if head:
                    tokens.add(head)
        tokens.update({"Session:", "CSeq:", "Content-Length:", "Transport:"})
        lines: list[str] = []
        if preserve_existing and dictionary_path.is_file():
            lines.extend(
                line
                for line in dictionary_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if not line.startswith("protolens_tok_")
            )
        prefix = "protolens_tok" if preserve_existing else "tok"
        lines.extend(
            f'{prefix}_{index}="{_escape(token)}"'
            for index, token in enumerate(sorted(tokens))
        )
        dictionary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return dictionary_path

    def write_queue_schedule(
        self,
        paths: list[PlannedStatePath],
        corpus_dir: Path,
        artifact_dir: Path,
        protocol: str,
    ) -> dict[str, object]:
        """Write an auditable mutation-point schedule and a compact TSV for AFLNet."""

        corpus_dir.mkdir(parents=True, exist_ok=True)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        entries: list[dict[str, object]] = []
        for index, path in enumerate(paths):
            if not path.reachable or not path.messages or not self._payload_for_path(path, protocol):
                continue
            mutation_points = sorted({item for item in path.mutation_points if item >= 0})
            weight = _queue_weight(path, mutation_points)
            entries.append(
                {
                    "seed_file": self.seed_name(index, path),
                    "conflict_id": path.conflict_id,
                    "weight": weight,
                    "mutation_points": mutation_points,
                    "messages": list(path.messages),
                    "required_guards": list(path.required_guards),
                    "reason": "weighted from mutation_points and required guards",
                }
            )
        if not entries:
            entries.append(
                {
                    "seed_file": "id_000000_fallback.raw",
                    "conflict_id": "fallback",
                    "weight": 100,
                    "mutation_points": [],
                    "messages": [],
                    "required_guards": [],
                    "reason": "fallback seed has no planned mutation points",
                }
            )
        json_path = artifact_dir / "aflnet_queue_weights.json"
        tsv_path = artifact_dir / "aflnet_queue_weights.tsv"
        json_path.write_text(json.dumps({"entries": entries}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tsv_path.write_text(
            "\n".join(f"{entry['seed_file']}\t{entry['weight']}" for entry in entries) + "\n",
            encoding="utf-8",
        )
        return {"json_path": str(json_path), "tsv_path": str(tsv_path), "entries": entries}

    def write_seed_queue_schedule(
        self,
        seed_manifest: dict[str, Any],
        artifact_dir: Path,
        *,
        replanning_plan: dict[str, object] | None = None,
    ) -> dict[str, object]:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        entries: list[dict[str, object]] = []
        replanned = _replanned_seed_scores(replanning_plan)
        for seed in seed_manifest.get("entries", []):
            if not isinstance(seed, dict):
                continue
            base_weight = _seed_weight(seed)
            replanned_score = replanned.get(str(seed.get("seed_id", "")))
            weight = _merge_replanned_weight(base_weight, replanned_score)
            entries.append(
                {
                    "seed_file": seed["seed_file"],
                    "seed_id": seed["seed_id"],
                    "conflict_id": seed["conflict_id"],
                    "family_id": seed.get("family_id", ""),
                    "variant": seed.get("variant", ""),
                    "weight": weight,
                    "base_weight": base_weight,
                    "replanned_score": replanned_score,
                    "mutation_points": list(seed.get("mutation_points", [])),
                    "byte_ranges": list(seed.get("byte_ranges", [])),
                    "messages": list(seed.get("messages", [])),
                    "required_guards": list(seed.get("required_guards", [])),
                    "coalesced_intents": list(seed.get("coalesced_intents", [])),
                    "reason": (
                        "weighted from seed intent priority, variant, guards, mutation byte ranges, "
                        "and previous closed-loop replanning score when present"
                    ),
                }
            )
        if not entries:
            entries.append(
                {
                    "seed_file": "id_000000_fallback.raw",
                    "seed_id": "fallback",
                    "conflict_id": "fallback",
                    "family_id": "fallback",
                    "variant": "fallback_minimal_request",
                    "weight": 100,
                    "mutation_points": [],
                    "byte_ranges": [],
                    "messages": [],
                    "required_guards": [],
                    "reason": "fallback seed has no planned mutation points",
                }
            )
        json_path = artifact_dir / "aflnet_queue_weights.json"
        tsv_path = artifact_dir / "aflnet_queue_weights.tsv"
        json_path.write_text(json.dumps({"entries": entries}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tsv_path.write_text(
            "\n".join(f"{entry['seed_file']}\t{entry['weight']}" for entry in entries) + "\n",
            encoding="utf-8",
        )
        return {"json_path": str(json_path), "tsv_path": str(tsv_path), "entries": entries}

    def seed_name(self, index: int, path: PlannedStatePath) -> str:
        return f"id_{index:06d}_{path.conflict_id[:48]}.raw"

    def payload_for_path(self, path: PlannedStatePath, protocol: str) -> bytes:
        return self._payload_for_path(path, protocol)

    def _encode_message(self, message: str, protocol: str, sequence: int) -> bytes:
        # AFLNet 自己按 CRLF/协议边界切分 seed，不能添加 replay 工具使用的长度前缀。
        request = _message_to_request(message, protocol, sequence)
        return request.encode("utf-8", errors="replace")

    def _payload_for_path(self, path: PlannedStatePath, protocol: str) -> bytes:
        payload, _ = self._payload_and_ranges(path.messages, protocol, path.mutation_points)
        return payload

    def _payload_and_ranges(
        self,
        messages: list[str],
        protocol: str,
        mutation_points: list[int],
    ) -> tuple[bytes, list[dict[str, Any]]]:
        chunks: list[bytes] = []
        byte_ranges: list[dict[str, Any]] = []
        offset = 0
        mutation_set = {item for item in mutation_points if item >= 0}
        for index, message in enumerate(messages):
            request = _message_to_request(message, protocol, sequence=index + 1)
            encoded = request.encode("utf-8", errors="replace")
            chunks.append(encoded)
            byte_ranges.extend(_mutation_byte_ranges(request, offset, index, message, mutation_set))
            offset += len(encoded)
        return b"".join(chunks), byte_ranges


def _message_to_request(message: str, protocol: str, sequence: int = 1) -> str:
    method = _method(message)
    flags = _directives(message)
    directives = _directive_values(message)
    argument = _argument_text(message)
    if protocol.lower() == "rtsp":
        target = directives.get("target") or directives.get("uri") or "rtsp://127.0.0.1:8554/protolens"
        if argument and (argument.startswith("rtsp://") or argument.startswith("/")):
            target = argument if argument.startswith("rtsp://") else f"rtsp://127.0.0.1:8554{argument}"
        headers = ""
        if method == "SETUP":
            if "no-transport" not in flags:
                value = directives.get("transport") or "RTP/AVP/TCP;unicast;interleaved=0-1"
                if "malformed-guard" in flags:
                    value = "RTP/AVP/TCP;interleaved=not-a-range"
                headers = f"Transport: {value}\r\n"
        elif method in {"PLAY", "PAUSE", "TEARDOWN", "GET_PARAMETER"}:
            if "omit-session" not in flags:
                value = directives.get("session") or "00000001"
                if "stale-session" in flags:
                    value = "DEAD0001"
                elif "malformed-guard" in flags:
                    value = "!!!!"
                headers = f"Session: {value}\r\n"
        return (
            f"{method} {target} RTSP/1.0\r\n"
            f"CSeq: {sequence}\r\n"
            "User-Agent: ProtoLens\r\n"
            f"{headers}"
            "\r\n"
        )
    if protocol.lower() == "ftp":
        return _ftp_command(message)
    if protocol.lower() == "smtp":
        arguments = {"EHLO": "localhost", "MAIL": "FROM:<fuzz@example.com>", "RCPT": "TO:<root@example.com>"}
        if argument:
            arguments = {**arguments, method: argument}
        if "malformed" in flags:
            arguments = {**arguments, method: "%%%PROTO%%%"}
        return f"{method} {arguments.get(method, '')}".rstrip() + "\r\n"
    if protocol.lower() in {"http", "daap-http"}:
        target = directives.get("path") or directives.get("target") or (argument if argument.startswith("/") else "/protolens")
        host = directives.get("host") or "127.0.0.1"
        body = directives.get("body", "")
        headers = f"Host: {host}\r\nConnection: keep-alive\r\n"
        if body:
            headers += f"Content-Length: {len(body.encode('utf-8', errors='replace'))}\r\n"
        return f"{method} {target} HTTP/1.1\r\n{headers}\r\n{body}"
    return f"{message}\r\n"


def _ftp_command(message: str) -> str:
    method = _method(message)
    flags = _directives(message)
    argument = _argument_text(message)
    # CONNECT 表示服务端 greeting，不是客户端可发送的 FTP 命令。
    if method == "CONNECT":
        return ""
    arguments = {
        "USER": "anonymous",
        "PASS": "protolens@example.com",
        "AUTH": "TLS",
        "PBSZ": "0",
        "PROT": "P",
        "CWD": "/",
        "TYPE": "I",
        "PORT": "127,0,0,1,7,138",
        "RETR": "protolens.txt",
        "STOR": "protolens.txt",
        "RNFR": "protolens.txt",
        "RNTO": "protolens-renamed.txt",
        "DELE": "protolens.txt",
        "MKD": "protolens-dir",
        "RMD": "protolens-dir",
    }
    if argument:
        arguments = {**arguments, method: argument}
    if "bad-argument" in flags and method in {"USER", "PASS"}:
        arguments = {**arguments, method: "invalid-protolens-credential"}
    if "malformed" in flags:
        arguments = {**arguments, method: "%%%PROTO%%%"}
    return f"{method} {arguments.get(method, '')}".rstrip() + "\r\n"


def _fallback_request(protocol: str) -> bytes:
    defaults = {
        "rtsp": "OPTIONS",
        "ftp": "USER",
        "smtp": "EHLO",
        "http": "GET",
        "daap-http": "GET",
    }
    message = defaults.get(protocol.lower(), "PROTOLENS")
    return _message_to_request(message, protocol).encode("utf-8")


def _queue_weight(path: PlannedStatePath, mutation_points: list[int]) -> int:
    weight = 100
    if mutation_points:
        weight += 35 * len(mutation_points)
    if path.required_guards:
        weight += 20 * len(path.required_guards)
    if len(path.messages) >= 3:
        weight += 15
    return max(50, min(400, weight))


def _seed_weight(seed: dict[str, Any]) -> int:
    weight = int(seed.get("priority") or 100)
    variant = str(seed.get("variant", ""))
    if variant in {"missing_guard_material", "stale_session_value", "malformed_guard_field"}:
        weight += 60
    elif variant in {"direct_divergent_trigger", "wrong_message_order"}:
        weight += 35
    if seed.get("byte_ranges"):
        weight += 30
    if seed.get("required_guards"):
        weight += 15 * len(seed.get("required_guards", []))
    return max(50, min(600, weight))


def _replanned_seed_scores(replanning_plan: dict[str, object] | None) -> dict[str, int]:
    if not isinstance(replanning_plan, dict):
        return {}
    scores: dict[str, int] = {}
    for item in replanning_plan.get("next_round_seed_priorities", []):
        if not isinstance(item, dict):
            continue
        seed_id = str(item.get("seed_id", "")).strip()
        if not seed_id:
            continue
        try:
            scores[seed_id] = int(item.get("score", 0))
        except (TypeError, ValueError):
            continue
    return scores


def _merge_replanned_weight(base_weight: int, replanned_score: int | None) -> int:
    if replanned_score is None:
        return base_weight
    return max(50, min(800, int(round(base_weight * 0.55 + replanned_score * 0.45))))


def _method(message: str) -> str:
    for token in str(message).split():
        if not token.startswith("--"):
            return token.upper()
    return str(message).upper()


def _directives(message: str) -> set[str]:
    return {token[2:].split("=", 1)[0].lower() for token in str(message).split() if token.startswith("--") and len(token) > 2}


def _directive_values(message: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for token in str(message).split():
        if not token.startswith("--") or "=" not in token:
            continue
        key, value = token[2:].split("=", 1)
        if key:
            values[key.lower()] = value
    return values


def _argument_text(message: str) -> str:
    parts = [token for token in str(message).split() if not token.startswith("--")]
    return " ".join(parts[1:]).strip() if len(parts) > 1 else ""


def _intent_audit_record(intent: SeedIntent) -> dict[str, Any]:
    return {
        "seed_id": intent.seed_id,
        "conflict_id": intent.conflict_id,
        "family_id": intent.family_id,
        "variant": intent.variant,
        "objective": intent.objective,
        "states": list(intent.states),
        "messages": list(intent.messages),
        "mutation_points": list(intent.mutation_points),
        "required_guards": list(intent.required_guards),
        "expected_feedback": list(intent.expected_feedback),
        "priority": int(intent.priority),
        "source_path_index": intent.source_path_index,
        "source_candidate_id": intent.source_candidate_id,
    }


def _mutation_byte_ranges(
    request: str,
    base_offset: int,
    message_index: int,
    message: str,
    mutation_points: set[int],
) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    if message_index in mutation_points:
        ranges.append(
            {
                "message_index": message_index,
                "field": "message",
                "start": base_offset,
                "end": base_offset + len(request.encode("utf-8", errors="replace")),
                "reason": "planned mutation point",
            }
        )
    for field in ("Session", "Transport", "CSeq", "Authorization", "Content-Length"):
        marker = f"{field}:"
        start = request.find(marker)
        if start < 0:
            continue
        line_end = request.find("\r\n", start)
        if line_end < 0:
            line_end = len(request)
        value_start = start + len(marker)
        while value_start < line_end and request[value_start] == " ":
            value_start += 1
        ranges.append(
            {
                "message_index": message_index,
                "field": field,
                "start": base_offset + value_start,
                "end": base_offset + line_end,
                "reason": "guard-bearing protocol field",
            }
        )
    if "malformed" in _directives(message) or "malformed-guard" in _directives(message):
        ranges.append(
            {
                "message_index": message_index,
                "field": "malformed_directive",
                "start": base_offset,
                "end": base_offset + len(request.encode("utf-8", errors="replace")),
                "reason": "seed intent requests malformed guard material",
            }
        )
    return _dedupe_ranges(ranges)


def _dedupe_ranges(ranges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[int, int, str]] = set()
    for item in ranges:
        key = (int(item["start"]), int(item["end"]), str(item["field"]))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _escape(token: str) -> str:
    return token.replace("\\", "\\\\").replace('"', '\\"')


def _remove_manifest_entries(corpus_dir: Path, manifest_path: Path) -> None:
    if not manifest_path.is_file():
        _remove_known_protolens_generated_files(corpus_dir)
        return
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    root = corpus_dir.resolve()
    for raw_path in data.get("generated_files", []):
        path = Path(str(raw_path)).expanduser()
        if not path.is_absolute():
            path = root / path
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            resolved.unlink()
    _remove_known_protolens_generated_files(corpus_dir)


def _remove_known_protolens_generated_files(corpus_dir: Path) -> None:
    markers = (
        "_seed__",
        "_fsm_divergence__",
        "_asr_conflict__",
        "_cross_layer_contamination__",
        "_unvalidated_hypothesis__",
        "_fallback.raw",
    )
    for path in corpus_dir.glob("id_*.raw"):
        if path.is_file() and any(marker in path.name for marker in markers):
            path.unlink()
