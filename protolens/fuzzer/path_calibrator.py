from __future__ import annotations

from collections import defaultdict
import hashlib
import errno
import os
import signal
import socket
import subprocess
import time
from typing import Any

from protolens.config import ProtoLensConfig
from protolens.fsm.fsm_model import PlannedStatePath
from protolens.fuzzer.aflnet_adapter import _run_build_command
from protolens.tools.corpus_encoder import CorpusEncoder


class PathCalibrator:
    """Probe candidate inputs against a fresh target, without inferring hidden FSM states."""

    def calibrate(self, config: ProtoLensConfig, paths: list[PlannedStatePath]) -> dict[str, Any]:
        settings = config.path_calibration
        reason = ""
        if not settings.enabled:
            reason = "path_calibration.enabled is false"
        elif config.aflnet.dry_run:
            reason = "dry-run: no target was executed"
        elif config.protocol.lower() not in {"rtsp", "ftp", "smtp", "http", "daap-http"}:
            reason = "protocol has no response oracle"
        elif config.host not in {"127.0.0.1", "localhost", "::1"}:
            reason = "managed calibration requires a loopback target"
        command: list[str] = []
        if not reason:
            try:
                command = config.aflnet.cmd[config.aflnet.cmd.index("--") + 1:]
            except ValueError:
                reason = "aflnet.cmd requires -- before the target for managed calibration"
            if not reason and (not command or any("@@" in part for part in command)):
                reason = "target command is empty or requires an AFL input-file substitution"
        if not reason:
            reason = _run_build_command(config) or ""
        items = []
        probes = 0
        for path in paths:
            if not path.reachable or not path.messages:
                result = self._unobserved("not_executable", path.reason or "empty candidate")
            elif reason:
                result = self._unobserved("candidate", reason)
            elif probes >= settings.max_probes:
                result = self._unobserved("candidate", "probe budget exhausted")
            else:
                result = self._probe(config, command, path)
                probes += 1
            path.calibration = result
            items.append({"candidate_id": path.candidate_id, "conflict_id": path.conflict_id, **result})
        return {
            "format": "protolens.path_calibration.v1",
            "probe_count": probes,
            "target_start_count": sum(bool(item.get("target_started")) for item in items),
            "connected_count": sum(bool(item.get("connected")) for item in items),
            "status_counts": {status: sum(item["status"] == status for item in items)
                              for status in sorted({item["status"] for item in items})},
            "basis": "per-candidate request/response observations; no edge coverage or hidden-state proof",
            "items": items,
        }

    @staticmethod
    def _unobserved(status: str, reason: str) -> dict[str, Any]:
        return {"status": status, "reason": reason, "accepted_prefix_length": 0,
                "state_verified": False, "target_started": False, "connected": False, "events": []}

    def _probe(self, config: ProtoLensConfig, command: list[str], path: PlannedStatePath) -> dict[str, Any]:
        result = self._unobserved("inconclusive", "")
        started = time.monotonic()
        target = None
        connection = None
        settings = config.path_calibration
        try:
            # Never probe a listener that was already present before this candidate's target.
            if _port_is_listening(config.host, config.port):
                result["reason"] = "target port already occupied; calibration skipped"
                return result
            target = subprocess.Popen(command, cwd=config.source_root, start_new_session=True,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            result["target_started"] = True
            deadline = time.monotonic() + settings.startup_seconds
            while connection is None:
                if target.poll() is not None:
                    raise OSError(f"target exited before accepting a connection: {target.returncode}")
                try:
                    connection = socket.create_connection((config.host, config.port), timeout=min(0.2, settings.timeout_seconds))
                except OSError as exc:
                    if not _is_connection_pending(exc):
                        raise
                    if time.monotonic() >= deadline:
                        raise TimeoutError("target startup timed out")
                    time.sleep(0.02)
            reader = _ResponseReader(connection, settings.timeout_seconds)
            result["connected"] = True
            protocol = config.protocol.lower()
            greeting = None
            if protocol in {"ftp", "smtp"}:
                greeting = reader.read(protocol)
                if greeting != 220:
                    raise ValueError(f"unexpected greeting code: {greeting}")
            encoder = CorpusEncoder()
            response_bindings: dict[str, str] = {}
            bound_messages: list[str] = []
            for index, message in enumerate(path.messages):
                bound_message = _bind_response_values(message, config.protocol, response_bindings)
                bound_messages.append(bound_message)
                payload = encoder._encode_message(bound_message, config.protocol, index + 1)
                event = {"message_index": index, "transition_id": path.transition_ids[index] if index < len(path.transition_ids) else "",
                         "message": message, "bound_message": bound_message,
                         "request_sha256": hashlib.sha256(payload).hexdigest(), "bytes_sent": 0}
                result["events"].append(event)
                if not payload:
                    if protocol != "ftp" or message.strip().upper() != "CONNECT" or index != 0:
                        raise ValueError("candidate contains an unsupported empty request")
                    code = greeting
                else:
                    connection.settimeout(settings.timeout_seconds)
                    connection.sendall(payload)
                    event["bytes_sent"] = len(payload)
                    code = reader.read(protocol)
                event["response_code"] = code
                event["response_headers"] = dict(reader.last_response.get("headers", {}))
                response_bindings.update(_extract_response_bindings(protocol, reader.last_response))
                if response_bindings:
                    event["bindings_after_response"] = dict(response_bindings)
                accepted = 200 <= code < (400 if protocol in {"ftp", "smtp"} else 300)
                event["accepted"] = accepted
                if not accepted:
                    result.update(status="rejected" if code >= 400 else "inconclusive",
                                  reason="response rejected the request" if code >= 400 else "response requires unsupported continuation",
                                  failure_index=index)
                    break
                result["accepted_prefix_length"] = index + 1
            else:
                result.update(status="response_accepted", reason="all encoded requests received positive responses")
            if response_bindings:
                result["response_bindings"] = dict(response_bindings)
                path.messages = bound_messages + path.messages[len(bound_messages):]
        except (OSError, ValueError) as exc:
            result.update(status="inconclusive", reason=str(exc))
        finally:
            if connection is not None:
                connection.close()
            if target is not None:
                result["target_exit_before_cleanup"] = target.poll()
                _stop_target(target)
            result["elapsed_seconds"] = time.monotonic() - started
        return result

    @staticmethod
    def select(paths: list[PlannedStatePath]) -> list[PlannedStatePath]:
        groups: dict[str, list[PlannedStatePath]] = defaultdict(list)
        for path in paths:
            groups[path.conflict_id].append(path)
        def rank(path: PlannedStatePath) -> tuple[int, int, int]:
            status = path.calibration.get("status", "candidate")
            return (int(status == "response_accepted"),
                    int(path.calibration.get("accepted_prefix_length", 0)), -len(path.messages))
        return [max(group, key=rank) for group in groups.values()]


class _ResponseReader:
    """Bounded framed responses; a partial packet must never count as acceptance."""

    def __init__(self, connection: socket.socket, timeout: float) -> None:
        self.connection = connection
        self.timeout = timeout
        self.buffer = b""
        self.deadline = 0.0
        self.received = 0
        self.last_response: dict[str, Any] = {}

    def _more(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("response deadline exceeded")
        self.connection.settimeout(remaining)
        block = self.connection.recv(4096)
        if not block:
            raise ValueError("connection closed before complete response")
        self.received += len(block)
        if self.received > 1_048_576:
            raise ValueError("response exceeds calibration byte limit")
        self.buffer += block

    def _line(self) -> bytes:
        while b"\r\n" not in self.buffer:
            self._more()
        line, self.buffer = self.buffer.split(b"\r\n", 1)
        return line

    def read(self, protocol: str) -> int:
        self.deadline = time.monotonic() + self.timeout
        self.received = len(self.buffer)
        line = self._line()
        if protocol in {"ftp", "smtp"}:
            if len(line) < 4 or not line[:3].isdigit() or line[3:4] not in {b" ", b"-"}:
                raise ValueError("invalid FTP/SMTP reply")
            code = int(line[:3])
            if line[3:4] == b"-":
                while not self._line().startswith(line[:3] + b" "):
                    pass
            self.last_response = {"status_code": code, "headers": {}}
            return code
        parts = line.split(b" ", 2)
        prefix = b"RTSP/" if protocol == "rtsp" else b"HTTP/"
        if len(parts) < 2 or not parts[0].startswith(prefix) or len(parts[1]) != 3 or not parts[1].isdigit():
            raise ValueError("invalid RTSP/HTTP status line")
        headers: dict[bytes, bytes] = {}
        while True:
            header = self._line()
            if not header:
                break
            name, separator, value = header.partition(b":")
            if not separator:
                raise ValueError("invalid response header")
            name = name.strip().lower()
            if name in headers:
                raise ValueError("duplicate response header")
            headers[name] = value.strip()
        if b"transfer-encoding" in headers:
            raise ValueError("transfer-encoded response is not supported by calibration")
        length = int(headers.get(b"content-length", b"0"))
        if length < 0 or length > 1_048_576:
            raise ValueError("invalid response body size")
        while len(self.buffer) < length:
            self._more()
        self.buffer = self.buffer[length:]
        code = int(parts[1])
        self.last_response = {
            "status_code": code,
            "headers": {
                name.decode("latin-1", errors="replace"): value.decode("latin-1", errors="replace")
                for name, value in headers.items()
            },
        }
        return code


def _bind_response_values(message: str, protocol: str, bindings: dict[str, str]) -> str:
    if protocol.lower() != "rtsp" or not bindings.get("session"):
        return message
    upper = message.upper()
    if not any(upper.startswith(method) for method in ("PLAY", "PAUSE", "TEARDOWN", "GET_PARAMETER")):
        return message
    if "--session=" in message or "--omit-session" in message or "--stale-session" in message or "--malformed-guard" in message:
        return message
    return f"{message} --session={bindings['session']}"


def _extract_response_bindings(protocol: str, response: dict[str, Any]) -> dict[str, str]:
    if protocol.lower() != "rtsp":
        return {}
    headers = response.get("headers", {}) if isinstance(response, dict) else {}
    session = str(headers.get("session", "") or headers.get("Session", "")).strip()
    if not session:
        return {}
    return {"session": session.split(";", 1)[0].strip()}


def _stop_target(target: subprocess.Popen) -> None:
    try:
        os.killpg(target.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        target.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    except ChildProcessError:
        return
    if target.poll() is not None:
        return
    try:
        os.killpg(target.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        target.wait(timeout=1)
    except (subprocess.TimeoutExpired, ChildProcessError):
        pass


def _port_is_listening(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError as exc:
        if _is_connection_pending(exc):
            return False
        return False


def _is_connection_pending(exc: OSError) -> bool:
    return isinstance(exc, (ConnectionRefusedError, TimeoutError, socket.timeout)) or exc.errno in {
        errno.ECONNREFUSED,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.ETIMEDOUT,
    }
