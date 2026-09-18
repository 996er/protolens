from __future__ import annotations

from dataclasses import dataclass
import re
import socket
import ssl
import struct
from typing import Any

from protolens.config import ProtoLensConfig
from protolens.tools.corpus_encoder import CorpusEncoder


@dataclass
class _Session:
    sock: socket.socket | ssl.SSLSocket | None = None
    data_sock: socket.socket | None = None
    data_listener: socket.socket | None = None
    sequence: int = 1


class TransportAwareHarness:
    """Execute cross-layer transport actions that cannot be encoded as AFLNet seeds."""

    def execute(self, config: ProtoLensConfig, manifest: dict[str, Any]) -> dict[str, Any]:
        actions = list(manifest.get("actions", []))
        if not config.transport_harness.enabled:
            return {
                "format": "protolens.transport_harness_result.v1",
                "executed": False,
                "reason": "transport_harness.enabled is false",
                "items": [],
            }
        if not actions:
            return {
                "format": "protolens.transport_harness_result.v1",
                "executed": False,
                "reason": "no transport-only actions were present",
                "items": [],
            }

        items: list[dict[str, Any]] = []
        for action in actions[: config.transport_harness.max_actions]:
            items.append(self._execute_action(config, action))
        return {
            "format": "protolens.transport_harness_result.v1",
            "executed": True,
            "items": items,
        }

    def _execute_action(self, config: ProtoLensConfig, action: dict[str, Any]) -> dict[str, Any]:
        session = _Session()
        events: list[dict[str, Any]] = []
        try:
            session.sock = self._connect(config)
            events.append({"event": "connect", "supported": True})
            for message in action.get("messages", []):
                event = self._apply_message(config, session, str(message))
                events.append(event)
                if event.get("closed"):
                    session.sock = None
            return {
                "conflict_id": action.get("conflict_id", ""),
                "supported": all(bool(event.get("supported", True)) for event in events),
                "events": events,
            }
        except OSError as exc:
            return {
                "conflict_id": action.get("conflict_id", ""),
                "supported": True,
                "events": events,
                "error": str(exc),
            }
        finally:
            _close(session.data_sock)
            _close(session.data_listener)
            _close(session.sock)

    def _connect(self, config: ProtoLensConfig) -> socket.socket | ssl.SSLSocket:
        raw_sock = socket.create_connection(
            (config.host, config.port),
            timeout=config.transport_harness.timeout_seconds,
        )
        raw_sock.settimeout(config.transport_harness.timeout_seconds)
        if not config.transport_harness.use_tls:
            return raw_sock
        context = ssl.create_default_context()
        if not config.transport_harness.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context.wrap_socket(raw_sock, server_hostname=config.host)

    def _apply_message(self, config: ProtoLensConfig, session: _Session, message: str) -> dict[str, Any]:
        upper = message.upper()
        if "TLS_RENEGOTIATION" in upper and "RESET" not in upper:
            return {
                "event": "tls_renegotiation",
                "supported": False,
                "reason": "Python ssl does not expose general-purpose TLS renegotiation",
            }
        if "RESET" in upper:
            return self._reset(config, session)
        if "HALF_CLOSE" in upper:
            return self._half_close(session)
        if "RECONNECT" in upper:
            _close(session.sock)
            session.sock = self._connect(config)
            return {"event": "reconnect", "supported": True}
        if config.protocol.lower() == "ftp":
            return self._send_ftp_message(config, session, message)
        return self._send_protocol_message(config, session, message)

    def _send_ftp_message(self, config: ProtoLensConfig, session: _Session, message: str) -> dict[str, Any]:
        method = _ftp_method(message)
        if method == "PORT":
            setup = self._setup_ftp_active_data_listener(config, session)
            response = self._send_control_bytes(config, session, f"PORT {setup['argument']}\r\n".encode("ascii"))
            return {"event": "ftp_port", "supported": True, **setup, **response}
        if method == "PASV":
            response = self._send_control_bytes(config, session, b"PASV\r\n")
            endpoint = _parse_ftp_pasv_endpoint(response.get("response_preview", ""))
            if not endpoint:
                return {
                    "event": "ftp_pasv",
                    "supported": True,
                    **response,
                    "data_channel": "passive",
                    "data_connected": False,
                    "reason": "server response did not include a parseable PASV endpoint",
                }
            _close(session.data_sock)
            session.data_sock = socket.create_connection(endpoint, timeout=config.transport_harness.timeout_seconds)
            session.data_sock.settimeout(config.transport_harness.timeout_seconds)
            return {
                "event": "ftp_pasv",
                "supported": True,
                **response,
                "data_channel": "passive",
                "data_connected": True,
                "data_endpoint": f"{endpoint[0]}:{endpoint[1]}",
            }
        if method in _FTP_DATA_TRANSFER_COMMANDS:
            setup_event: dict[str, Any] | None = None
            if session.data_sock is None and session.data_listener is None:
                setup = self._setup_ftp_active_data_listener(config, session)
                setup_response = self._send_control_bytes(config, session, f"PORT {setup['argument']}\r\n".encode("ascii"))
                setup_event = {"event": "ftp_auto_port", **setup, **setup_response}
            payload = CorpusEncoder()._encode_message(message, config.protocol, session.sequence)
            session.sequence += 1
            response = self._send_control_bytes(config, session, payload) if payload else {"bytes_sent": 0, "response_bytes": 0, "response_preview": ""}
            data_result = self._exercise_ftp_data_socket(config, session, method)
            final_response = _recv_available(session.sock) if session.sock is not None else b""
            result: dict[str, Any] = {
                "event": "ftp_transfer",
                "supported": True,
                "message": message,
                "method": method,
                **response,
                "data_result": data_result,
                "final_response_bytes": len(final_response),
                "final_response_preview": final_response[:200].decode("utf-8", errors="replace"),
            }
            if setup_event is not None:
                result["setup"] = setup_event
            return result
        return self._send_protocol_message(config, session, message)

    def _send_protocol_message(self, config: ProtoLensConfig, session: _Session, message: str) -> dict[str, Any]:
        if session.sock is None:
            session.sock = self._connect(config)
        payload = CorpusEncoder()._encode_message(message, config.protocol, session.sequence)
        session.sequence += 1
        if not payload:
            return {"event": "send", "supported": True, "message": message, "bytes_sent": 0}
        response = self._send_control_bytes(config, session, payload)
        return {
            "event": "send",
            "supported": True,
            "message": message,
            **response,
        }

    def _send_control_bytes(self, config: ProtoLensConfig, session: _Session, payload: bytes) -> dict[str, Any]:
        if session.sock is None:
            session.sock = self._connect(config)
        session.sock.sendall(payload)
        response = _recv_available(session.sock)
        return {
            "bytes_sent": len(payload),
            "response_bytes": len(response),
            "response_preview": response[:200].decode("utf-8", errors="replace"),
        }

    def _setup_ftp_active_data_listener(self, config: ProtoLensConfig, session: _Session) -> dict[str, Any]:
        _close(session.data_sock)
        _close(session.data_listener)
        host = _advertised_local_host(session.sock, config.host)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(config.transport_harness.timeout_seconds)
        listener.bind((host, 0))
        listener.listen(1)
        session.data_listener = listener
        bound_host, bound_port = listener.getsockname()
        argument = _ftp_port_argument(bound_host, int(bound_port))
        return {
            "data_channel": "active",
            "listener": f"{bound_host}:{bound_port}",
            "argument": argument,
        }

    def _exercise_ftp_data_socket(self, config: ProtoLensConfig, session: _Session, method: str) -> dict[str, Any]:
        data_sock = session.data_sock
        accepted = False
        if data_sock is None and session.data_listener is not None:
            try:
                data_sock, peer = session.data_listener.accept()
                data_sock.settimeout(config.transport_harness.timeout_seconds)
                accepted = True
            except OSError as exc:
                _close(session.data_listener)
                session.data_listener = None
                return {"connected": False, "error": str(exc)}
        if data_sock is None:
            return {"connected": False, "reason": "no FTP data socket was available"}
        try:
            if method in {"STOR", "APPE", "STOU"}:
                payload = b"ProtoLens FTP data channel probe\r\n"
                data_sock.sendall(payload)
                return {"connected": True, "accepted_active": accepted, "bytes_sent": len(payload), "bytes_received": 0}
            data = _recv_available(data_sock, size=65536)
            return {"connected": True, "accepted_active": accepted, "bytes_sent": 0, "bytes_received": len(data)}
        finally:
            _close(data_sock)
            _close(session.data_listener)
            session.data_sock = None
            session.data_listener = None

    def _half_close(self, session: _Session) -> dict[str, Any]:
        if session.sock is None:
            return {"event": "half_close", "supported": True, "reason": "connection already closed"}
        session.sock.shutdown(socket.SHUT_WR)
        response = _recv_available(session.sock)
        return {
            "event": "half_close",
            "supported": True,
            "response_bytes": len(response),
            "response_preview": response[:200].decode("utf-8", errors="replace"),
        }

    def _reset(self, config: ProtoLensConfig, session: _Session) -> dict[str, Any]:
        if session.sock is None:
            session.sock = self._connect(config)
        if isinstance(session.sock, ssl.SSLSocket):
            _close(session.sock)
            return {
                "event": "tcp_reset",
                "supported": False,
                "closed": True,
                "reason": "cannot force TCP RST through an ssl.SSLSocket without raw socket ownership",
            }
        session.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        session.sock.close()
        return {"event": "tcp_reset", "supported": True, "closed": True}


def _recv_available(sock: socket.socket | ssl.SSLSocket, size: int = 4096) -> bytes:
    try:
        return sock.recv(size)
    except (socket.timeout, BlockingIOError, ssl.SSLWantReadError):
        return b""


def _close(sock: socket.socket | ssl.SSLSocket | None) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


_FTP_DATA_TRANSFER_COMMANDS = {"LIST", "NLST", "MLSD", "MLST", "RETR", "STOR", "APPE", "STOU"}


def _ftp_method(message: str) -> str:
    text = str(message).strip()
    if text.lower().startswith(("raw:", "raw-b64:", "base64:")):
        return ""
    return text.split()[0].upper().rstrip(":") if text.split() else ""


def _parse_ftp_pasv_endpoint(response: str) -> tuple[str, int] | None:
    match = re.search(r"\((\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})\)", response)
    if not match:
        return None
    nums = [int(item) for item in match.groups()]
    if any(item < 0 or item > 255 for item in nums):
        return None
    return ".".join(str(item) for item in nums[:4]), nums[4] * 256 + nums[5]


def _advertised_local_host(sock: socket.socket | ssl.SSLSocket | None, fallback: str) -> str:
    if sock is not None:
        try:
            host = str(sock.getsockname()[0])
            if host and host != "0.0.0.0":
                return host
        except OSError:
            pass
    return "127.0.0.1" if fallback in {"localhost", "0.0.0.0", "::1"} else fallback


def _ftp_port_argument(host: str, port: int) -> str:
    octets = host.split(".")
    if len(octets) != 4 or any(not item.isdigit() for item in octets):
        octets = ["127", "0", "0", "1"]
    return ",".join([*octets, str(port // 256), str(port % 256)])
