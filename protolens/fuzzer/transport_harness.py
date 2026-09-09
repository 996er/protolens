from __future__ import annotations

from dataclasses import dataclass
import socket
import ssl
import struct
from typing import Any

from protolens.config import ProtoLensConfig
from protolens.tools.corpus_encoder import CorpusEncoder


@dataclass
class _Session:
    sock: socket.socket | ssl.SSLSocket | None = None
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
        return self._send_protocol_message(config, session, message)

    def _send_protocol_message(self, config: ProtoLensConfig, session: _Session, message: str) -> dict[str, Any]:
        if session.sock is None:
            session.sock = self._connect(config)
        payload = CorpusEncoder()._encode_message(message, config.protocol, session.sequence)
        session.sequence += 1
        if not payload:
            return {"event": "send", "supported": True, "message": message, "bytes_sent": 0}
        session.sock.sendall(payload)
        response = _recv_available(session.sock)
        return {
            "event": "send",
            "supported": True,
            "message": message,
            "bytes_sent": len(payload),
            "response_bytes": len(response),
            "response_preview": response[:200].decode("utf-8", errors="replace"),
        }

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


def _recv_available(sock: socket.socket | ssl.SSLSocket) -> bytes:
    try:
        return sock.recv(4096)
    except (socket.timeout, BlockingIOError, ssl.SSLWantReadError):
        return b""


def _close(sock: socket.socket | ssl.SSLSocket | None) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass
