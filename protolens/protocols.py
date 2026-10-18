"""Shared protocol identities and wire capabilities for the benchmark targets."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProtocolProfile:
    name: str
    aflnet_name: str
    transport: str = "tcp"
    binary: bool = False
    fallback: str = ""


PROTOCOLS = {
    p.name: p for p in (
        ProtocolProfile("ftp", "FTP", fallback="USER"),
        ProtocolProfile("rtsp", "RTSP", fallback="OPTIONS"),
        ProtocolProfile("smtp", "SMTP", fallback="EHLO"),
        ProtocolProfile("http", "HTTP", fallback="GET /"),
        ProtocolProfile("daap-http", "HTTP", fallback="GET /server-info"),
        ProtocolProfile("sip", "SIP", "udp", fallback="OPTIONS"),
        ProtocolProfile("dns", "DNS", "udp", True, "QUERY test.com A"),
        ProtocolProfile("tls", "TLS", "tcp", True, "CLIENT_HELLO"),
        ProtocolProfile("dtls", "DTLS12", "udp", True, "CLIENT_HELLO"),
        ProtocolProfile("ssh", "SSH", "tcp", True, "IDENTIFICATION"),
        ProtocolProfile("dicom", "DICOM", "tcp", True, "A-ASSOCIATE-RQ"),
    )
}


def normalize_protocol(protocol: str) -> str:
    key = protocol.strip().lower().replace("_", "-")
    return {"dtls12": "dtls", "dtls1.2": "dtls", "dtls-1.2": "dtls",
            "daap": "daap-http"}.get(key, key)


def protocol_profile(protocol: str) -> ProtocolProfile:
    key = normalize_protocol(protocol)
    return PROTOCOLS.get(key, ProtocolProfile(key, key.upper()))


def seed_message_contract(protocol: str) -> dict[str, object]:
    """Give LLM producers the same wire contract used by the encoder."""
    from protolens.tools.wire_protocols import BINARY_METHODS
    profile = protocol_profile(protocol)
    return {
        "protocol": profile.name,
        "transport": profile.transport,
        "binary": profile.binary,
        "fallback_example": profile.fallback,
        "binary_templates": sorted(BINARY_METHODS.get(profile.name, set())),
        "requirements": [
            "Use client_send only for client-originated wire messages; keep server/internal events separate.",
            "For exact packets or unsupported binary messages use raw-b64:<base64 of wire bytes>.",
            "raw:<escaped bytes> is also supported. Never encode a binary message as its English name.",
            "Templates provide initial probes, not a complete cryptographic or authenticated session.",
            "Preserve captured target-specific handshake bytes and prerequisites where needed.",
        ],
    }
