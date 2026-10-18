"""Initial wire probes and lossless framing, not full protocol clients.

Layouts: RFC 1035, RFC 5246, RFC 6347, RFC 4253 and DICOM PS3.8 §9.3.
Stateful/encrypted continuations must be supplied as captured raw bytes.
"""
from __future__ import annotations

import re
import struct

from protolens.protocols import normalize_protocol


BINARY_METHODS = {
    "dns": {"QUERY", "DNS_QUERY"},
    "tls": {"CLIENT_HELLO", "CLIENTHELLO", "CHANGE_CIPHER_SPEC", "ALERT", "CLOSE_NOTIFY"},
    "dtls": {"CLIENT_HELLO", "CLIENTHELLO", "CHANGE_CIPHER_SPEC", "ALERT", "CLOSE_NOTIFY"},
    "ssh": {"IDENTIFICATION", "VERSION", "KEXINIT", "SSH_MSG_KEXINIT", "NEWKEYS", "SSH_MSG_NEWKEYS"},
    "dicom": {"A-ASSOCIATE-RQ", "A_ASSOCIATE_RQ", "A-RELEASE-RQ", "A_RELEASE_RQ", "A-ABORT", "A_ABORT"},
}


def encode_binary(message: str, protocol: str, sequence: int = 1) -> bytes:
    protocol = normalize_protocol(protocol)
    parts = message.split()
    method = parts[0].upper()
    args = [p for p in parts[1:] if not p.startswith("--")]
    options = dict(p[2:].split("=", 1) for p in parts[1:] if p.startswith("--") and "=" in p)
    if method not in BINARY_METHODS.get(protocol, set()):
        raise ValueError(f"unsupported {protocol} template {method}; use raw-b64 for exact wire bytes")
    if protocol == "dns":
        name = options.get("name", args[0] if args else "test.com").rstrip(".")
        labels = [label.encode("idna") for label in name.split(".")] if name else []
        if any(not label or len(label) > 63 for label in labels):
            raise ValueError("DNS labels must contain 1..63 bytes")
        qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
        if len(qname) > 255:
            raise ValueError("DNS name exceeds 255 wire bytes")
        qtype = options.get("type", args[1] if len(args) > 1 else "A").upper()
        types = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
                 "AAAA": 28, "SRV": 33, "OPT": 41, "DS": 43, "DNSKEY": 48, "ANY": 255}
        number = types[qtype] if qtype in types else int(qtype)
        return struct.pack("!6H", int(options.get("id", sequence)) & 65535, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", number, 1)
    if protocol in {"tls", "dtls"}:
        dtls = protocol == "dtls"
        version = b"\xfe\xfd" if dtls else b"\x03\x03"
        content_type = 22
        if method in {"CLIENT_HELLO", "CLIENTHELLO"}:
            body = version + bytes(range(32)) + b"\x00"  # empty session ID
            if dtls:
                cookie = bytes.fromhex(options.get("cookie", ""))
                if len(cookie) > 255:
                    raise ValueError("DTLS cookie exceeds 255 bytes")
                body += bytes([len(cookie)]) + cookie
            # PSK + ECDHE_ECDSA for TinyDTLS; RSA for the OpenSSL benchmark.
            suites = b"\xc0\xa8\xc0\xae\xc0\x2b" if dtls else b"\x00\x2f\x00\x35"
            body += struct.pack("!H", len(suites)) + suites + b"\x01\x00"
            extensions = b"\xff\x01\x00\x01\x00"  # secure renegotiation indication
            body += struct.pack("!H", len(extensions)) + extensions
            size = len(body).to_bytes(3, "big")
            handshake = b"\x01" + size
            if dtls:
                handshake += (sequence - 1).to_bytes(2, "big") + b"\x00" * 3 + size
            body = handshake + body
        elif method == "CHANGE_CIPHER_SPEC":
            content_type, body = 20, b"\x01"
        else:
            content_type = 21
            body = bytes([int(options.get("level", "1")), int(options.get("description", "0"))])
        header = bytes([content_type]) + version
        if dtls:
            header += int(options.get("epoch", "0")).to_bytes(2, "big") + (sequence - 1).to_bytes(6, "big")
        return header + struct.pack("!H", len(body)) + body
    if protocol == "ssh":
        if method in {"IDENTIFICATION", "VERSION"}:
            return b"SSH-2.0-ProtoLens\r\n"
        if method.endswith("NEWKEYS"):
            payload = b"\x15"
        else:
            def string(value: bytes) -> bytes:
                return struct.pack("!I", len(value)) + value
            algorithms = [b"diffie-hellman-group14-sha1", b"ssh-rsa", b"aes128-ctr", b"aes128-ctr",
                          b"hmac-sha1", b"hmac-sha1", b"none", b"none", b"", b""]
            payload = b"\x14" + bytes(range(16)) + b"".join(string(v) for v in algorithms) + b"\x00" * 5
        padding = 8 - ((5 + len(payload)) % 8)
        if padding < 4:
            padding += 8
        return struct.pack("!IB", 1 + len(payload) + padding, padding) + payload + b"\x00" * padding
    method = method.replace("_", "-")
    if method == "A-ASSOCIATE-RQ":
        def item(kind: int, value: bytes) -> bytes:
            return bytes([kind, 0]) + struct.pack("!H", len(value)) + value
        def ae(key: str, default: str) -> bytes:
            value = options.get(key, default).encode("ascii")
            if not value.strip() or len(value) > 16:
                raise ValueError("DICOM AE titles must contain 1..16 ASCII characters")
            return value.ljust(16, b" ")
        body = b"\x00\x01\x00\x00" + ae("called-ae", "ACME_STORE") + ae("calling-ae", "PROTOLENS") + b"\x00" * 32
        body += item(0x10, b"1.2.840.10008.3.1.1.1")
        body += item(0x20, b"\x01\x00\x00\x00" + item(0x30, b"1.2.840.10008.1.1") + item(0x40, b"1.2.840.10008.1.2"))
        body += item(0x50, item(0x51, struct.pack("!I", 16384)) + item(0x52, b"2.25.329800735698586629295641978511506172918"))
        kind = 1
    elif method == "A-RELEASE-RQ":
        kind, body = 5, b"\x00" * 4
    else:
        kind, body = 7, b"\x00\x00\x00\x00"
    return bytes([kind, 0]) + struct.pack("!I", len(body)) + body


def dns_message_end(payload: bytes, start: int = 0) -> int:
    """Find DNS boundaries using section counts, including compressed names."""
    if len(payload) - start < 12:
        raise ValueError("truncated DNS header")
    counts = struct.unpack_from("!4H", payload, start + 4)
    cursor = start + 12

    def name_end(pos: int) -> int:
        for _ in range(128):
            if pos >= len(payload):
                break
            size = payload[pos]
            pos += 1
            if size == 0:
                return pos
            if size & 0xC0 == 0xC0:
                if pos >= len(payload):
                    break
                return pos + 1
            if size > 63:
                break
            pos += size
        raise ValueError("invalid or truncated DNS name")

    for section, count in enumerate(counts):
        for _ in range(count):
            cursor = name_end(cursor)
            if section == 0:
                cursor += 4
            else:
                if cursor + 10 > len(payload):
                    raise ValueError("truncated DNS resource record")
                cursor += 10 + int.from_bytes(payload[cursor + 8:cursor + 10], "big")
            if cursor > len(payload):
                raise ValueError("truncated DNS message")
    return cursor


def split_wire_messages(payload: bytes, protocol: str) -> list[bytes]:
    """Never discard bytes; keep an unframeable remainder as one opaque message."""
    protocol = normalize_protocol(protocol)
    chunks: list[bytes] = []
    offset = 0
    smtp_data = False
    while offset < len(payload):
        remaining = payload[offset:]
        end = -1
        if protocol in {"tls", "dtls", "dicom", "ssh"}:
            if protocol == "ssh" and remaining.startswith(b"SSH-"):
                mark = remaining.find(b"\n")
                end = mark + 1 if mark >= 0 else -1
            else:
                header, size_start, size_end = {"tls": (5, 3, 5), "dtls": (13, 11, 13),
                                                "dicom": (6, 2, 6), "ssh": (4, 0, 4)}[protocol]
                if len(remaining) >= header:
                    end = header + int.from_bytes(remaining[size_start:size_end], "big")
                    # AFLNet's patched OpenSSH format appends an 8-byte MAC to
                    # non-key-exchange packets. Keep those opaque (MAC length is
                    # not knowable for arbitrary encrypted captures).
                    if protocol == "ssh" and (len(remaining) < 6 or not 20 <= remaining[5] <= 49):
                        end = -1
        elif protocol == "dns":
            try:
                end = dns_message_end(remaining)
            except ValueError:
                pass
        elif protocol in {"rtsp", "http", "daap-http", "sip"}:
            mark = remaining.find(b"\r\n\r\n")
            if mark >= 0:
                headers = remaining[:mark]
                length = re.findall(rb"(?im)^(?:content-length|l):\s*(\d+)\s*$", headers)
                if not re.search(rb"(?im)^transfer-encoding:", headers) and len(length) <= 1:
                    end = mark + 4 + (int(length[0]) if length else 0)
        else:
            separator = b"\r\n.\r\n" if smtp_data else b"\r\n"
            mark = remaining.find(separator)
            if mark >= 0:
                end = mark + len(separator)
                smtp_data = protocol == "smtp" and not smtp_data and remaining[:end].strip().upper() == b"DATA"
        if end <= 0 or end > len(remaining):
            chunks.append(remaining)
            break
        chunks.append(remaining[:end])
        offset += end
    return chunks


def wire_method(payload: bytes, protocol: str) -> str:
    protocol = normalize_protocol(protocol)
    if not payload:
        return "RAW"
    if protocol == "dns":
        return "QUERY" if len(payload) >= 12 and not payload[2] & 0x80 else "RAW"
    if protocol in {"tls", "dtls"}:
        header = 13 if protocol == "dtls" else 5
        if len(payload) > header and payload[0] == 22:
            return {1: "CLIENT_HELLO", 2: "SERVER_HELLO", 3: "HELLO_VERIFY_REQUEST"}.get(payload[header], "HANDSHAKE")
        return {20: "CHANGE_CIPHER_SPEC", 21: "ALERT", 23: "APPLICATION_DATA"}.get(payload[0], "RAW")
    if protocol == "dicom":
        return {1: "A-ASSOCIATE-RQ", 2: "A-ASSOCIATE-AC", 3: "A-ASSOCIATE-RJ",
                4: "P-DATA-TF", 5: "A-RELEASE-RQ", 6: "A-RELEASE-RP", 7: "A-ABORT"}.get(payload[0], "RAW")
    if protocol == "ssh":
        if payload.startswith(b"SSH-"):
            return "IDENTIFICATION"
        return {20: "KEXINIT", 21: "NEWKEYS"}.get(payload[5], "RAW") if len(payload) > 5 else "RAW"
    return payload.split(None, 1)[0].decode("ascii", errors="replace") if payload.strip() else "RAW"
