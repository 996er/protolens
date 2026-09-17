from __future__ import annotations

import re
from typing import Any


PROTOCOL_METHODS: dict[str, set[str]] = {
    "ftp": {
        "ABOR", "ACCT", "ALLO", "APPE", "AUTH", "CCC", "CDUP", "CWD", "DELE", "EPRT",
        "EPSV", "FEAT", "HELP", "LIST", "MDTM", "MFMT", "MKD", "MLSD", "MLST", "MODE",
        "NLST", "NOOP", "OPTS", "PASS", "PASV", "PBSZ", "PORT", "PROT", "PWD", "QUIT",
        "REIN", "REST", "RETR", "RMD", "RNFR", "RNTO", "SITE", "SIZE", "SMNT", "STAT",
        "STOR", "STOU", "STRU", "SYST", "TYPE", "USER", "XCUP", "XCWD", "XMKD", "XPWD",
        "XRMD",
    },
    "rtsp": {
        "ANNOUNCE", "DESCRIBE", "GET_PARAMETER", "OPTIONS", "PAUSE", "PLAY", "PLAY_NOTIFY",
        "RECORD", "REDIRECT", "SET_PARAMETER", "SETUP", "TEARDOWN",
    },
    "smtp": {"AUTH", "DATA", "EHLO", "EXPN", "HELO", "HELP", "MAIL", "NOOP", "QUIT", "RCPT", "RSET", "STARTTLS", "VRFY"},
    "http": {"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"},
    "daap-http": {"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"},
}
EXTENSIBLE_METHOD_PROTOCOLS = {"rtsp"}

_CLIENT_SEND_TYPES = {
    "client_send",
    "client-send",
    "client.send",
    "client request",
    "client_request",
    "client-request",
}
_SEMANTIC_ARGUMENT_LEADERS = {
    "after",
    "and",
    "before",
    "command",
    "fails",
    "failure",
    "for",
    "from",
    "is",
    "on",
    "or",
    "request",
    "returns",
    "succeeds",
    "success",
    "to",
    "valid",
    "via",
    "when",
    "with",
}
_INTERNAL_TOKENS = {
    "accept",
    "bind",
    "client_thread",
    "clientsocket",
    "connection_handler",
    "fork",
    "getpeername",
    "getsockname",
    "invalid_socket",
    "listen",
    "poll",
    "select",
    "server",
    "socket",
    "thread",
    "worker",
}


def is_client_send_transition(transition: Any) -> bool:
    message_type = str(getattr(transition, "message_type", "") or "").strip().lower()
    if not message_type:
        return False
    normalized = re.sub(r"[^a-z0-9]+", "_", message_type).strip("_")
    if message_type in _CLIENT_SEND_TYPES or normalized in _CLIENT_SEND_TYPES:
        return True
    return normalized.startswith("client_") and any(token in normalized for token in ("send", "request"))


def transition_client_seed_message(transition: Any, protocol: str) -> str | None:
    if not is_client_send_transition(transition):
        return None
    return client_seed_message(str(getattr(transition, "trigger", "") or ""), protocol)


def client_seed_message(message: str, protocol: str) -> str | None:
    text = str(message).strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered.startswith(("raw:", "raw-b64:", "base64:")):
        return text
    if _looks_internal(text):
        return None

    protocol_key = protocol.lower().replace("_", "-")
    commands = PROTOCOL_METHODS.get(protocol_key)
    parts = text.split()
    if len(parts) >= 2 and parts[0].lower().replace("_", "-").rstrip(":") == protocol_key:
        parts = parts[1:]
    if not parts:
        return None

    method = parts[0].upper().rstrip(":,;")
    if commands is not None and method not in commands and protocol_key not in EXTENSIBLE_METHOD_PROTOCOLS:
        return None
    if (commands is None or method not in commands) and not re.fullmatch(r"[A-Z][A-Z0-9_.-]{1,24}", method):
        return None

    directives = [token for token in parts[1:] if token.startswith("--") and len(token) > 2]
    arguments = [token for token in parts[1:] if not token.startswith("--")]
    if arguments and _semantic_argument(arguments[0]):
        arguments = []
    normalized = " ".join([method, *arguments, *directives]).strip()
    return normalized or None


def _looks_internal(text: str) -> bool:
    lowered = text.lower()
    normalized = re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")
    if "()" in text or any(token in normalized for token in _INTERNAL_TOKENS):
        return True
    return " returns " in lowered or lowered.startswith(("return ", "on ", "when "))


def _semantic_argument(token: str) -> bool:
    cleaned = token.lower().strip(",:;()[]{}")
    return cleaned in _SEMANTIC_ARGUMENT_LEADERS or cleaned.endswith("succeeds") or cleaned.endswith("fails")
