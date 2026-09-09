from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import inspect
import os
import sys


class Logger:
    def __init__(
        self,
        verbose: bool = True,
        debug_enabled: bool = False,
        log_file: str | Path | None = None,
        include_location: bool = True,
    ) -> None:
        self.verbose = verbose
        self.debug_enabled = debug_enabled
        self.log_file = Path(log_file).resolve() if log_file else None
        self.include_location = include_location
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def debug(self, message: str, **fields: Any) -> None:
        if self.debug_enabled:
            self._emit("DEBUG", message, fields)

    def info(self, message: str, **fields: Any) -> None:
        if self.verbose:
            self._emit("INFO", message, fields)

    def warning(self, message: str, **fields: Any) -> None:
        self._emit("WARN", message, fields)

    def error(self, message: str, **fields: Any) -> None:
        self._emit("ERROR", message, fields)

    def _emit(self, level: str, message: str, fields: dict[str, Any] | None = None) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        merged_fields = dict(fields or {})
        if self.include_location:
            location = _caller_location()
            if location:
                merged_fields.setdefault("loc", location)
        suffix = _format_fields(merged_fields)
        line = f"[{timestamp}] {level} {message}{suffix}"
        print(line, file=sys.stderr)
        if self.log_file:
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.write("\n")


def _format_fields(fields: dict[str, Any]) -> str:
    if not fields:
        return ""
    pairs = []
    for key, value in sorted(fields.items()):
        pairs.append(f"{key}={_format_value(value)}")
    return " " + " ".join(pairs)


def _format_value(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return "[" + ",".join(_format_value(item) for item in value) + "]"
    text = str(value)
    if not text:
        return '""'
    if any(char.isspace() for char in text):
        return repr(text)
    return text


def _caller_location() -> str | None:
    frame = inspect.currentframe()
    if frame is None:
        return None
    try:
        frame = frame.f_back
        while frame is not None:
            filename = frame.f_code.co_filename
            if not filename.endswith("protolens/utils/logger.py"):
                return f"{_short_path(filename)}:{frame.f_lineno}"
            frame = frame.f_back
    finally:
        del frame
    return None


def _short_path(filename: str) -> str:
    try:
        return os.path.relpath(filename, Path.cwd())
    except ValueError:
        return filename
