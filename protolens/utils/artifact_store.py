from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import os
import tempfile


class ArtifactStore:
    """限定在单次 run 目录内的原子 JSON/JSONL 工件存储。"""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, relative: str | Path) -> Path:
        candidate = (self.root / relative).resolve()
        # resolve + relative_to 同时阻止 ../ 和符号链接逃逸 run 目录。
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(f"artifact path escapes run directory: {relative}") from exc
        return candidate

    def write_json(self, relative: str | Path, data: Any) -> Path:
        path = self.path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(_jsonable(data), handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(tmp_name, path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        return path

    def read_json(self, relative: str | Path) -> Any:
        with self.path(relative).open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def append_jsonl(self, relative: str | Path, data: Any) -> Path:
        path = self.path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_jsonable(data), ensure_ascii=False, sort_keys=True))
            handle.write("\n")
        return path

    def write_text(self, relative: str | Path, text: str) -> Path:
        path = self.path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.replace(tmp_name, path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        return path


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dataclass_fields__"):
        return {key: _jsonable(item) for key, item in value.__dict__.items()}
    return value
