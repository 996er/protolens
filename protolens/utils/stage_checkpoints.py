from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json

from protolens.utils.artifact_store import ArtifactStore


class StageCheckpointStore:
    VERSION = 1
    CHECKPOINT_PATH = "checkpoints/fsm_stages.json"

    def __init__(self, store: ArtifactStore) -> None:
        self.store = store

    def is_valid(self, stage: str, fingerprint: str, artifacts: list[str]) -> bool:
        state = self._read()
        record = state.get("stages", {}).get(stage)
        if not isinstance(record, dict) or record.get("fingerprint") != fingerprint:
            return False
        recorded = record.get("artifacts")
        if not isinstance(recorded, dict) or set(recorded) != set(artifacts):
            return False
        for relative in artifacts:
            path = self.store.path(relative)
            if not path.is_file() or file_sha256(path) != recorded.get(relative):
                return False
        return True

    def record(
        self,
        stage: str,
        fingerprint: str,
        artifacts: list[str],
        *,
        invalidate: tuple[str, ...] = (),
    ) -> None:
        state = self._read()
        stages = state.setdefault("stages", {})
        for name in invalidate:
            stages.pop(name, None)
        stages[stage] = {
            "fingerprint": fingerprint,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": {
                relative: file_sha256(self.store.path(relative))
                for relative in artifacts
            },
        }
        self.store.write_json(self.CHECKPOINT_PATH, state)

    def invalidate(self, *stage_names: str) -> None:
        state = self._read()
        stages = state.setdefault("stages", {})
        changed = False
        for stage_name in stage_names:
            if stage_name in stages:
                stages.pop(stage_name)
                changed = True
        if changed:
            self.store.write_json(self.CHECKPOINT_PATH, state)

    def _read(self) -> dict[str, Any]:
        path = self.store.path(self.CHECKPOINT_PATH)
        if not path.exists():
            return {"version": self.VERSION, "stages": {}}
        try:
            value = self.store.read_json(self.CHECKPOINT_PATH)
        except (OSError, json.JSONDecodeError):
            return {"version": self.VERSION, "stages": {}}
        if not isinstance(value, dict) or value.get("version") != self.VERSION:
            return {"version": self.VERSION, "stages": {}}
        if not isinstance(value.get("stages"), dict):
            value["stages"] = {}
        return value


def stable_fingerprint(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
