from __future__ import annotations

from protolens.config import ProtoLensConfig
from protolens.fsm.fsm_model import FuzzResult, PlannedStatePath, SeedIntent
from protolens.fuzzer.aflnet_adapter import AFLNetAdapter, ProgressCallback


class PathAwareFuzzer:
    def __init__(self, adapter: AFLNetAdapter | None = None) -> None:
        self.adapter = adapter or AFLNetAdapter()

    def prepare(
        self,
        config: ProtoLensConfig,
        paths: list[PlannedStatePath],
        seed_intents: list[SeedIntent] | None = None,
    ) -> FuzzResult:
        return self.adapter.prepare(config, paths, seed_intents=seed_intents)

    def execute(
        self,
        config: ProtoLensConfig,
        prepared: FuzzResult,
        on_progress: ProgressCallback | None = None,
    ) -> FuzzResult:
        return self.adapter.execute(config, prepared, on_progress=on_progress)

    def run(
        self,
        config: ProtoLensConfig,
        paths: list[PlannedStatePath],
        seed_intents: list[SeedIntent] | None = None,
    ) -> FuzzResult:
        return self.adapter.prepare_and_run(config, paths, seed_intents=seed_intents)
