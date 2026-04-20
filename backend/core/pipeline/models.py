"""Shared request/state models for scan pipeline stages."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from core.job_manager import CancellationToken, JobManager


@dataclass(slots=True)
class ScanPipelineRequest:
    """Immutable input payload for a scan pipeline run."""

    project_path: str
    ruleset_path: str | None
    baseline_profile: str | None
    differential_mode: bool
    changed_files: list[str] | None
    pr_mode: bool
    pr_gate_preset: str | None
    selected_rules: list[str] | None
    project_context_overrides: dict[str, object] | None


@dataclass(slots=True)
class ScanPipelineContext:
    """Runtime context shared by stages."""

    request: ScanPipelineRequest
    job_id: str
    token: CancellationToken
    manager: JobManager
    loop: asyncio.AbstractEventLoop
    stage_cache: Any | None = None

    async def update_progress(
        self,
        progress: float,
        phase: str,
        *,
        current_file: str | None = None,
        files_processed: int = 0,
        files_total: int = 0,
    ) -> None:
        """Forward progress updates to job manager."""
        await self.manager.update_progress(
            self.job_id,
            progress,
            phase,
            current_file=current_file,
            files_processed=files_processed,
            files_total=files_total,
        )

    def check_cancelled(self) -> None:
        """Raise cancellation error when cancellation is requested."""
        self.token.check()

    def schedule_progress(
        self,
        progress: float,
        phase: str,
        *,
        current_file: str | None = None,
        files_processed: int = 0,
        files_total: int = 0,
    ) -> None:
        """Schedule progress updates from worker threads."""
        asyncio.run_coroutine_threadsafe(
            self.update_progress(
                progress,
                phase,
                current_file=current_file,
                files_processed=files_processed,
                files_total=files_total,
            ),
            self.loop,
        )


@dataclass(slots=True)
class ScanPipelineState:
    """Mutable state object passed between pipeline stages."""

    start_time: float = 0.0
    project_info: Any | None = None
    ruleset: Any | None = None
    facts: Any | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    rule_engine: Any | None = None
    engine_result: Any | None = None
    report: Any | None = None
    baseline_diff: Any | None = None
    warnings: list[str] = field(default_factory=list)
    cache_stats: dict[str, Any] = field(default_factory=dict)
