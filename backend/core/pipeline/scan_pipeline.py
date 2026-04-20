"""Composable scan pipeline orchestrator."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Awaitable, Callable

from schemas.report import ScanReport

from .stage_cache import StageCacheManager
from .errors import ReportingError, ScanError
from .models import ScanPipelineContext, ScanPipelineRequest, ScanPipelineState
from .stages import (
    BuildFactsStage,
    DetectProjectStage,
    ReportingStage,
    RunRulesStage,
    ScoringStage,
)

logger = logging.getLogger(__name__)


class ScanPipeline:
    """High-level scan workflow composed of isolated stages."""

    def __init__(
        self,
        context: ScanPipelineContext,
        *,
        detect_stage: DetectProjectStage | None = None,
        build_stage: BuildFactsStage | None = None,
        run_rules_stage: RunRulesStage | None = None,
        scoring_stage: ScoringStage | None = None,
        reporting_stage: ReportingStage | None = None,
    ) -> None:
        self.context = context
        self.detect_stage = detect_stage or DetectProjectStage()
        self.build_stage = build_stage or BuildFactsStage()
        self.run_rules_stage = run_rules_stage or RunRulesStage()
        self.scoring_stage = scoring_stage or ScoringStage()
        self.reporting_stage = reporting_stage or ReportingStage()
        self.state = ScanPipelineState(start_time=time.perf_counter())

    async def run(self) -> ScanReport:
        await self._run_stage("detect_project", self.detect_stage.run, critical=True)
        await self._run_stage("build_facts", self.build_stage.run, critical=True)
        await self._run_stage("run_rules", self.run_rules_stage.run, critical=True)
        await self._run_stage("scoring", self.scoring_stage.run, critical=True)
        await self._run_stage("reporting", self.reporting_stage.run, critical=False)

        if self.state.report is None:
            raise ReportingError(
                "Scan finished without a report",
                stage="reporting",
                context={"project_path": self.context.request.project_path},
            )

        if self.state.warnings:
            logger.warning(
                "[Pipeline] Completed with non-critical warnings: %s",
                ",".join(self.state.warnings),
            )
        if self.context.stage_cache is not None:
            self.state.cache_stats = self.context.stage_cache.get_stats()
        return self.state.report

    async def _run_stage(
        self,
        name: str,
        stage_runner: Callable[[ScanPipelineContext, ScanPipelineState], Awaitable[None]],
        *,
        critical: bool,
    ) -> None:
        logger.info("[Pipeline] Running %s", name)
        try:
            self.context.check_cancelled()
            await stage_runner(self.context, self.state)
        except ScanError:
            if critical:
                raise
            logger.exception("[Pipeline] Non-critical stage error in %s", name)
            self.state.warnings.append(name)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("[Pipeline] Unexpected stage error in %s", name)
            wrapped = ScanError(
                f"Unexpected stage error: {exc}",
                stage=name,
                context={"project_path": self.context.request.project_path},
            )
            if critical:
                raise wrapped from exc
            self.state.warnings.append(name)


async def run_scan_pipeline(
    request: ScanPipelineRequest,
    *,
    job_id: str,
    token,
    manager,
) -> ScanReport:
    """Convenience function for route/job manager integration."""
    loop = asyncio.get_running_loop()
    stage_cache = StageCacheManager(request.project_path)
    context = ScanPipelineContext(
        request=request,
        job_id=job_id,
        token=token,
        manager=manager,
        loop=loop,
        stage_cache=stage_cache,
    )
    pipeline = ScanPipeline(context)
    return await pipeline.run()
