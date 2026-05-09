"""Project detection stage for scan pipeline."""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

from core.detector import ProjectDetector
from core.pipeline.errors import ProjectDetectionError
from core.pipeline.models import ScanPipelineContext, ScanPipelineState

logger = logging.getLogger(__name__)


class DetectProjectStage:
    """Detect project metadata and architecture profile."""

    def __init__(self, detector_factory: Callable[[str], ProjectDetector] | None = None):
        self._detector_factory = detector_factory or ProjectDetector

    async def run(self, context: ScanPipelineContext, state: ScanPipelineState) -> None:
        await context.update_progress(5.0, "detecting")
        context.check_cancelled()
        cache_payload = {"project_path": context.request.project_path}
        if context.stage_cache is not None:
            cached = context.stage_cache.load("detect_project", cache_payload)
            if cached is not None:
                state.project_info = cached
                logger.info("[Pipeline] detect_project cache hit")
                return
        try:
            detector = self._detector_factory(context.request.project_path)
            state.project_info = await asyncio.to_thread(detector.detect)
            if context.stage_cache is not None and state.project_info is not None:
                context.stage_cache.save("detect_project", state.project_info, cache_payload)
            logger.info(
                "[Pipeline] detect_project complete",
                extra={
                    "project_path": context.request.project_path,
                    "project_type": getattr(getattr(state.project_info, "project_type", None), "value", "unknown"),
                },
            )
        except Exception as exc:
            logger.exception(
                "[Pipeline] detect_project failed",
                extra={"project_path": context.request.project_path},
            )
            raise ProjectDetectionError(
                "Failed to detect project type",
                stage="detect_project",
                context={"project_path": context.request.project_path},
            ) from exc
