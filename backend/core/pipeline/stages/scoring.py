"""Scoring/report generation stage for scan pipeline."""

from __future__ import annotations

import asyncio
import logging

from core.pipeline.errors import ScoringError
from core.pipeline.models import ScanPipelineContext, ScanPipelineState
from core.scoring import ScoringEngine

logger = logging.getLogger(__name__)


class ScoringStage:
    """Generate the base `ScanReport` from rule findings."""

    async def run(self, context: ScanPipelineContext, state: ScanPipelineState) -> None:
        await context.update_progress(85.0, "scoring")
        context.check_cancelled()

        if state.ruleset is None or state.engine_result is None or state.facts is None or state.project_info is None:
            raise ScoringError(
                "Scoring stage prerequisites are missing",
                stage="scoring",
                context={"project_path": context.request.project_path},
            )

        scoring_engine = ScoringEngine(state.ruleset)
        findings_sig = ""
        if state.engine_result is not None:
            fps = sorted(str(getattr(f, "fingerprint", "") or "") for f in (state.engine_result.findings or []))
            findings_sig = "|".join(fps[:2000])
        cache_payload = {
            "ruleset_name": str(getattr(state.ruleset, "name", "") or ""),
            "ruleset_source": str(getattr(state.ruleset, "source_path", "") or ""),
            "project_type": str(getattr(getattr(state.project_info, "project_type", None), "value", "unknown") or "unknown"),
            "findings_sig": findings_sig,
            "files_count": len(getattr(state.facts, "files", []) or []),
            "methods_count": len(getattr(state.facts, "methods", []) or []),
        }
        try:
            if context.stage_cache is not None:
                cached = context.stage_cache.load("scoring", cache_payload)
            else:
                cached = None
            if cached is not None:
                state.report = cached
                logger.info("[Pipeline] scoring cache hit")
            else:
                state.report = await asyncio.to_thread(
                    scoring_engine.generate_report,
                    job_id=context.job_id,
                    project_path=context.request.project_path,
                    findings=state.engine_result.findings,
                    facts=state.facts,
                    project_info=state.project_info,
                    ruleset_path=str(context.request.ruleset_path) if context.request.ruleset_path else None,
                    rules_executed=state.rule_engine.get_rule_ids() if state.rule_engine else [],
                )
                if context.stage_cache is not None and state.report is not None:
                    context.stage_cache.save("scoring", state.report, cache_payload)
            if not isinstance(state.report.analysis_debug, dict):
                state.report.analysis_debug = {}
            state.report.analysis_debug["requested_project_context"] = dict(
                context.request.project_context_overrides or {}
            )
            logger.info(
                "[Pipeline] scoring complete",
                extra={
                    "report_id": getattr(state.report, "id", ""),
                    "findings": len(getattr(state.report, "findings", []) or []),
                },
            )
        except Exception as exc:
            logger.exception(
                "[Pipeline] scoring failed",
                extra={"project_path": context.request.project_path},
            )
            raise ScoringError(
                "Failed to generate scan report",
                stage="scoring",
                context={"project_path": context.request.project_path},
            ) from exc
