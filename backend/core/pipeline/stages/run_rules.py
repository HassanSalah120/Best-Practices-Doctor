"""Rule execution stage for scan pipeline."""

from __future__ import annotations

import asyncio
import logging

from core.pipeline.errors import RuleExecutionError
from core.pipeline.models import ScanPipelineContext, ScanPipelineState
from core.rule_engine import create_engine
from core.trust import enrich_findings_with_trust

logger = logging.getLogger(__name__)


class RunRulesStage:
    """Execute configured rules against extracted facts and metrics."""

    async def run(self, context: ScanPipelineContext, state: ScanPipelineState) -> None:
        await context.update_progress(55.0, "analyzing")
        context.check_cancelled()

        if state.ruleset is None or state.facts is None or state.project_info is None:
            raise RuleExecutionError(
                "Rules stage prerequisites are missing",
                stage="run_rules",
                context={"project_path": context.request.project_path},
            )

        rule_engine = create_engine(
            ruleset=state.ruleset,
            selected_rules=context.request.selected_rules,
        )
        state.rule_engine = rule_engine
        cache_payload = {
            "ruleset_name": str(getattr(state.ruleset, "name", "") or ""),
            "ruleset_source": str(getattr(state.ruleset, "source_path", "") or ""),
            "selected_rules": sorted(context.request.selected_rules or []),
            "differential_mode": bool(context.request.differential_mode),
            "changed_files": sorted(context.request.changed_files or []),
            "project_type": str(getattr(getattr(state.project_info, "project_type", None), "value", "unknown") or "unknown"),
        }

        def on_rule_progress(fraction: float, rules_done: int, rules_total: int) -> None:
            pct = 55.0 + fraction * 25.0
            context.schedule_progress(
                pct,
                "analyzing",
                current_file=f"Rule {rules_done}/{rules_total}",
                files_processed=rules_done,
                files_total=rules_total,
            )

        try:
            if context.stage_cache is not None:
                cached = context.stage_cache.load("run_rules", cache_payload)
            else:
                cached = None
            if cached is not None:
                state.engine_result = cached
                logger.info("[Pipeline] run_rules cache hit")
            else:
                state.engine_result = await asyncio.to_thread(
                    rule_engine.run,
                    state.facts,
                    state.metrics,
                    state.project_info.project_type.value,
                    context.token.is_cancelled,
                    context.request.differential_mode,
                    set(context.request.changed_files or []),
                    on_rule_progress,
                )
                if context.stage_cache is not None and state.engine_result is not None:
                    context.stage_cache.save("run_rules", state.engine_result, cache_payload)
            context.check_cancelled()
            if state.engine_result is not None:
                resolver = lambda rid: float(rule_engine._confidence_floor_for_rule(rid))  # noqa: E731, SLF001
                enrich_findings_with_trust(
                    state.engine_result.findings,
                    confidence_floor_resolver=resolver,
                    profile_name=str(getattr(state.ruleset, "name", "startup") or "startup"),
                    suppressed_count=int(getattr(state.engine_result, "suppressed_count", 0) or 0),
                    deduped_overlap_count=int(getattr(state.engine_result, "deduped_overlap_count", 0) or 0),
                    filtered_by_confidence=int(getattr(state.engine_result, "filtered_by_confidence", 0) or 0),
                )
            await context.update_progress(80.0, "analyzing")
            logger.info(
                "[Pipeline] run_rules complete",
                extra={
                    "rules_run": getattr(state.engine_result, "rules_run", 0),
                    "findings": len(getattr(state.engine_result, "findings", []) or []),
                },
            )
        except Exception as exc:
            logger.exception(
                "[Pipeline] run_rules failed",
                extra={"project_path": context.request.project_path},
            )
            raise RuleExecutionError(
                "Failed to execute rule engine",
                stage="run_rules",
                context={"project_path": context.request.project_path},
            ) from exc
