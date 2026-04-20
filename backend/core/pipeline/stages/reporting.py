"""Reporting enrichment stage for scan pipeline."""

from __future__ import annotations

import logging
import time

from core.pipeline.models import ScanPipelineContext, ScanPipelineState

logger = logging.getLogger(__name__)


class ReportingStage:
    """Apply optional report enrichments and baseline metadata."""

    async def run(self, context: ScanPipelineContext, state: ScanPipelineState) -> None:
        if state.report is None or state.facts is None:
            return

        await context.update_progress(90.0, "reporting")
        self._apply_hotspots(state)
        self._apply_duration(state)
        self._apply_baseline(state, context)
        self._apply_pr_gate(state, context)
        self._apply_project_memory(state, context)
        self._apply_cache_debug(state, context)
        await context.update_progress(95.0, "reporting")
        logger.info("[Pipeline] reporting enrichments complete")

    def _apply_hotspots(self, state: ScanPipelineState) -> None:
        try:
            from schemas.report import ComplexityHotspot, DuplicationHotspot

            method_by_fqn = {m.method_fqn: m for m in getattr(state.facts, "methods", []) or []}
            hotspots: list[ComplexityHotspot] = []
            for metric in (state.metrics or {}).values():
                if not metric:
                    continue
                method_info = method_by_fqn.get(getattr(metric, "method_fqn", "") or "")
                if not method_info:
                    continue
                hotspots.append(
                    ComplexityHotspot(
                        method_fqn=metric.method_fqn,
                        file=metric.file_path,
                        line_start=int(getattr(method_info, "line_start", 1) or 1),
                        loc=int(getattr(method_info, "loc", 0) or 0),
                        cyclomatic=int(getattr(metric, "cyclomatic_complexity", 1) or 1),
                        cognitive=int(getattr(metric, "cognitive_complexity", 1) or 1),
                        nesting_depth=int(getattr(metric, "nesting_depth", 0) or 0),
                    )
                )
            hotspots.sort(key=lambda item: (-item.cognitive, -item.cyclomatic, item.method_fqn))
            state.report.complexity_hotspots = hotspots[:10]

            dup_raw = getattr(state.facts, "_duplication", None)
            duplication_hotspots: list[DuplicationHotspot] = []
            if isinstance(dup_raw, dict):
                for file_path, data in dup_raw.items():
                    if not isinstance(data, dict):
                        continue
                    pct = float(data.get("duplication_pct", 0.0) or 0.0)
                    if pct <= 0:
                        continue
                    duplication_hotspots.append(
                        DuplicationHotspot(
                            file=str(file_path),
                            duplication_pct=pct,
                            duplicated_tokens=int(data.get("duplicated_tokens", 0) or 0),
                            total_tokens=int(data.get("total_tokens", 0) or 0),
                            duplicate_blocks=int(data.get("duplicate_blocks", 0) or 0),
                        )
                    )
            duplication_hotspots.sort(
                key=lambda item: (-item.duplication_pct, -item.duplicated_tokens, item.file)
            )
            state.report.duplication_hotspots = duplication_hotspots[:10]
        except Exception as exc:
            logger.warning("[Pipeline] Failed to compute hotspots: %s", exc)
            state.warnings.append("reporting:hotspots")

    def _apply_duration(self, state: ScanPipelineState) -> None:
        state.report.duration_ms = round((time.perf_counter() - state.start_time) * 1000)

    def _apply_baseline(self, state: ScanPipelineState, context: ScanPipelineContext) -> None:
        try:
            from core.baseline import update_report_baseline_metadata

            profile_name = (context.request.baseline_profile or getattr(state.ruleset, "name", "startup") or "startup").strip()
            state.baseline_diff = update_report_baseline_metadata(state.report, profile=profile_name)
        except Exception as exc:
            logger.warning("[Pipeline] Failed to compute baseline metadata: %s", exc)
            state.warnings.append("reporting:baseline")

    def _apply_pr_gate(self, state: ScanPipelineState, context: ScanPipelineContext) -> None:
        if not context.request.pr_mode:
            return
        try:
            from core.pr_gate import evaluate_pr_gate

            gate = evaluate_pr_gate(
                state.report,
                preset_name=context.request.pr_gate_preset or getattr(state.ruleset, "name", "startup"),
                profile=context.request.baseline_profile or getattr(state.ruleset, "name", "startup"),
                baseline_diff=state.baseline_diff,
            )
            state.report.pr_gate = {
                "preset": gate.preset,
                "profile": gate.profile,
                "passed": gate.passed,
                "reason": gate.reason,
                "baseline_has_previous": gate.baseline_has_previous,
                "baseline_path": gate.baseline_path,
                "total_new_findings": gate.total_new_findings,
                "eligible_new_findings": gate.eligible_new_findings,
                "blocking_findings_count": gate.blocking_findings_count,
                "blocking_fingerprints": list(gate.blocking_fingerprints),
                "by_severity": dict(gate.by_severity),
                "by_rule": dict(gate.by_rule),
            }
        except Exception as exc:
            logger.warning("[Pipeline] Failed to evaluate PR gate: %s", exc)
            state.warnings.append("reporting:pr_gate")

    def _apply_project_memory(self, state: ScanPipelineState, context: ScanPipelineContext) -> None:
        try:
            from core.project_memory import ProjectIntelligenceManager

            manager = ProjectIntelligenceManager()
            if context.request.project_context_overrides:
                manager.record_context_overrides(
                    context.request.project_path,
                    context.request.project_context_overrides,
                )
            baseline = state.baseline_diff
            if baseline is not None:
                new_fps = list(getattr(baseline, "new_fingerprints", []) or [])
                resolved_fps = list(getattr(baseline, "resolved_fingerprints", []) or [])
                unchanged_fps = list(getattr(baseline, "unchanged_fingerprints", []) or [])
                manager.record_baseline_diff(
                    context.request.project_path,
                    new_count=len(new_fps),
                    resolved_count=len(resolved_fps),
                    unchanged_count=len(unchanged_fps),
                )
        except Exception as exc:
            logger.warning("[Pipeline] Failed to update project memory: %s", exc)
            state.warnings.append("reporting:project_memory")

    def _apply_cache_debug(self, state: ScanPipelineState, context: ScanPipelineContext) -> None:
        cache_stats = {}
        if context.stage_cache is not None:
            try:
                cache_stats = context.stage_cache.get_stats()
            except Exception:
                cache_stats = {}
        state.cache_stats = cache_stats
        state.report.pipeline_cache = dict(cache_stats or {})
        if not isinstance(state.report.analysis_debug, dict):
            state.report.analysis_debug = {}
        state.report.analysis_debug["pipeline_cache"] = dict(cache_stats or {})
