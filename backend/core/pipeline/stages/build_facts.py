"""Facts and metrics stage for scan pipeline."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from analysis.facts_builder import FactsBuilder
from analysis.metrics_analyzer import MetricsAnalyzer
from core.context_profiles import load_laravel_context_matrix, load_react_context_matrix
from core.pipeline.errors import FactBuildError
from core.pipeline.models import ScanPipelineContext, ScanPipelineState
from core.ruleset import Ruleset

logger = logging.getLogger(__name__)


class BuildFactsStage:
    """Resolve ruleset, build facts, and derive method metrics."""

    async def run(self, context: ScanPipelineContext, state: ScanPipelineState) -> None:
        await context.update_progress(10.0, "parsing")
        context.check_cancelled()

        if state.project_info is None:
            raise FactBuildError(
                "Project info is missing before facts build",
                stage="build_facts",
                context={"project_path": context.request.project_path},
            )

        ruleset = self._resolve_ruleset(context)
        state.ruleset = ruleset
        context_matrix = self._load_context_matrix_for_project(state.project_info)
        cache_payload = {
            "ruleset_path": str(getattr(ruleset, "source_path", "") or ""),
            "ruleset_name": str(getattr(ruleset, "name", "") or ""),
            "selected_rules": sorted(context.request.selected_rules or []),
            "context_overrides": dict(context.request.project_context_overrides or {}),
            "max_file_size_kb": int(getattr(ruleset.scan, "max_file_size_kb", 0) or 0),
            "max_files": int(getattr(ruleset.scan, "max_files", 0) or 0),
            "ignore_patterns": list(getattr(ruleset.scan, "ignore", []) or []),
            "context_matrix_framework": str(getattr(context_matrix, "framework", "laravel") or "laravel"),
        }
        if context.stage_cache is not None:
            cached = context.stage_cache.load("build_facts", cache_payload)
            if isinstance(cached, dict) and "facts" in cached and "metrics" in cached:
                state.facts = cached.get("facts")
                state.metrics = dict(cached.get("metrics") or {})
                logger.info("[Pipeline] build_facts cache hit")
                return

        builder = FactsBuilder(
            project_info=state.project_info,
            ignore_patterns=ruleset.scan.ignore,
            cancellation_check=context.token.is_cancelled,
            max_file_size_kb=ruleset.scan.max_file_size_kb,
            max_files=ruleset.scan.max_files,
            context_overrides=context.request.project_context_overrides,
            context_matrix=context_matrix,
        )

        def on_facts_progress(progress) -> None:
            if progress.total_files <= 0:
                return
            pct = 10.0 + (progress.files_processed / progress.total_files) * 40.0
            context.schedule_progress(
                pct,
                "parsing",
                current_file=progress.current_file,
                files_processed=progress.files_processed,
                files_total=progress.total_files,
            )

        try:
            state.facts = await asyncio.to_thread(builder.build, on_facts_progress)
            context.check_cancelled()
            analyzer = MetricsAnalyzer()
            state.metrics = analyzer.analyze(state.facts)
            if context.stage_cache is not None and state.facts is not None:
                context.stage_cache.save(
                    "build_facts",
                    {"facts": state.facts, "metrics": state.metrics},
                    cache_payload,
                )
            logger.info(
                "[Pipeline] build_facts complete",
                extra={
                    "files": len(getattr(state.facts, "files", []) or []),
                    "classes": len(getattr(state.facts, "classes", []) or []),
                    "methods": len(getattr(state.facts, "methods", []) or []),
                },
            )
        except Exception as exc:
            logger.exception(
                "[Pipeline] build_facts failed",
                extra={"project_path": context.request.project_path},
            )
            raise FactBuildError(
                "Failed to build facts or metrics",
                stage="build_facts",
                context={"project_path": context.request.project_path},
            ) from exc

    def _resolve_ruleset(self, context: ScanPipelineContext) -> Ruleset:
        request = context.request
        ruleset: Ruleset | None = None

        if request.ruleset_path:
            try:
                ruleset = Ruleset.load(request.ruleset_path)
            except Exception:
                logger.warning(
                    "[Pipeline] Unable to load explicit ruleset override",
                    extra={"ruleset_path": request.ruleset_path},
                )

        if ruleset is None and request.baseline_profile:
            try:
                from core.ruleset_profiles import get_profile_path

                profile_path = get_profile_path(request.baseline_profile)
                if profile_path:
                    ruleset = Ruleset.load(Path(profile_path))
            except Exception:
                logger.warning(
                    "[Pipeline] Unable to load baseline profile ruleset",
                    extra={"baseline_profile": request.baseline_profile},
                )

        if ruleset is None:
            ruleset = Ruleset.load_default(override_path=request.ruleset_path)

        return ruleset

    def _load_context_matrix_for_project(self, project_info) -> object:
        """Load Laravel/React context matrix based on static project type signals."""
        project_type = str(
            getattr(getattr(project_info, "project_type", None), "value", "")
            or getattr(project_info, "project_type", "")
            or ""
        ).lower()
        if project_type.startswith("laravel"):
            return load_laravel_context_matrix()
        has_react = bool(getattr(project_info, "has_react_components", False))
        npm_packages = dict(getattr(project_info, "npm_packages", {}) or {})
        if "react" in project_type or has_react or "react" in npm_packages:
            try:
                return load_react_context_matrix()
            except Exception:
                logger.warning("[Pipeline] Falling back to Laravel matrix after React matrix load failure")
        return load_laravel_context_matrix()
