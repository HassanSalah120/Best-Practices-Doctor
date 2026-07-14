"""Scoring/report generation stage for scan pipeline."""

from __future__ import annotations

import asyncio
import logging

from core.pipeline.errors import ScoringError
from core.pipeline.cache_signatures import implementation_signature, stable_signature
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
            "runtime_contract_mode": str(context.request.runtime_contract_mode or "hybrid"),
            "runtime_route_scope": str(context.request.runtime_route_scope or "all"),
            "findings_sig": findings_sig,
            "files_count": len(getattr(state.facts, "files", []) or []),
            "methods_count": len(getattr(state.facts, "methods", []) or []),
            "ruleset_signature": stable_signature(state.ruleset),
            "implementation_signature": implementation_signature([ScoringEngine]),
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
                    rules_executed=self._rule_ids_for_report(state),
                )
                if context.stage_cache is not None and state.report is not None:
                    context.stage_cache.save("scoring", state.report, cache_payload)
            # Ensure job-scoped identity remains correct even when scoring cache is reused.
            state.report.id = context.job_id
            state.report.project_path = context.request.project_path
            for rule_id in self._rule_ids_for_report(state):
                if rule_id not in (state.report.rules_executed or []):
                    state.report.rules_executed.append(rule_id)
            if not isinstance(state.report.analysis_debug, dict):
                state.report.analysis_debug = {}
            state.report.runtime_contracts = state.runtime_contracts
            if state.runtime_contracts is not None:
                state.report.analysis_debug["runtime_contracts"] = {
                    "mode": state.runtime_contracts.mode,
                    "scope": state.runtime_contracts.scope,
                    "routes_total": state.runtime_contracts.routes_total,
                    "static_checked": state.runtime_contracts.static_checked,
                    "runtime_probed": state.runtime_contracts.runtime_probed,
                    "issues": len(state.runtime_contracts.issues),
                    "generated_tests": state.runtime_contracts.generated_tests,
                    "skipped": dict(state.runtime_contracts.skipped),
                    "warnings": list(state.runtime_contracts.warnings),
                }
            state.report.analysis_debug["requested_project_context"] = dict(
                context.request.project_context_overrides or {},
            )
            state.report.analysis_debug["analysis_performance"] = {
                "facts": dict(getattr(state.facts, "analysis_stats", {}) or {}),
                "rules": dict(getattr(state.engine_result, "analysis_stats", {}) or {}),
                "rule_engine_ms": round(float(getattr(state.engine_result, "execution_time_ms", 0.0) or 0.0), 3),
            }
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

    def _rule_ids_for_report(self, state: ScanPipelineState) -> list[str]:
        rule_ids = list(state.rule_engine.get_rule_ids() if state.rule_engine else [])
        runtime_contracts = state.runtime_contracts
        if runtime_contracts is not None and getattr(runtime_contracts, "mode", "off") != "off":
            if "runtime-contract-guard" not in rule_ids:
                rule_ids.append("runtime-contract-guard")
        return rule_ids
