"""Runtime Contract Guard stage for scan pipeline."""

from __future__ import annotations

import asyncio
import logging

from core.pipeline.models import ScanPipelineContext, ScanPipelineState
from core.runtime_contracts import RuntimeContractAnalyzer
from schemas.report import RuntimeContractSummary

logger = logging.getLogger(__name__)


class ContractChecksStage:
    """Add Laravel route/request/page contract findings before scoring."""

    async def run(self, context: ScanPipelineContext, state: ScanPipelineState) -> None:
        await context.update_progress(82.0, "contract_checks")
        context.check_cancelled()

        if state.facts is None or state.engine_result is None:
            return

        mode = context.request.runtime_contract_mode or "hybrid"
        summary: RuntimeContractSummary
        findings = []
        try:
            analyzer = RuntimeContractAnalyzer()
            summary, findings = await asyncio.to_thread(
                analyzer.analyze,
                facts=state.facts,
                project_path=context.request.project_path,
                mode=mode,
                scope=context.request.runtime_route_scope or "all",
                base_url=context.request.runtime_base_url,
                allow_mutating_probes=bool(context.request.runtime_allow_mutating_probes),
                manual_routes=context.request.runtime_manual_routes,
                changed_files=context.request.changed_files,
            )
        except Exception as exc:
            logger.warning("[Pipeline] Runtime Contract Guard failed and was skipped: %s", exc)
            state.warnings.append("contract_checks")
            summary = RuntimeContractSummary(
                mode=str(mode or "hybrid"),
                scope=str(context.request.runtime_route_scope or "all"),
                warnings=[f"Runtime Contract Guard failed: {exc}"],
            )

        state.runtime_contracts = summary
        if findings:
            state.engine_result.findings.extend(findings)
            logger.info(
                "[Pipeline] contract checks added %s finding(s)",
                len(findings),
            )
        await context.update_progress(85.0, "contract_checks")
