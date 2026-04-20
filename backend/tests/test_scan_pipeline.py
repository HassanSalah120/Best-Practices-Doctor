from __future__ import annotations

import asyncio

import pytest

from core.job_manager import JobManager
from core.pipeline import ScanError, ScanPipeline, ScanPipelineContext, ScanPipelineRequest
from schemas.report import ScanReport


class _RecorderStage:
    def __init__(self, name: str, bucket: list[str]):
        self.name = name
        self.bucket = bucket

    async def run(self, context, state) -> None:
        self.bucket.append(self.name)
        if self.name == "scoring":
            state.report = ScanReport(id=context.job_id, project_path=context.request.project_path)


class _CriticalFailStage:
    async def run(self, context, state) -> None:
        raise ScanError("boom", stage="run_rules", context={"rule": "x"})


class _NonCriticalFailStage:
    async def run(self, context, state) -> None:
        raise RuntimeError("reporting failed")


def _make_context() -> ScanPipelineContext:
    manager = JobManager()
    job_id, token = manager.create_job("sample")
    request = ScanPipelineRequest(
        project_path="sample",
        ruleset_path=None,
        baseline_profile=None,
        differential_mode=False,
        changed_files=None,
        pr_mode=False,
        pr_gate_preset=None,
        selected_rules=None,
        project_context_overrides=None,
    )
    loop = asyncio.get_running_loop()
    return ScanPipelineContext(
        request=request,
        job_id=job_id,
        token=token,
        manager=manager,
        loop=loop,
    )


@pytest.mark.asyncio
async def test_scan_pipeline_runs_stages_in_order():
    order: list[str] = []
    context = _make_context()
    pipeline = ScanPipeline(
        context,
        detect_stage=_RecorderStage("detect_project", order),
        build_stage=_RecorderStage("build_facts", order),
        run_rules_stage=_RecorderStage("run_rules", order),
        scoring_stage=_RecorderStage("scoring", order),
        reporting_stage=_RecorderStage("reporting", order),
    )

    report = await pipeline.run()

    assert report.id == context.job_id
    assert order == ["detect_project", "build_facts", "run_rules", "scoring", "reporting"]


@pytest.mark.asyncio
async def test_scan_pipeline_stops_on_critical_error():
    context = _make_context()
    pipeline = ScanPipeline(
        context,
        detect_stage=_RecorderStage("detect_project", []),
        build_stage=_RecorderStage("build_facts", []),
        run_rules_stage=_CriticalFailStage(),
        scoring_stage=_RecorderStage("scoring", []),
        reporting_stage=_RecorderStage("reporting", []),
    )

    with pytest.raises(ScanError):
        await pipeline.run()


@pytest.mark.asyncio
async def test_scan_pipeline_continues_on_non_critical_reporting_error():
    context = _make_context()
    pipeline = ScanPipeline(
        context,
        detect_stage=_RecorderStage("detect_project", []),
        build_stage=_RecorderStage("build_facts", []),
        run_rules_stage=_RecorderStage("run_rules", []),
        scoring_stage=_RecorderStage("scoring", []),
        reporting_stage=_NonCriticalFailStage(),
    )

    report = await pipeline.run()
    assert report.id == context.job_id
    assert "reporting" in pipeline.state.warnings
