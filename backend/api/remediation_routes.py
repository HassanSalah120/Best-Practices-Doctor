"""API routes for Remediation Runs."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from core.job_manager import job_manager
from core.remediation.agent_package import build_agent_package, write_project_mirror
from core.remediation.ledger import LedgerCorruptionError, RemediationLedger
from core.remediation.models import RemediationRun
from core.remediation.rescan import compare_scans
from core.remediation.runner import run_verification
from core.remediation.storage import (
    canonical_run_dir,
    find_run_dir,
    ledger_path,
    list_run_dirs_for_job,
    project_hash_for_path,
    validate_run_id,
    write_snapshot,
)
from core.remediation.task_builder import build_tasks
from core.rule_engine import REGISTERED_RULES


remediation_router = APIRouter()


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateRemediationRunRequest(StrictRequest):
    selected_fingerprints: list[str] = Field(default_factory=list)
    use_top_n: int | None = Field(default=None, ge=1, le=50)
    label: str | None = None


class EvidenceRequest(StrictRequest):
    agent_notes: str = ""
    files_changed: list[str] = Field(default_factory=list)
    strategy_applied: str = ""
    project_hash: str | None = None


class RescanCompareRequest(StrictRequest):
    rescan_job_id: str


@remediation_router.post("/scan/{job_id}/remediation-runs", status_code=201)
async def create_remediation_run(job_id: str, request: CreateRemediationRunRequest):
    report = job_manager.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {job_id}")
    if not request.selected_fingerprints and request.use_top_n is None:
        raise HTTPException(status_code=400, detail="selected_fingerprints or use_top_n is required")

    selected = list(request.selected_fingerprints)
    if request.use_top_n is not None:
        selected = _select_top_fingerprints(report, request.use_top_n)

    run_id = f"rr_{uuid.uuid4().hex[:12]}"
    project_hash = project_hash_for_path(report.project_path)
    tasks = build_tasks(report, selected)
    now = datetime.now(timezone.utc)
    run = RemediationRun(
        run_id=run_id,
        source_job_id=job_id,
        project_path=str(Path(report.project_path).resolve()),
        project_hash=project_hash,
        status="draft",
        selected_fingerprints=selected,
        tasks=tasks,
        verification_results=[],
        rescan_comparison=None,
        warnings=[],
        created_at=now,
        updated_at=now,
    )
    run.warnings.extend(write_project_mirror(run))
    _write_agent_package_files(run)

    ledger = RemediationLedger(ledger_path(project_hash, run_id))
    ledger.append("run_created", {"run": run.model_dump(mode="json"), "label": request.label or ""})
    write_snapshot(project_hash, run_id, run.model_dump(mode="json"))
    return run.model_dump(mode="json")


@remediation_router.get("/scan/{job_id}/remediation-runs")
async def list_remediation_runs(job_id: str):
    runs: list[dict[str, Any]] = []
    for run_dir in list_run_dirs_for_job(job_id):
        try:
            run = _load_run_from_dir(run_dir)
        except Exception:
            continue
        runs.append(run.model_dump(mode="json"))
    runs.sort(key=lambda r: str(r.get("created_at", "")), reverse=True)
    return {"runs": runs, "total": len(runs)}


@remediation_router.get("/remediation-runs/{run_id}")
async def get_remediation_run(run_id: str):
    return _load_run(run_id).model_dump(mode="json")


@remediation_router.get("/remediation-runs/{run_id}/agent-package")
async def get_agent_package(run_id: str):
    return build_agent_package(_load_run(run_id))


@remediation_router.post("/remediation-runs/{run_id}/tasks/{task_id}/evidence")
async def record_task_evidence(run_id: str, task_id: str, request: EvidenceRequest):
    run = _load_run(run_id)
    _validate_run_ownership(run, request.project_hash)
    if not any(task.task_id == task_id for task in run.tasks):
        raise HTTPException(status_code=404, detail=f"Task not found: {task_id}")
    entry = _ledger_for_run(run).append(
        "evidence_recorded",
        {
            "task_id": task_id,
            "agent_notes": request.agent_notes,
            "files_changed": request.files_changed,
            "strategy_applied": request.strategy_applied,
        },
    )
    updated = _load_run(run_id)
    write_snapshot(updated.project_hash, updated.run_id, updated.model_dump(mode="json"))
    return {"recorded": True, "ledger_seq": entry.seq, "run": updated.model_dump(mode="json")}


@remediation_router.post("/remediation-runs/{run_id}/verify")
async def verify_remediation_run(run_id: str):
    run = _load_run(run_id)
    _validate_run_ownership(run, None)
    commands = sorted({cmd for task in run.tasks for cmd in task.verification_commands})
    if not commands:
        commands = ["echo 'No verification commands detected'"]
    results = await run_verification(commands, Path(run.project_path))
    _ledger_for_run(run).append(
        "verification_recorded",
        {"results": [result.model_dump(mode="json") for result in results]},
    )
    updated = _load_run(run_id)
    write_snapshot(updated.project_hash, updated.run_id, updated.model_dump(mode="json"))
    return {
        "verification_started": True,
        "results": [result.model_dump(mode="json") for result in results],
        "run": updated.model_dump(mode="json"),
    }


@remediation_router.post("/remediation-runs/{run_id}/rescan")
async def start_remediation_rescan(run_id: str):
    run = _load_run(run_id)
    _validate_run_ownership(run, None)
    from api.routes import run_scan

    job_id, _token = job_manager.create_job(run.project_path)
    await job_manager.start_job(
        job_id,
        run_scan,
        run.project_path,
        None,
        None,
        False,
        None,
        False,
        None,
        None,
        None,
        "hybrid",
        "all",
        None,
        False,
        None,
    )
    return {"rescan_job_id": job_id, "status": "scanning"}


@remediation_router.post("/remediation-runs/{run_id}/rescan/compare")
async def compare_remediation_rescan(run_id: str, request: RescanCompareRequest):
    run = _load_run(run_id)
    _validate_run_ownership(run, None)
    baseline_report = job_manager.get_report(run.source_job_id)
    rescan_report = job_manager.get_report(request.rescan_job_id)
    if not baseline_report:
        raise HTTPException(status_code=404, detail=f"Baseline report not found: {run.source_job_id}")
    if not rescan_report:
        raise HTTPException(status_code=404, detail=f"Rescan report not found: {request.rescan_job_id}")
    comparison = compare_scans(baseline_report, rescan_report, run_id)
    _ledger_for_run(run).append("rescan_recorded", {"comparison": comparison.model_dump(mode="json")})
    updated = _load_run(run_id)
    write_snapshot(updated.project_hash, updated.run_id, updated.model_dump(mode="json"))
    return comparison.model_dump(mode="json")


def _select_top_fingerprints(report, top_n: int) -> list[str]:
    def key(finding) -> tuple[int, float, str]:
        rule = REGISTERED_RULES.get(str(finding.rule_id))
        weight = int(getattr(rule, "severity_weight", 5) or 5) if rule else 5
        confidence = float(getattr(finding, "confidence", 0.0) or 0.0)
        return (weight, confidence, str(finding.fingerprint))

    ranked = sorted(report.findings, key=key, reverse=True)
    return [str(f.fingerprint) for f in ranked[:top_n]]


def _load_run(run_id: str) -> RemediationRun:
    try:
        run_dir = find_run_dir(validate_run_id(run_id))
        return _load_run_from_dir(run_dir)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Remediation run not found: {run_id}") from exc
    except LedgerCorruptionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _load_run_from_dir(run_dir: Path) -> RemediationRun:
    run = RemediationLedger(run_dir / "ledger.jsonl").replay_run()
    if run is None:
        raise FileNotFoundError(str(run_dir))
    return run


def _ledger_for_run(run: RemediationRun) -> RemediationLedger:
    return RemediationLedger(ledger_path(run.project_hash, run.run_id))


def _validate_run_ownership(run: RemediationRun, provided_project_hash: str | None) -> None:
    actual = project_hash_for_path(run.project_path)
    if actual != run.project_hash:
        raise HTTPException(status_code=403, detail="Remediation run ownership validation failed")
    if provided_project_hash and str(provided_project_hash) != run.project_hash:
        raise HTTPException(status_code=403, detail="Remediation run project_hash mismatch")


def _write_agent_package_files(run: RemediationRun) -> None:
    package = build_agent_package(run)
    root = canonical_run_dir(run.project_hash, run.run_id) / "agent-package"
    root.mkdir(parents=True, exist_ok=True)
    (root / "REMEDIATION.md").write_text(package["files"]["REMEDIATION.md"], encoding="utf-8")
    (root / "agent-package.json").write_text(
        json.dumps(package["json_payload"], indent=2, ensure_ascii=True, default=str),
        encoding="utf-8",
    )
