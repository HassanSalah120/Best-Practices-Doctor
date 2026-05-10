from pathlib import Path

import pytest

from api import routes
from core.fix_history import FixHistoryConflictError, FixHistoryManager
from core.incremental import IncrementalScanManager
from core.job_manager import CancellationToken, JobManager, job_manager
from core.scan_history import ScanHistoryManager
from schemas.finding import Category, Finding, Severity
from schemas.report import QualityScores, ScanReport


def _log_debug_finding() -> Finding:
    return Finding(
        rule_id="no-log-debug-in-app",
        file="app/Services/PaymentService.php",
        line_start=9,
        line_end=9,
        title="Log::debug in application code",
        description="Log::debug should not be used in production code",
        why_it_matters="Debug logs can expose sensitive information",
        suggested_fix="Use Log::info instead",
        category=Category.LARAVEL_BEST_PRACTICE,
        severity=Severity.LOW,
    )


def _sample_php() -> str:
    return """<?php

namespace App\\Services;

class PaymentService
{
    public function process($amount)
    {
        Log::debug("Processing payment");
        return $amount;
    }
}
"""


def test_fix_history_undo_redo_and_conflict(tmp_path: Path):
    file_path = tmp_path / "app" / "Service.php"
    file_path.parent.mkdir(parents=True)
    before = "<?php\nLog::debug('x');\n"
    after = "<?php\nLog::info('x');\n"
    file_path.write_text(after, encoding="utf-8")

    manager = FixHistoryManager(tmp_path)
    entry = manager.record_apply(
        job_id="job-1",
        file="app/Service.php",
        line_start=2,
        rule_id="no-log-debug-in-app",
        title="Replace debug log",
        before_content=before,
        after_content=after,
    )

    undone = manager.undo(entry.id)
    assert undone.undone is True
    assert file_path.read_text(encoding="utf-8") == before

    redone = manager.redo(entry.id)
    assert redone.undone is False
    assert file_path.read_text(encoding="utf-8") == after

    file_path.write_text("<?php\nLog::warning('external');\n", encoding="utf-8")
    with pytest.raises(FixHistoryConflictError):
        manager.undo(entry.id)


def test_apply_fix_route_records_history_and_undo_redo_api(client, tmp_path: Path):
    project = tmp_path / "project"
    target = project / "app" / "Services" / "PaymentService.php"
    target.parent.mkdir(parents=True)
    target.write_text(_sample_php(), encoding="utf-8")

    job_id, _ = job_manager.create_job(str(project))
    job_manager._reports[job_id] = ScanReport(
        id=job_id,
        project_path=str(project),
        findings=[_log_debug_finding()],
    )

    try:
        apply_resp = client.post(
            f"/api/scan/{job_id}/fixes/app/Services/PaymentService.php/apply?line_start=9&dry_run=false",
        )
        assert apply_resp.status_code == 200
        history_entry = apply_resp.json()["history_entry"]
        assert history_entry["rule_id"] == "no-log-debug-in-app"
        assert "Log::info" in target.read_text(encoding="utf-8")

        history_resp = client.get(f"/api/scan/{job_id}/fixes/history")
        assert history_resp.status_code == 200
        assert history_resp.json()["total"] == 1

        undo_resp = client.post(f"/api/scan/{job_id}/fixes/history/{history_entry['id']}/undo")
        assert undo_resp.status_code == 200
        assert "Log::debug" in target.read_text(encoding="utf-8")

        redo_resp = client.post(f"/api/scan/{job_id}/fixes/history/{history_entry['id']}/redo")
        assert redo_resp.status_code == 200
        assert "Log::info" in target.read_text(encoding="utf-8")
    finally:
        job_manager.cleanup_job(job_id)


def test_suppression_route_adds_by_fingerprint_and_deletes_by_id(client, tmp_path: Path):
    finding = _log_debug_finding()
    job_id, _ = job_manager.create_job(str(tmp_path))
    job_manager._reports[job_id] = ScanReport(
        id=job_id,
        project_path=str(tmp_path),
        findings=[finding],
    )

    try:
        add_resp = client.post(
            f"/api/scan/{job_id}/suppressions",
            json={"fingerprint": finding.fingerprint, "reason": "Known legacy line"},
        )
        assert add_resp.status_code == 200
        payload = add_resp.json()
        assert payload["id"].startswith("suppress-")
        assert payload["rule_id"] == finding.rule_id
        assert payload["file_pattern"] == finding.file
        assert payload["line_start"] == finding.line_start

        list_resp = client.get(f"/api/scan/{job_id}/suppressions")
        assert list_resp.status_code == 200
        assert list_resp.json()["suppressions"][0]["id"] == payload["id"]

        delete_resp = client.delete(f"/api/scan/{job_id}/suppressions/{payload['id']}")
        assert delete_resp.status_code == 200
    finally:
        job_manager.cleanup_job(job_id)


def test_project_changed_files_preflight_uses_incremental_manifest(client, tmp_path: Path):
    project = tmp_path / "project"
    target = project / "app" / "Example.php"
    target.parent.mkdir(parents=True)
    target.write_text("<?php\nclass Example {}\n", encoding="utf-8")

    first = client.post("/api/project/changes", json={"path": str(project)})
    assert first.status_code == 200
    assert "app/Example.php" in first.json()["changes"]["added"]

    IncrementalScanManager(project).update_manifest(["app/Example.php"])
    target.write_text("<?php\nclass Example { public function changed() {} }\n", encoding="utf-8")

    second = client.post("/api/project/changes", json={"path": str(project)})
    assert second.status_code == 200
    assert "app/Example.php" in second.json()["changes"]["modified"]


def test_scan_history_uses_report_contract_and_trends(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    manager = ScanHistoryManager(app_data_dir=tmp_path / "history")

    first = ScanReport(
        id="scan-one",
        project_path=str(project),
        scores=QualityScores(overall=70.0, grade="C"),
        duration_ms=125,
        files_scanned=3,
    )
    duplicate_first = ScanReport(
        id="scan-one",
        project_path=str(project),
        scores=QualityScores(overall=72.0, grade="C"),
        duration_ms=150,
        files_scanned=4,
    )
    second = ScanReport(
        id="scan-two",
        project_path=str(project),
        scores=QualityScores(overall=84.0, grade="B"),
        duration_ms=200,
        files_scanned=5,
    )

    summary = manager.add_scan(first, profile="startup")
    assert summary.job_id == "scan-one"
    assert summary.overall_score == 70.0
    assert summary.execution_time_ms == 125

    manager.add_scan(duplicate_first, profile="startup")
    manager.add_scan(second, profile="strict")
    history = manager.get_history_by_path(str(project))
    assert [scan.job_id for scan in history.scans] == ["scan-one", "scan-two"]

    trend = manager.get_trend(history.project_hash)
    assert trend["direction"] == "improving"
    assert trend["score_change"] == 12.0


@pytest.mark.asyncio
async def test_run_scan_forwards_compact_mode_options(monkeypatch, tmp_path: Path):
    captured = {}

    async def fake_pipeline(request, job_id, token, manager):
        captured["request"] = request
        captured["job_id"] = job_id
        return ScanReport(id=job_id, project_path=request.project_path)

    monkeypatch.setattr(routes, "run_scan_pipeline", fake_pipeline)

    report = await routes.run_scan(
        str(tmp_path),
        None,
        "balanced",
        True,
        ["app/Changed.php"],
        True,
        "strict",
        ["no-log-debug-in-app"],
        {"project_type": "saas"},
        "hybrid",
        "all",
        "http://127.0.0.1:8000",
        False,
        None,
        "scan-options",
        CancellationToken(),
        JobManager(),
    )

    request = captured["request"]
    assert report.id == "scan-options"
    assert request.baseline_profile == "balanced"
    assert request.differential_mode is True
    assert request.changed_files == ["app/Changed.php"]
    assert request.pr_mode is True
    assert request.pr_gate_preset == "strict"
    assert request.selected_rules == ["no-log-debug-in-app"]
    assert request.project_context_overrides == {"project_type": "saas"}
    assert request.runtime_contract_mode == "hybrid"
    assert request.runtime_route_scope == "all"
    assert request.runtime_base_url == "http://127.0.0.1:8000"
    assert request.runtime_allow_mutating_probes is False
