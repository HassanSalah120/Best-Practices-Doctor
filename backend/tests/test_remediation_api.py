from __future__ import annotations

from pathlib import Path

from core.job_manager import job_manager
from core.rule_engine import REGISTERED_RULES
from schemas.finding import Category, Finding, Severity
from schemas.report import ScanReport


class ApiRule:
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Replace the risky pattern with the approved project helper."
    false_positive_notes = "Check whether this is a generated file before editing."
    related_rules = []
    group = "api"
    auto_fixable = False


def _finding(fp: str = "fp1") -> Finding:
    return Finding(
        fingerprint=fp,
        rule_id="api-rule",
        title="API rule finding",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        file="app/Foo.php",
        line_start=1,
        description="desc",
        why_it_matters="why",
        suggested_fix="raw",
    )


def _install_report(tmp_path: Path, job_id: str = "scan_api") -> ScanReport:
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text('{"scripts":{"test":"vitest"}}', encoding="utf-8")
    report = ScanReport(id=job_id, project_path=str(project), findings=[_finding("fp1"), _finding("fp2")])
    job_manager._reports[job_id] = report
    return report


def test_create_run_and_agent_package(client, tmp_path):
    old = dict(REGISTERED_RULES)
    try:
        REGISTERED_RULES["api-rule"] = ApiRule
        _install_report(tmp_path)
        response = client.post("/api/scan/scan_api/remediation-runs", json={"selected_fingerprints": ["fp1"]})
        assert response.status_code == 201, response.text
        run = response.json()
        assert run["tasks"]
        run_id = run["run_id"]

        package = client.get(f"/api/remediation-runs/{run_id}/agent-package")
        assert package.status_code == 200
        assert "Replace the risky pattern" in package.json()["markdown"]
        assert "Operating Protocol" in package.json()["markdown"]
        assert "verifiable goal" in package.json()["markdown"]
        assert package.json()["json_payload"]["run_id"] == run_id
        assert "operating_protocol" in package.json()["json_payload"]
    finally:
        REGISTERED_RULES.clear()
        REGISTERED_RULES.update(old)


def test_create_run_requires_selection(client, tmp_path):
    _install_report(tmp_path)
    response = client.post("/api/scan/scan_api/remediation-runs", json={})
    assert response.status_code == 400


def test_get_run_replays_ledger_and_evidence_ownership(client, tmp_path):
    old = dict(REGISTERED_RULES)
    try:
        REGISTERED_RULES["api-rule"] = ApiRule
        _install_report(tmp_path)
        run = client.post("/api/scan/scan_api/remediation-runs", json={"use_top_n": 1}).json()
        run_id = run["run_id"]
        task_id = run["tasks"][0]["task_id"]

        forbidden = client.post(
            f"/api/remediation-runs/{run_id}/tasks/{task_id}/evidence",
            json={"agent_notes": "bad", "files_changed": [], "strategy_applied": "guided_edit", "project_hash": "wrong"},
        )
        assert forbidden.status_code == 403

        ok = client.post(
            f"/api/remediation-runs/{run_id}/tasks/{task_id}/evidence",
            json={"agent_notes": "started", "files_changed": ["app/Foo.php"], "strategy_applied": "guided_edit"},
        )
        assert ok.status_code == 200
        loaded = client.get(f"/api/remediation-runs/{run_id}")
        assert loaded.status_code == 200
        assert loaded.json()["tasks"][0]["state"] == "in_progress"
    finally:
        REGISTERED_RULES.clear()
        REGISTERED_RULES.update(old)


def test_unknown_run_evidence_rejected(client):
    response = client.post(
        "/api/remediation-runs/rr_missing/tasks/task/evidence",
        json={"agent_notes": "", "files_changed": [], "strategy_applied": "guided_edit"},
    )
    assert response.status_code == 404
