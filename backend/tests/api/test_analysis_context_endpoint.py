from __future__ import annotations

from pathlib import Path

from core.job_manager import job_manager
from schemas.report import ScanReport


def test_analysis_context_endpoint_returns_scan_time_payload(client, auth_headers, tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.php").write_text("<?php\n$value = request('value');\n", encoding="utf-8")

    report = ScanReport(
        id="scan_ctx_test",
        project_path=str(project),
        analysis_debug={
            "analysis_contexts_by_file": {
                "app.php": {
                    "file_path": "app.php",
                    "language": "php",
                    "sources": [{"name": "value", "kind": "request_input", "taint": "tainted"}],
                    "sinks": [],
                    "traces": [],
                },
            },
        },
    )
    job_manager._reports["ctx_job"] = report

    try:
        response = client.get(
            "/api/scan/ctx_job/analysis-context?file=app.php",
            headers=auth_headers,
        )
    finally:
        job_manager._reports.pop("ctx_job", None)

    assert response.status_code == 200
    payload = response.json()
    assert payload["file_path"] == "app.php"
    assert payload["language"] == "php"
    assert payload["sources"][0]["taint"] == "tainted"


def test_analysis_context_endpoint_rejects_path_escape(client, auth_headers, tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    report = ScanReport(id="scan_ctx_escape", project_path=str(project))
    job_manager._reports["ctx_escape_job"] = report

    try:
        response = client.get(
            "/api/scan/ctx_escape_job/analysis-context?file=../secret.php",
            headers=auth_headers,
        )
    finally:
        job_manager._reports.pop("ctx_escape_job", None)

    assert response.status_code == 400
