from __future__ import annotations

import shutil
import time
from pathlib import Path


def _poll_report(client, auth_headers, job_id: str, attempts: int = 40, delay_s: float = 0.25) -> dict:
    last = {}
    for _ in range(attempts):
        resp = client.get(f"/api/scan/{job_id}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        last = data
        job = data.get("job", {})
        if job.get("status") == "completed":
            assert "report" in data
            return data["report"]
        if job.get("status") in {"failed", "cancelled"}:
            raise AssertionError(f"Job ended early: {job}")
        time.sleep(delay_s)
    raise AssertionError(f"Timed out waiting for report. Last={last}")


def test_new_issues_delta_between_scans(client, auth_headers, fixture_path, tmp_path: Path):
    # Copy a fixture into a temp project to mutate between scans.
    src = fixture_path / "sample-lara"
    project = tmp_path / "proj"
    shutil.copytree(src, project)

    # First scan: no previous baseline -> new issues should be empty (undefined).
    resp1 = client.post("/api/scan", json={"path": str(project)}, headers=auth_headers)
    assert resp1.status_code == 200
    job_id_1 = resp1.json()["job_id"]
    report1 = _poll_report(client, auth_headers, job_id_1)

    assert report1.get("new_findings_count", 0) == 0
    assert report1.get("new_finding_fingerprints", []) == []

    # Mutate: add an unused private method to introduce a new fingerprint.
    target = project / "app" / "Http" / "Controllers" / "UserController.php"
    text = target.read_text(encoding="utf-8")
    assert "class UserController" in text
    if "private function unusedHelper" not in text:
        text = text.replace(
            "}\n",
            "    private function unusedHelper(): void\n"
            "    {\n"
            "        // intentionally unused\n"
            "    }\n"
            "}\n",
        )
        target.write_text(text, encoding="utf-8")

    # Second scan: compare against baseline from first scan.
    resp2 = client.post("/api/scan", json={"path": str(project)}, headers=auth_headers)
    assert resp2.status_code == 200
    job_id_2 = resp2.json()["job_id"]
    report2 = _poll_report(client, auth_headers, job_id_2)

    new_fps = set(report2.get("new_finding_fingerprints", []) or [])
    assert report2.get("new_findings_count", 0) == len(new_fps)
    assert len(new_fps) >= 1

    # Ensure the new issues list includes the newly introduced unused-private-method finding.
    unused = [f for f in (report2.get("findings", []) or []) if f.get("rule_id") == "unused-private-method"]
    assert unused, "Expected unused-private-method after adding unusedHelper()"
    assert any(f.get("fingerprint") in new_fps for f in unused)

    # Baseline reset: clears new-issues metadata for UI without changing findings.
    reset = client.post(f"/api/scan/{job_id_2}/baseline/reset", headers=auth_headers)
    assert reset.status_code == 200
    updated = reset.json()
    assert updated.get("new_findings_count", 0) == 0
    assert updated.get("new_finding_fingerprints", []) == []

