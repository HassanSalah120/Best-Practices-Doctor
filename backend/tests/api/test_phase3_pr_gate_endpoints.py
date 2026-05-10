from __future__ import annotations

import shutil
import time
from pathlib import Path


def _poll_report(client, auth_headers, job_id: str, attempts: int = 50, delay_s: float = 0.25) -> dict:
    last = {}
    for _ in range(attempts):
        resp = client.get(f"/api/scan/{job_id}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        last = data
        status = data.get("job", {}).get("status")
        if status == "completed":
            return data.get("report", {})
        if status in {"failed", "cancelled"}:
            raise AssertionError(f"scan failed: {data.get('job')}")
        time.sleep(delay_s)
    raise AssertionError(f"timed out waiting for scan completion, last={last}")


def test_phase3_pr_gate_endpoint_blocks_new_high_regression(client, auth_headers, fixture_path, tmp_path: Path):
    src = fixture_path / "sample-lara"
    project = tmp_path / "proj"
    shutil.copytree(src, project)

    # First scan creates baseline.
    s1 = client.post("/api/scan", json={"path": str(project)}, headers=auth_headers)
    assert s1.status_code == 200
    r1 = _poll_report(client, auth_headers, s1.json()["job_id"])
    assert r1.get("new_findings_count", 0) == 0

    # Inject a high-severity security issue (unsafe-eval).
    target = project / "app" / "Http" / "Controllers" / "UserController.php"
    txt = target.read_text(encoding="utf-8")
    if "public function dangerousEval" not in txt:
        txt = txt.replace(
            "}\n",
            "    public function dangerousEval($payload)\n"
            "    {\n"
            "        return eval($payload);\n"
            "    }\n"
            "}\n",
        )
        target.write_text(txt, encoding="utf-8")

    # Second scan should report new finding(s) vs prior baseline.
    s2 = client.post("/api/scan", json={"path": str(project)}, headers=auth_headers)
    assert s2.status_code == 200
    job2 = s2.json()["job_id"]
    r2 = _poll_report(client, auth_headers, job2)
    assert r2.get("new_findings_count", 0) >= 1

    gate = client.get(
        f"/api/scan/{job2}/pr-gate?preset=startup&include_sarif=true",
        headers=auth_headers,
    )
    assert gate.status_code == 200
    payload = gate.json()
    assert payload.get("preset") == "startup"
    assert payload.get("total_new_findings", 0) >= 1
    assert payload.get("blocking_findings_count", 0) >= 1
    assert payload.get("passed") is False
    assert payload.get("sarif", {}).get("version") == "2.1.0"


def test_phase3_baseline_compare_and_save_endpoints(client, auth_headers, fixture_path, tmp_path: Path):
    src = fixture_path / "sample-lara"
    project = tmp_path / "proj"
    shutil.copytree(src, project)

    start = client.post("/api/scan", json={"path": str(project)}, headers=auth_headers)
    assert start.status_code == 200
    job_id = start.json()["job_id"]
    _ = _poll_report(client, auth_headers, job_id)

    cmp_resp = client.get(f"/api/scan/{job_id}/baseline", headers=auth_headers)
    assert cmp_resp.status_code == 200
    cmp_data = cmp_resp.json()
    assert cmp_data.get("profile") in {"startup", "balanced", "strict", "default"}
    assert cmp_data.get("has_baseline") is True
    assert isinstance(cmp_data.get("baseline_path"), str)
    assert cmp_data.get("new_findings_count", 0) == 0

    save_resp = client.post(f"/api/scan/{job_id}/baseline/save", headers=auth_headers)
    assert save_resp.status_code == 200
    saved = save_resp.json()
    assert saved.get("new_findings_count", 0) == 0
    assert saved.get("new_finding_fingerprints", []) == []

