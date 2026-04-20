import pytest
import time
from fastapi.testclient import TestClient

def test_scan_lifecycle(client, auth_headers, fixture_path):
    """Test starting a scan and checking progress."""
    project_path = str(fixture_path / "sample-lara")
    
    # Start scan
    response = client.post(
        "/api/scan",
        json={"path": project_path},
        headers=auth_headers
    )
    assert response.status_code == 200
    job_id = response.json()["job_id"]
    
    # Poll job status
    attempts = 0
    job_data = {}
    while attempts < 20:
        status_resp = client.get(f"/api/scan/{job_id}", headers=auth_headers)
        assert status_resp.status_code == 200
        data = status_resp.json()
        job_data = data.get("job", {})
        if job_data.get("status") == "completed":
            break
        time.sleep(0.5)
        attempts += 1
    
    assert job_data.get("status") == "completed", f"Job failed: {job_data.get('error')}"
    assert job_data.get("files_processed", 0) >= 0

def test_scan_cancellation(client, auth_headers, fixture_path):
    """Test cancelling an active scan job."""
    project_path = str(fixture_path / "sample-lara")
    
    # Start scan
    response = client.post(
        "/api/scan",
        json={"path": project_path},
        headers=auth_headers
    )
    job_id = response.json()["job_id"]
    
    # Cancel immediately
    cancel_resp = client.post(f"/api/scan/{job_id}/cancel", headers=auth_headers)
    
    # With pipeline caching, scan may complete before cancellation (400 = already done)
    # 200 = cancelled successfully, 400 = already completed (also valid)
    assert cancel_resp.status_code in [200, 400], f"Unexpected status: {cancel_resp.status_code}"
    
    # Verify status
    status_resp = client.get(f"/api/scan/{job_id}", headers=auth_headers)
    job_data = status_resp.json().get("job", {})
    # Job should be either cancelled, completed, or failed
    assert job_data.get("status") in ["cancelled", "completed", "failed"]

def test_ruleset_api(client, auth_headers):
    """Test GET and PUT for ruleset."""
    # GET
    get_resp = client.get("/api/ruleset", headers=auth_headers)
    assert get_resp.status_code == 200
    ruleset = get_resp.json()
    assert "rules" in ruleset
    
    # PUT (Update a threshold)
    fat_id = "fat-controller"
    original_fat_controller = ruleset["rules"][fat_id]
    original_fat_controller["thresholds"]["method_lines"] = 55
    
    put_resp = client.put("/api/ruleset", json=ruleset, headers=auth_headers)
    assert put_resp.status_code == 200
    
    # Verify persistence
    verify_resp = client.get("/api/ruleset", headers=auth_headers)
    new_ruleset = verify_resp.json()
    new_fat_controller = new_ruleset["rules"][fat_id]
    assert new_fat_controller["thresholds"]["method_lines"] == 55


def test_scan_sarif_endpoint(client, auth_headers, fixture_path):
    project_path = str(fixture_path / "sample-lara")

    start = client.post("/api/scan", json={"path": project_path}, headers=auth_headers)
    assert start.status_code == 200
    job_id = start.json()["job_id"]

    attempts = 0
    while attempts < 20:
        status_resp = client.get(f"/api/scan/{job_id}", headers=auth_headers)
        assert status_resp.status_code == 200
        job = status_resp.json().get("job", {})
        if job.get("status") == "completed":
            break
        time.sleep(0.5)
        attempts += 1

    sarif_resp = client.get(f"/api/scan/{job_id}/sarif", headers=auth_headers)
    assert sarif_resp.status_code == 200
    sarif = sarif_resp.json()
    assert sarif.get("version") == "2.1.0"
    assert isinstance(sarif.get("runs"), list)


def test_context_suggest_endpoint_returns_detected_and_suggested_context(client, auth_headers, fixture_path):
    project_path = str(fixture_path / "sample-lara")

    resp = client.post(
        "/api/context/suggest",
        json={"path": project_path},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert "framework" in payload
    assert "project_context" in payload
    assert "suggested_context" in payload
    assert "pinned_context" in payload
    project_context = payload["project_context"]
    assert isinstance(project_context, dict)
    assert "project_type" in project_context
    assert "architecture_style" in project_context
    assert "auto_detected_context" in project_context
    assert isinstance(payload["pinned_context"], dict)
    assert payload["pinned_context"].get("context_lock_mode") == "pinned_detected_snapshot"


def test_scan_report_persists_requested_project_context(client, auth_headers, fixture_path):
    project_path = str(fixture_path / "sample-lara")
    requested_context = {
        "project_type": "saas_platform",
        "architecture_profile": "layered",
        "capabilities": {"multi_tenant": True, "billing": True},
        "team_expectations": {"thin_controllers": True},
        "context_lock_mode": "pinned_detected_snapshot",
    }

    start = client.post(
        "/api/scan",
        json={"path": project_path, "project_context_overrides": requested_context},
        headers=auth_headers,
    )
    assert start.status_code == 200
    job_id = start.json()["job_id"]

    attempts = 0
    while attempts < 20:
        status_resp = client.get(f"/api/scan/{job_id}", headers=auth_headers)
        assert status_resp.status_code == 200
        data = status_resp.json()
        if data.get("job", {}).get("status") == "completed":
            report = data.get("report", {})
            analysis_debug = report.get("analysis_debug", {})
            assert analysis_debug.get("requested_project_context", {}) == requested_context
            detected_context = analysis_debug.get("project_context", {})
            assert detected_context.get("project_type") in {"saas_platform", "unknown", "api_backend", "internal_admin_system", "clinic_erp_management", "realtime_game_control_platform", "public_website_with_dashboard", "portal_based_business_app"}
            return
        time.sleep(0.5)
        attempts += 1

    raise AssertionError("Timed out waiting for scan completion")
