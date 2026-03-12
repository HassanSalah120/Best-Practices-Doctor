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
    assert cancel_resp.status_code == 200
    
    # Verify status
    status_resp = client.get(f"/api/scan/{job_id}", headers=auth_headers)
    job_data = status_resp.json().get("job", {})
    assert job_data.get("status") in ["cancelled", "failed"]

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
