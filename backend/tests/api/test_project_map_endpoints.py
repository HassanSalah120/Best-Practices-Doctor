import time


def _wait_for_report(client, auth_headers, job_id: str, attempts: int = 60, delay: float = 0.5):
    for _ in range(attempts):
        resp = client.get(f"/api/scan/{job_id}", headers=auth_headers)
        assert resp.status_code == 200
        payload = resp.json()
        status = payload.get("job", {}).get("status")
        if status == "completed":
            return payload.get("report", {})
        if status in {"failed", "cancelled"}:
            raise AssertionError(f"scan did not complete (status={status})")
        time.sleep(delay)
    raise AssertionError("timed out waiting for scan completion")


def test_project_map_endpoints_return_expected_shape(client, auth_headers, fixture_path):
    project_path = str(fixture_path / "sample-lara")
    start = client.post("/api/scan", json={"path": project_path}, headers=auth_headers)
    assert start.status_code == 200
    job_id = start.json()["job_id"]

    _wait_for_report(client, auth_headers, job_id)

    map_resp = client.get(f"/api/scan/{job_id}/project-map", headers=auth_headers)
    assert map_resp.status_code == 200
    map_payload = map_resp.json()
    assert "nodes" in map_payload and isinstance(map_payload["nodes"], list)
    assert "edges" in map_payload and isinstance(map_payload["edges"], list)
    assert "hierarchy" in map_payload and isinstance(map_payload["hierarchy"], dict)
    assert "insights" in map_payload and isinstance(map_payload["insights"], dict)
    assert "explainer" in map_payload and isinstance(map_payload["explainer"], dict)

    latest_map_resp = client.get("/api/project-map", headers=auth_headers)
    assert latest_map_resp.status_code == 200
    latest_map_payload = latest_map_resp.json()
    assert latest_map_payload.get("job_id") == job_id
    assert isinstance(latest_map_payload.get("nodes"), list)


def test_project_explainer_endpoints_support_filters(client, auth_headers, fixture_path):
    project_path = str(fixture_path / "sample-lara")
    start = client.post("/api/scan", json={"path": project_path}, headers=auth_headers)
    assert start.status_code == 200
    job_id = start.json()["job_id"]
    _wait_for_report(client, auth_headers, job_id)

    explainer_resp = client.get(f"/api/scan/{job_id}/project-explainer", headers=auth_headers)
    assert explainer_resp.status_code == 200
    payload = explainer_resp.json()
    assert payload.get("job_id") == job_id
    assert isinstance(payload.get("explainer"), dict)
    assert isinstance(payload.get("filters"), dict)
    assert "endpoint_catalog" in payload["explainer"]
    assert "endpoint_flows" in payload["explainer"]
    assert "function_dependency_index" in payload["explainer"]

    filtered_resp = client.get(
        f"/api/scan/{job_id}/project-explainer?framework=laravel&problems_only=true",
        headers=auth_headers,
    )
    assert filtered_resp.status_code == 200
    filtered = filtered_resp.json()
    assert filtered["filters"]["framework"] == "laravel"
    assert filtered["filters"]["problems_only"] is True

    latest_resp = client.get("/api/project-explainer", headers=auth_headers)
    assert latest_resp.status_code == 200
    latest_payload = latest_resp.json()
    assert latest_payload.get("job_id") == job_id

