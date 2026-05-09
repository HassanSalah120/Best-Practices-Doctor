import asyncio
import os
from pathlib import Path

import pytest
from httpx import AsyncClient, ASGITransport

from main import app
from core.job_manager import job_manager


@pytest.fixture
def anyio_backend():
    # JobManager uses asyncio.create_task; restrict these integration tests to asyncio backend.
    return "asyncio"


@pytest.fixture(autouse=True)
def _disable_auth(monkeypatch: pytest.MonkeyPatch):
    # verify_token enforces auth when APP_AUTH_TOKEN is set.
    monkeypatch.delenv("APP_AUTH_TOKEN", raising=False)


@pytest.mark.anyio
async def test_sse_events_endpoint_returns_event_stream(tmp_path: Path):
    # Create a minimal project (native PHP) to keep the scan fast.
    (tmp_path / "index.php").write_text("<?php echo 'ok';\n")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/scan", json={"path": str(tmp_path)})
        assert resp.status_code == 200
        job_id = resp.json()["job_id"]

        async with client.stream("GET", f"/api/scan/{job_id}/events") as sse:
            assert sse.status_code == 200
            assert sse.headers.get("content-type", "").startswith("text/event-stream")
            # Read the first event (JobManager sends initial state immediately).
            first = await sse.aiter_text().__anext__()
            assert "data:" in first


@pytest.mark.anyio
async def test_cancel_endpoint_cancels_running_job(tmp_path: Path):
    # Create a job directly and start a long-running scan coroutine so we can cancel.
    job_id, token = job_manager.create_job(str(tmp_path))

    async def slow_scan(_project_path: str, _ruleset_path: str | None, _job_id: str, _token, _manager):
        await asyncio.sleep(60)
        raise AssertionError("should be cancelled before completion")

    await job_manager.start_job(job_id, slow_scan, str(tmp_path), None)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(f"/api/scan/{job_id}/cancel")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"
