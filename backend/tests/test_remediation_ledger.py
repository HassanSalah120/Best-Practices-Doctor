from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from core.remediation.ledger import LedgerCorruptionError, RemediationLedger
from core.remediation.models import RemediationRun
from core.remediation.storage import canonical_run_dir


def _run_payload(tmp_path: Path) -> dict:
    run = RemediationRun(
        run_id="rr_test123",
        source_job_id="scan_1",
        project_path=str(tmp_path),
        project_hash="abc123",
        status="draft",
        selected_fingerprints=[],
        tasks=[],
        verification_results=[],
        rescan_comparison=None,
        warnings=[],
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    return run.model_dump(mode="json")


def test_append_load_and_replay(tmp_path):
    ledger = RemediationLedger(tmp_path / "ledger.jsonl")
    e1 = ledger.append("run_created", {"run": _run_payload(tmp_path)})
    e2 = ledger.append("evidence_recorded", {"task_id": "missing"})
    e3 = ledger.append("verification_recorded", {"results": []})

    entries = ledger.load_all()
    assert [e.seq for e in entries] == [1, 2, 3]
    assert e2.prev_hash == e1.self_hash
    assert e3.prev_hash == e2.self_hash
    assert ledger.replay_run() is not None


def test_corrupted_entry_detected(tmp_path):
    ledger = RemediationLedger(tmp_path / "ledger.jsonl")
    ledger.append("run_created", {"run": _run_payload(tmp_path)})
    rows = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    rows[0]["self_hash"] = "bad"
    (tmp_path / "ledger.jsonl").write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    with pytest.raises(LedgerCorruptionError):
        ledger.load_all()


def test_tmp_file_crash_does_not_affect_ledger(tmp_path):
    ledger = RemediationLedger(tmp_path / "ledger.jsonl")
    ledger.append("run_created", {"run": _run_payload(tmp_path)})
    (tmp_path / ".ledger.crashed.tmp").write_text("partial", encoding="utf-8")
    assert len(ledger.load_all()) == 1


def test_path_traversal_run_id_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr("config.settings.app_data_dir", tmp_path)
    with pytest.raises(ValueError):
        canonical_run_dir("abc", "../../../etc")
