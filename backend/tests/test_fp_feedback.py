from __future__ import annotations

import json

from core.fp_feedback import FeedbackStore


def test_feedback_store_deduplicates_by_fingerprint_and_rule(tmp_path):
    path = tmp_path / "fp_feedback.json"
    store = FeedbackStore(path=path)

    store.record(
        fingerprint="abc123",
        rule_id="missing-rate-limiting",
        project_hash="p1",
        feedback_type="false_positive",
    )
    store.record(
        fingerprint="abc123",
        rule_id="missing-rate-limiting",
        project_hash="p1",
        feedback_type="not_actionable",
    )

    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["feedback_type"] == "not_actionable"


def test_feedback_store_summary_by_rule(tmp_path):
    path = tmp_path / "fp_feedback.json"
    store = FeedbackStore(path=path)
    store.record(
        fingerprint="f1",
        rule_id="debug-exposure-risk",
        project_hash="p1",
        feedback_type="false_positive",
    )
    store.record(
        fingerprint="f2",
        rule_id="debug-exposure-risk",
        project_hash="p1",
        feedback_type="correct",
    )
    store.record(
        fingerprint="f3",
        rule_id="unsafe-redirect",
        project_hash="p1",
        feedback_type="not_actionable",
    )

    summary = store.summary()
    assert summary["debug-exposure-risk"]["false_positive"] == 1
    assert summary["debug-exposure-risk"]["correct"] == 1
    assert summary["unsafe-redirect"]["not_actionable"] == 1
