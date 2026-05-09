from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from core.remediation.models import (
    FixRanking,
    FixStrategy,
    LedgerEntry,
    RemediationFindingRef,
    ledger_entry_hash,
)


def test_models_reject_extra_fields():
    with pytest.raises(ValidationError):
        RemediationFindingRef(
            fingerprint="fp",
            rule_id="rule",
            file_path="app/Foo.php",
            line=1,
            severity="medium",
            severity_weight=5,
            confidence="high",
            fix_suggestion="Fix it",
            false_positive_notes="",
            related_rules=[],
            unexpected=True,
        )


def test_ledger_entry_hash_reproducible():
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    payload = {"b": 2, "a": 1}
    h1 = ledger_entry_hash(seq=1, timestamp=ts, op="run_created", payload=payload, prev_hash="genesis")
    h2 = ledger_entry_hash(seq=1, timestamp=ts, op="run_created", payload={"a": 1, "b": 2}, prev_hash="genesis")
    assert h1 == h2
    entry = LedgerEntry(seq=1, timestamp=ts, op="run_created", payload=payload, prev_hash="genesis", self_hash=h1)
    assert entry.self_hash == h1


def test_fix_ranking_accepts_formula_score():
    ranking = FixRanking(
        strategy=FixStrategy.SAFE_EDIT,
        rank_score=1.0 * 0.35 + 1.0 * 0.40 + 1.0 * 0.25,
        rationale="safe",
        risk_level="low",
        estimated_effort="minutes",
        acceptance_checks=["check"],
    )
    assert ranking.rank_score == 1.0
