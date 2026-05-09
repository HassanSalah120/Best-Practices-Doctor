from __future__ import annotations

from schemas.finding import Category, Finding, Severity
from schemas.report import ScanReport, ScanScore
from core.remediation.rescan import compare_scans


def _finding(fp: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        fingerprint=fp,
        rule_id="rule",
        title="title",
        category=Category.SECURITY,
        severity=severity,
        file="app/Foo.php",
        line_start=1,
        description="desc",
        why_it_matters="why",
        suggested_fix="fix",
    )


def test_compare_scans_resolved_new_and_score_delta(tmp_path):
    baseline = ScanReport(id="scan_a", project_path=str(tmp_path), findings=[_finding("a"), _finding("b")], score=ScanScore(security=70))
    rescan = ScanReport(id="scan_b", project_path=str(tmp_path), findings=[_finding("b"), _finding("c")], score=ScanScore(security=90))
    comparison = compare_scans(baseline, rescan, "rr")
    assert comparison.resolved_fingerprints == ["a"]
    assert comparison.unchanged_fingerprints == ["b"]
    assert comparison.new_fingerprints == ["c"]
    assert comparison.score_delta["security"] == 20
    assert comparison.severity_deltas["high"] == 0
