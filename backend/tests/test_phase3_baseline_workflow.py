from __future__ import annotations

from pathlib import Path

from core.baseline import (
    compare_baseline_snapshot,
    load_baseline_snapshot,
    save_baseline_snapshot,
    update_report_baseline_metadata,
)
from schemas.finding import Category, Finding, Severity
from schemas.project_type import ProjectInfo
from schemas.report import ScanReport


def _finding(fp: str, *, rule_id: str = "x-rule", severity: Severity = Severity.HIGH, file: str = "app/A.php") -> Finding:
    return Finding(
        rule_id=rule_id,
        fingerprint=fp,
        context=fp,
        title=f"Finding {fp}",
        category=Category.SECURITY,
        severity=severity,
        file=file,
        line_start=10,
        description="desc",
        why_it_matters="why",
        suggested_fix="fix",
        confidence=0.9,
    )


def _report(report_id: str, project: Path, findings: list[Finding]) -> ScanReport:
    return ScanReport(
        id=report_id,
        project_path=str(project),
        project_info=ProjectInfo(root_path=str(project)),
        findings=findings,
    )


def test_phase3_baseline_snapshot_saved_under_project_folder(tmp_path: Path):
    project = tmp_path / "clinic-app"
    project.mkdir(parents=True, exist_ok=True)

    saved = save_baseline_snapshot(
        str(project),
        [_finding("fp-a"), _finding("fp-b", severity=Severity.MEDIUM)],
        profile="balanced",
    )

    p = Path(saved.path)
    assert p.exists()
    assert ".bpdoctor/baselines/" in str(p).replace("\\", "/")
    assert p.name == "balanced.json"
    assert saved.finding_count == 2
    assert saved.fingerprints == ["fp-a", "fp-b"]

    loaded = load_baseline_snapshot(str(project), profile="balanced")
    assert loaded is not None
    assert loaded.profile == "balanced"
    assert loaded.fingerprints == ["fp-a", "fp-b"]
    assert loaded.counts_by_severity.get("high", 0) == 1
    assert loaded.counts_by_severity.get("medium", 0) == 1


def test_phase3_baseline_compare_reports_new_resolved_unchanged(tmp_path: Path):
    project = tmp_path / "clinic-app"
    project.mkdir(parents=True, exist_ok=True)

    save_baseline_snapshot(
        str(project),
        [_finding("fp-a", rule_id="r1"), _finding("fp-b", rule_id="r2", severity=Severity.MEDIUM)],
        profile="startup",
    )

    diff = compare_baseline_snapshot(
        str(project),
        [_finding("fp-b", rule_id="r2", severity=Severity.MEDIUM), _finding("fp-c", rule_id="r3", severity=Severity.CRITICAL)],
        profile="startup",
    )

    assert diff.has_baseline is True
    assert diff.new_fingerprints == ["fp-c"]
    assert diff.resolved_fingerprints == ["fp-a"]
    assert diff.unchanged_fingerprints == ["fp-b"]
    assert diff.new_counts_by_severity.get("critical", 0) == 1
    assert diff.resolved_counts_by_severity.get("high", 0) == 1
    assert diff.unchanged_counts_by_severity.get("medium", 0) == 1


def test_phase3_update_report_baseline_metadata_persists_and_replays(tmp_path: Path):
    project = tmp_path / "clinic-app"
    project.mkdir(parents=True, exist_ok=True)

    first = _report("scan_1", project, [_finding("fp-a")])
    diff1 = update_report_baseline_metadata(first, profile="strict")

    # First scan has no previous baseline, so regressions are undefined/no-op.
    assert diff1.has_baseline is False
    assert first.new_findings_count == 0
    assert first.new_finding_fingerprints == []

    second = _report("scan_2", project, [_finding("fp-a"), _finding("fp-b", severity=Severity.CRITICAL)])
    diff2 = update_report_baseline_metadata(second, profile="strict")

    assert diff2.has_baseline is True
    assert second.new_findings_count == 1
    assert second.new_finding_fingerprints == ["fp-b"]
    assert second.resolved_findings_count == 0
    assert second.unchanged_findings_count == 1
    assert second.baseline_profile == "strict"

