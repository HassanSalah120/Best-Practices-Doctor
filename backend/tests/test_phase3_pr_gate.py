from __future__ import annotations

from pathlib import Path

from core.baseline import compare_baseline_snapshot, save_baseline_snapshot
from core.pr_gate import evaluate_pr_gate, get_pr_gate_preset, load_pr_gate_presets
from schemas.finding import Category, Finding, Severity
from schemas.project_type import ProjectInfo
from schemas.report import ScanReport


def _finding(
    fp: str,
    *,
    rule_id: str = "x-rule",
    severity: Severity = Severity.HIGH,
    category: Category = Category.SECURITY,
    confidence: float = 0.9,
    file: str = "app/Http/Controllers/X.php",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        fingerprint=fp,
        context=fp,
        title=f"Finding {fp}",
        category=category,
        severity=severity,
        file=file,
        line_start=10,
        description="desc",
        why_it_matters="why",
        suggested_fix="fix",
        confidence=confidence,
    )


def _report(project: Path, findings: list[Finding]) -> ScanReport:
    return ScanReport(
        id="scan_x",
        project_path=str(project),
        project_info=ProjectInfo(root_path=str(project)),
        findings=findings,
    )


def test_phase3_pr_gate_presets_yaml_loads():
    presets = load_pr_gate_presets()
    assert "startup" in presets
    assert "balanced" in presets
    assert "strict" in presets
    assert get_pr_gate_preset("startup").confidence_floor >= 0.5


def test_phase3_pr_gate_startup_blocks_only_new_high_critical(tmp_path: Path):
    project = tmp_path / "clinic-app"
    project.mkdir(parents=True, exist_ok=True)

    base = [_finding("fp-old", rule_id="r-old", severity=Severity.HIGH)]
    save_baseline_snapshot(str(project), base, profile="startup")

    now = [
        _finding("fp-old", rule_id="r-old", severity=Severity.HIGH),
        _finding("fp-new-medium", rule_id="r-med", severity=Severity.MEDIUM),
        _finding("fp-new-high", rule_id="r-high", severity=Severity.HIGH),
    ]
    report = _report(project, now)
    diff = compare_baseline_snapshot(str(project), now, profile="startup")
    gate = evaluate_pr_gate(report, preset_name="startup", profile="startup", baseline_diff=diff)

    assert gate.passed is False
    assert gate.total_new_findings == 2
    assert gate.blocking_findings_count == 1
    assert gate.blocking_fingerprints == ["fp-new-high"]


def test_phase3_pr_gate_balanced_blocks_security_regression(tmp_path: Path):
    project = tmp_path / "clinic-app"
    project.mkdir(parents=True, exist_ok=True)

    save_baseline_snapshot(str(project), [_finding("fp-old", rule_id="r-old", severity=Severity.LOW)], profile="balanced")

    now = [
        _finding("fp-old", rule_id="r-old", severity=Severity.LOW),
        _finding("fp-sec-medium", rule_id="tenant-scope-enforcement", severity=Severity.MEDIUM, category=Category.SECURITY),
    ]
    report = _report(project, now)
    diff = compare_baseline_snapshot(str(project), now, profile="balanced")
    gate = evaluate_pr_gate(report, preset_name="balanced", profile="balanced", baseline_diff=diff)

    assert gate.passed is False
    assert gate.blocking_findings_count == 1
    assert gate.blocking_fingerprints == ["fp-sec-medium"]


def test_phase3_pr_gate_strict_respects_confidence_floor_and_allowlist(tmp_path: Path):
    project = tmp_path / "clinic-app"
    project.mkdir(parents=True, exist_ok=True)

    save_baseline_snapshot(str(project), [_finding("fp-old", rule_id="r-old", severity=Severity.LOW)], profile="strict")

    now = [
        _finding("fp-old", rule_id="r-old", severity=Severity.LOW),
        _finding("fp-low-confidence", rule_id="r-low", severity=Severity.LOW, confidence=0.2),
        _finding("fp-allowlisted", rule_id="r-low", severity=Severity.LOW, file="tests/Feature/XTest.php"),
        _finding("fp-block", rule_id="r-low", severity=Severity.LOW, confidence=0.9),
    ]
    report = _report(project, now)
    diff = compare_baseline_snapshot(str(project), now, profile="strict")
    gate = evaluate_pr_gate(report, preset_name="strict", profile="strict", baseline_diff=diff)

    assert gate.passed is False
    assert gate.blocking_findings_count == 1
    assert gate.blocking_fingerprints == ["fp-block"]

