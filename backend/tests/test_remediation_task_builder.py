from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from core.remediation.models import FixStrategy
from core.remediation.task_builder import build_tasks, rank_fix_strategies
from core.rule_engine import REGISTERED_RULES
from schemas.finding import Category, Finding, Severity
from schemas.report import ScanReport


class FakeRule:
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Use the safe project pattern."
    false_positive_notes = ""
    related_rules = []
    group = "fake"
    auto_fixable = True


def _finding(fp: str, rule_id: str, file: str = "app/Foo.php", severity=Severity.HIGH) -> Finding:
    return Finding(
        fingerprint=fp,
        rule_id=rule_id,
        title=f"{rule_id} title",
        category=Category.SECURITY,
        severity=severity,
        file=file,
        line_start=1,
        description="desc",
        why_it_matters="why",
        suggested_fix="raw suggestion",
        confidence=1.0,
    )


def _report(tmp_path: Path, findings: list[Finding]) -> ScanReport:
    return ScanReport(id="scan_1", project_path=str(tmp_path), findings=findings)


def test_safe_edit_top_for_auto_fixable_high_confidence_single_file(tmp_path):
    old = dict(REGISTERED_RULES)
    try:
        REGISTERED_RULES["fake-safe"] = FakeRule
        tasks = build_tasks(_report(tmp_path, [_finding("fp1", "fake-safe")]), ["fp1"])
        assert tasks[0].chosen_strategy == FixStrategy.SAFE_EDIT
        assert tasks[0].fix_rankings[0].rank_score == 1.0
    finally:
        REGISTERED_RULES.clear()
        REGISTERED_RULES.update(old)


def test_related_rules_clustered(tmp_path):
    class RuleA(FakeRule):
        related_rules = ["rule-b"]

    class RuleB(FakeRule):
        auto_fixable = False

    old = dict(REGISTERED_RULES)
    try:
        REGISTERED_RULES["rule-a"] = RuleA
        REGISTERED_RULES["rule-b"] = RuleB
        tasks = build_tasks(_report(tmp_path, [_finding("a", "rule-a"), _finding("b", "rule-b")]), ["a", "b"])
        assert len(tasks) == 1
        assert tasks[0].group_strategy == "by_related"
    finally:
        REGISTERED_RULES.clear()
        REGISTERED_RULES.update(old)


def test_group_split_max_ten(tmp_path):
    old = dict(REGISTERED_RULES)
    try:
        REGISTERED_RULES["fake-many"] = FakeRule
        findings = [_finding(f"fp{i}", "fake-many", file=f"app/F{i}.php") for i in range(11)]
        tasks = build_tasks(_report(tmp_path, findings), [f.fingerprint for f in findings])
        assert len(tasks) == 2
        assert max(len(task.findings) for task in tasks) == 10
    finally:
        REGISTERED_RULES.clear()
        REGISTERED_RULES.update(old)


def test_conservative_tiebreak_prefers_safer():
    item = SimpleNamespace(
        ref=SimpleNamespace(confidence="medium", severity="medium", severity_weight=5, rule_id="r", file_path="a.php", fix_suggestion="fix", false_positive_notes=""),
        rule=SimpleNamespace(auto_fixable=False),
        feedback_type="",
    )
    rankings = rank_fix_strategies([item], ["a.php", "b.php", "c.php"])
    guided = next(r for r in rankings if r.strategy == FixStrategy.GUIDED_EDIT)
    defer = next(r for r in rankings if r.strategy == FixStrategy.DEFER)
    if abs(guided.rank_score - defer.rank_score) < 0.05:
        assert rankings.index(guided) < rankings.index(defer)


def test_low_confidence_medium_generates_defer(tmp_path):
    class LowRule(FakeRule):
        confidence = "low"
        auto_fixable = False

    old = dict(REGISTERED_RULES)
    try:
        REGISTERED_RULES["low-rule"] = LowRule
        task = build_tasks(_report(tmp_path, [_finding("fp", "low-rule", severity=Severity.MEDIUM)]), ["fp"])[0]
        assert any(r.strategy == FixStrategy.DEFER for r in task.fix_rankings)
        assert all(r.acceptance_checks for r in task.fix_rankings)
    finally:
        REGISTERED_RULES.clear()
        REGISTERED_RULES.update(old)
