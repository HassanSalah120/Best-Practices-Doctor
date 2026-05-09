from core.scoring import ScoringEngine
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity


def _finding(rule_id: str, severity: Severity, category: Category, confidence: float = 0.85) -> Finding:
    return Finding(
        rule_id=rule_id,
        file="app/Http/Controllers/UserController.php",
        line_start=10,
        title=f"{rule_id} issue",
        description="desc",
        why_it_matters="why",
        suggested_fix="fix",
        category=category,
        severity=severity,
        classification=FindingClassification.RISK,
        confidence=confidence,
    )


def test_triage_plan_and_recommendation_fields_present():
    findings = [
        _finding("authorization-bypass-risk", Severity.HIGH, Category.SECURITY, 0.9),
        _finding("controller-business-logic", Severity.MEDIUM, Category.ARCHITECTURE, 0.8),
    ]
    facts = Facts(project_path="demo", files=["app/Http/Controllers/UserController.php"])
    report = ScoringEngine().generate_report(
        job_id="scan_1",
        project_path="demo",
        findings=findings,
        facts=facts,
        ruleset_path=None,
        rules_executed=[],
    )

    assert report.triage_plan
    assert len(report.top_5_first) >= 1
    assert isinstance(report.safe_to_defer, list)
    item = report.triage_plan[0]
    assert item.recommendation in {"fix_now", "schedule_next", "ignore_safely_candidate"}
    assert 0.0 <= item.triage_score <= 100.0
