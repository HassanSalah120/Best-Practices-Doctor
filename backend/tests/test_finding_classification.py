from core.scoring import ScoringEngine
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity


def _finding(classification: FindingClassification, *, rule_id: str = "demo-rule") -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Demo finding",
        category=Category.ARCHITECTURE,
        severity=Severity.MEDIUM,
        classification=classification,
        file="app/Demo.php",
        line_start=10,
        description="desc",
        why_it_matters="why",
        suggested_fix="fix",
        context=f"{rule_id}:{classification.value}",
    )


def test_advisory_findings_penalize_scores_less_than_risk_findings():
    engine = ScoringEngine()

    advisory = engine.calculate([_finding(FindingClassification.ADVISORY)])
    risk = engine.calculate([_finding(FindingClassification.RISK)])

    assert advisory.category_scores[Category.ARCHITECTURE.value].raw_score > risk.category_scores[Category.ARCHITECTURE.value].raw_score


def test_report_exposes_classification_on_findings_and_actions():
    engine = ScoringEngine()
    findings = [
        _finding(FindingClassification.ADVISORY, rule_id="controller-query-direct"),
        _finding(FindingClassification.RISK, rule_id="missing-csrf-token-verification"),
    ]

    report = engine.generate_report(
        "scan-1",
        ".",
        findings,
        Facts(project_path="."),
    )

    assert report.findings_by_classification == {"advisory": 1, "risk": 1}
    by_rule = {item.rule_id: item for item in report.action_plan}
    assert by_rule["controller-query-direct"].classification == FindingClassification.ADVISORY
    assert by_rule["missing-csrf-token-verification"].classification == FindingClassification.RISK
