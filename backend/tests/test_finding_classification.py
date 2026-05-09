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


def test_v2_score_weights_advisory_findings_less_than_risk_findings():
    engine = ScoringEngine()
    rule_id = "controller-query-direct"

    advisory = engine.calculate_v2_score([_finding(FindingClassification.ADVISORY, rule_id=rule_id)], rules_executed=[rule_id])
    risk = engine.calculate_v2_score([_finding(FindingClassification.RISK, rule_id=rule_id)], rules_executed=[rule_id])

    assert advisory.architecture > risk.architecture
    assert advisory.overall > risk.overall


def test_multiple_high_advisory_findings_do_not_dominate_v2_score():
    engine = ScoringEngine()
    rule_id = "controller-query-direct"
    executed_rules = [
        "controller-query-direct",
        "controller-business-logic",
        "fat-controller",
        "service-extraction",
        "repository-suggestion",
    ]
    findings = [
        _finding(FindingClassification.ADVISORY, rule_id=rule_id).model_copy(
            update={
                "fingerprint": f"advisory-{idx}",
                "file": f"app/Http/Controllers/Demo{idx}.php",
                "severity": Severity.HIGH,
            }
        )
        for idx in range(5)
    ]

    score = engine.calculate_v2_score(findings, rules_executed=executed_rules)

    assert score.architecture > 0


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


def test_report_prioritizes_risk_actions_before_advisory_actions():
    engine = ScoringEngine()
    advisory_findings = [
        _finding(FindingClassification.ADVISORY, rule_id="controller-query-direct").model_copy(
            update={
                "fingerprint": f"advisory-{idx}",
                "file": f"app/Http/Controllers/Demo{idx}.php",
                "severity": Severity.HIGH,
            }
        )
        for idx in range(6)
    ]
    risk = _finding(FindingClassification.RISK, rule_id="missing-csrf-token-verification").model_copy(
        update={"fingerprint": "risk-1", "severity": Severity.MEDIUM}
    )

    report = engine.generate_report(
        "scan-2",
        ".",
        [*advisory_findings, risk],
        Facts(project_path="."),
    )

    assert report.action_plan[0].classification == FindingClassification.RISK
    assert report.triage_plan[0].classification == FindingClassification.RISK
    assert report.top_5_first[0] == report.triage_plan[0].id
