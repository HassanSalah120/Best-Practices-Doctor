from schemas.finding import Finding, Category, Severity
from core.scoring import ScoringEngine
from core.ruleset import Ruleset


def _mk_finding(*, rule_id: str, file: str, severity: Severity, category: Category, score_impact: int) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="t",
        category=category,
        severity=severity,
        file=file,
        line_start=1,
        description="d",
        why_it_matters="w",
        suggested_fix="s",
        score_impact=score_impact,
        context=f"{rule_id}:{file}:{severity.value}:{score_impact}",
    )


def test_low_info_penalty_capped_once_per_file_per_rule():
    rs = Ruleset()
    rs.scoring.cap_low_info_per_file_rule = True
    scorer = ScoringEngine(rs)

    findings = []
    # 30 low findings for the same rule+file should only apply max(score_impact) once.
    for i in range(30):
        findings.append(
            _mk_finding(
                rule_id="long-method",
                file="app/Foo.php",
                severity=Severity.LOW,
                category=Category.SRP,
                score_impact=1 + (i % 10),
            )
        )
    # Another file should add another capped penalty for the same rule.
    for i in range(10):
        findings.append(
            _mk_finding(
                rule_id="long-method",
                file="app/Bar.php",
                severity=Severity.LOW,
                category=Category.SRP,
                score_impact=5,
            )
        )

    result = scorer.calculate(findings=findings, file_count=2)
    srp = result.category_scores[Category.SRP.value]

    # With capping, SRP should remain far above 30% despite many findings.
    assert srp.raw_score > 30.0


def test_medium_and_higher_not_capped():
    rs = Ruleset()
    rs.scoring.cap_low_info_per_file_rule = True
    scorer = ScoringEngine(rs)

    findings = [
        _mk_finding(rule_id="x", file="a.php", severity=Severity.MEDIUM, category=Category.MAINTAINABILITY, score_impact=5),
        _mk_finding(rule_id="x", file="a.php", severity=Severity.MEDIUM, category=Category.MAINTAINABILITY, score_impact=5),
    ]
    result = scorer.calculate(findings=findings, file_count=1)
    maint = result.category_scores[Category.MAINTAINABILITY.value]
    assert maint.raw_score <= 90.0  # both penalties counted

