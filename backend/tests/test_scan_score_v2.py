from core.scoring import ScoringEngine
from schemas.finding import Category, Finding, Severity


def _finding(
    rule_id: str,
    category: Category = Category.SECURITY,
    *,
    file: str = "app/Foo.php",
    context: str = "Test issue",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Issue",
        category=category,
        severity=Severity.HIGH,
        file=file,
        line_start=1,
        description="Test issue",
        why_it_matters="It can break production.",
        suggested_fix="Fix it.",
        context=context,
    )


def test_v2_score_dedupes_identical_findings_by_fingerprint() -> None:
    score = ScoringEngine().calculate_v2_score(
        [_finding("hardcoded-secrets"), _finding("hardcoded-secrets")],
        rules_executed=["hardcoded-secrets"],
    )

    assert score.security == 0
    assert score.overall < 100


def test_v2_score_penalizes_distinct_high_findings_across_files() -> None:
    findings = [
        _finding(
            "unstable-react-key",
            Category.REACT_BEST_PRACTICE,
            file=f"src/Component{i}.tsx",
            context=f"key_expr_{i}",
        )
        for i in range(39)
    ]

    score = ScoringEngine().calculate_v2_score(
        findings,
        rules_executed=["unstable-react-key"],
    )

    assert score.quality == 0
    assert score.overall <= 86


def test_v2_score_uses_medium_fallback_for_orphaned_rule_ids() -> None:
    score = ScoringEngine().calculate_v2_score(
        [_finding("orphan-runtime-contract-rule")],
        rules_executed=["hardcoded-secrets"],
    )

    # hardcoded-secrets contributes 8 possible security points; the orphaned
    # finding contributes the explicit fallback penalty of 5.
    assert score.security == 38
    assert score.overall < 100
