from __future__ import annotations

from core.ruleset import Ruleset, ScoringConfig
from core.scoring import ScoringEngine
from schemas.finding import Category, Finding, Severity


def _mk_finding(rule_id: str, category: Category) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="t",
        category=category,
        severity=Severity.HIGH,
        file="a.php",
        line_start=1,
        description="d",
        why_it_matters="w",
        suggested_fix="s",
        context="ctx",
    )


def test_missing_category_weight_returns_na_score_in_breakdown():
    # Explicit weights: only architecture is weighted.
    ruleset = Ruleset(scoring=ScoringConfig(weights={"architecture": 1.0}))
    scoring = ScoringEngine(ruleset)

    res = scoring.calculate([_mk_finding("god-class", Category.MAINTAINABILITY)], file_count=10)
    cs = res.category_scores["maintainability"]

    assert cs.weight == 0
    assert cs.has_weight is False
    assert cs.score is None  # N/A
    assert cs.raw_score < 100  # still computed for diagnostics


def test_explicit_weights_missing_categories_get_weight_0_and_na_score():
    ruleset = Ruleset(scoring=ScoringConfig(weights={"architecture": 1.0}))
    scoring = ScoringEngine(ruleset)

    res = scoring.calculate([_mk_finding("long-method", Category.MAINTAINABILITY)], file_count=10)
    cs = res.category_scores["maintainability"]

    assert cs.weight == 0
    assert cs.has_weight is False
    assert cs.score is None  # N/A


def test_not_configured_category_is_not_counted_with_default_weights():
    assert Category.MAINTAINABILITY.value == "maintainability"

    ruleset = Ruleset(scoring=ScoringConfig(weights={}))
    scoring = ScoringEngine(ruleset)

    res = scoring.calculate([_mk_finding("long-method", Category.MAINTAINABILITY)], file_count=10)
    cs = res.category_scores["maintainability"]

    assert cs.weight > 0
    assert cs.has_weight is True
    assert cs.score is not None
    assert cs.score < 100

