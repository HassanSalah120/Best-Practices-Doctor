from core.ruleset import Ruleset, ScoringConfig
from core.scoring import ScoringEngine


def test_scoring_weight_aliases_and_fraction_scaling():
    ruleset = Ruleset(scoring=ScoringConfig(weights={"laravel": 0.25, "react": 0.05, "architecture": 0.70}))
    engine = ScoringEngine(ruleset)

    # Fractions should be scaled to 0-100 and aliases should be normalized.
    assert engine.category_weights["laravel_best_practice"] == 25.0
    assert engine.category_weights["react_best_practice"] == 5.0
    assert engine.category_weights["architecture"] == 70.0


def test_scoring_ignores_invalid_weight_keys():
    ruleset = Ruleset(scoring=ScoringConfig(weights={"laravel": 0.25, "not_a_category": 0.75}))
    engine = ScoringEngine(ruleset)
    assert "not_a_category" not in engine.category_weights
    assert engine.category_weights["laravel_best_practice"] == 25.0
