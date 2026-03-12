from pathlib import Path

from core.ruleset import Ruleset
from core.scoring import ScoringEngine
from schemas.finding import Category


def _load_profile(name: str) -> Ruleset:
    # Tests run with cwd=backend, so profiles live in backend/rulesets.
    p = Path(__file__).resolve().parents[1] / "rulesets" / f"{name}.yaml"
    assert p.exists(), f"Missing profile YAML: {p}"
    return Ruleset.load(p)


def test_startup_profile_calibration_flags_and_thresholds():
    rs = _load_profile("startup")

    assert rs.get_rule_config("god-class").enabled is True
    assert rs.get_rule_config("god-class").severity == "medium"
    assert rs.get_threshold("god-class", "max_loc") == 600
    assert rs.get_threshold("god-class", "max_methods") == 35

    assert rs.get_rule_config("high-complexity").severity == "medium"
    assert rs.get_threshold("high-complexity", "max_cyclomatic") == 15

    assert rs.get_rule_config("long-method").severity == "low"
    assert rs.get_threshold("long-method", "max_lines") == 80

    assert rs.get_rule_config("dry-violation").severity == "low"
    assert rs.get_threshold("dry-violation", "min_token_count") == 50

    for rid in [
        "repository-suggestion",
        "service-extraction",
        "dto-suggestion",
        "contract-suggestion",
        "action-class-suggestion",
        "ioc-instead-of-new",
    ]:
        assert rs.get_rule_config(rid).enabled is False

    assert rs.get_rule_config("unsafe-file-upload").enabled is True
    assert rs.get_rule_config("unsafe-file-upload").severity == "high"
    assert rs.get_rule_config("mass-assignment-risk").enabled is True
    assert rs.get_rule_config("env-outside-config").enabled is True
    assert rs.get_rule_config("sql-injection-risk").enabled is True
    assert rs.get_rule_config("sql-injection-risk").severity == "high"

    assert rs.get_rule_config("n-plus-one-risk").enabled is True
    assert rs.get_rule_config("n-plus-one-risk").severity == "medium"

    assert rs.get_rule_config("blade-queries").enabled is True
    assert rs.get_rule_config("blade-queries").severity == "medium"


def test_balanced_profile_enables_arch_suggestions_and_mid_thresholds():
    rs = _load_profile("balanced")

    for rid in [
        "repository-suggestion",
        "service-extraction",
        "dto-suggestion",
        "contract-suggestion",
        "action-class-suggestion",
        "ioc-instead-of-new",
    ]:
        assert rs.get_rule_config(rid).enabled is True
        assert rs.get_rule_config(rid).severity == "low"

    assert rs.get_threshold("god-class", "max_loc") == 400
    assert rs.get_threshold("high-complexity", "max_cyclomatic") == 12
    assert rs.get_threshold("long-method", "max_lines") == 60


def test_strict_profile_keeps_strict_thresholds():
    rs = _load_profile("strict")
    assert rs.get_threshold("god-class", "max_loc") == 300
    assert rs.get_threshold("high-complexity", "max_cyclomatic") == 10
    assert rs.get_threshold("long-method", "max_lines") == 50


def test_startup_profile_core_category_weights_nonzero():
    rs = _load_profile("startup")
    scorer = ScoringEngine(rs)

    # Ensure core categories are counted (avoids misleading 0% due to missing weights).
    assert scorer._get_weight(Category.SECURITY) > 0
    assert scorer._get_weight(Category.PERFORMANCE) > 0
    assert scorer._get_weight(Category.LARAVEL_BEST_PRACTICE) > 0
    assert scorer._get_weight(Category.MAINTAINABILITY) > 0
    assert scorer._get_weight(Category.COMPLEXITY) > 0

