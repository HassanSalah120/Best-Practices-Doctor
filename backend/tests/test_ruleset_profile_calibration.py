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


def test_profiles_have_practical_noise_gradient():
    startup = _load_profile("startup")
    balanced = _load_profile("balanced")
    strict = _load_profile("strict")

    startup_enabled = sum(1 for cfg in startup.rules.values() if cfg.enabled)
    balanced_enabled = sum(1 for cfg in balanced.rules.values() if cfg.enabled)
    strict_enabled = sum(1 for cfg in strict.rules.values() if cfg.enabled)

    assert startup_enabled < balanced_enabled < strict_enabled


def test_balanced_has_fewer_urgent_style_rules_than_strict():
    balanced = _load_profile("balanced")
    strict = _load_profile("strict")
    style_categories = {
        "architecture",
        "laravel_best_practice",
        "maintainability",
        "dry",
        "srp",
        "react_best_practice",
        "complexity",
        "accessibility",
    }
    urgent = {"high", "critical"}

    def count_urgent_style(rs: Ruleset) -> int:
        return sum(
            1
            for cfg in rs.rules.values()
            if cfg.enabled and str(cfg.category) in style_categories and str(cfg.severity) in urgent
        )

    assert count_urgent_style(balanced) < count_urgent_style(strict)


def test_startup_and_balanced_keep_ide_style_rules_out_of_default_reports():
    startup = _load_profile("startup")
    balanced = _load_profile("balanced")
    strict = _load_profile("strict")
    ide_style_rule_ids = [
        "typescript-type-check",
        "css-font-size-px",
        "css-spacing-px",
        "tailwind-arbitrary-value-overuse",
        "tailwind-arbitrary-spacing",
        "anonymous-default-export-component",
        "multiple-exported-react-components",
        "no-inline-types",
        "no-inline-services",
        "laravel-naming-conventions",
        "hardcoded-magic-strings",
    ]

    for rid in ide_style_rule_ids:
        assert startup.get_rule_config(rid).enabled is False
        assert balanced.get_rule_config(rid).enabled is False
        assert strict.get_rule_config(rid).enabled is True


def test_profile_classification_multipliers_keep_advice_light():
    startup = _load_profile("startup")
    balanced = _load_profile("balanced")
    strict = _load_profile("strict")

    assert startup.scoring.classification_multipliers["advisory"] < balanced.scoring.classification_multipliers["advisory"]
    assert balanced.scoring.classification_multipliers["advisory"] < strict.scoring.classification_multipliers["advisory"]
    assert balanced.scoring.classification_multipliers["risk"] == 1.0


def test_universal_health_rules_are_in_expected_profiles():
    startup = _load_profile("startup")
    balanced = _load_profile("balanced")
    strict = _load_profile("strict")

    startup_devops = [
        "env-example-missing-or-out-of-sync",
        "env-committed-to-git",
        "storage-paths-not-in-gitignore",
    ]
    balanced_rules = [
        *startup_devops,
        "app-debug-not-false-in-production",
        "app-env-not-set-to-production",
        "missing-queue-worker-supervision",
        "no-logging-strategy-configured",
        "missing-api-rate-limit-headers",
        "eloquent-raw-where-string",
        "missing-model-observer-registration",
        "catch-too-broad",
        "console-log-in-production-code",
        "inertia-page-missing-error-boundary",
    ]
    strict_only = [
        "blade-component-no-fallback-slot",
        "api-response-inconsistent-shape",
        "no-pagination-on-relationship",
        "missing-return-type-nullable",
        "useless-suspense-boundary",
        "missing-feature-flag-pattern",
    ]

    for rid in startup_devops:
        assert startup.get_rule_config(rid).enabled is True

    for rid in set(balanced_rules) - set(startup_devops):
        assert startup.get_rule_config(rid).enabled is False

    for rid in balanced_rules:
        assert balanced.get_rule_config(rid).enabled is True
        assert strict.get_rule_config(rid).enabled is True

    for rid in strict_only:
        assert startup.get_rule_config(rid).enabled is False
        assert balanced.get_rule_config(rid).enabled is False
        assert strict.get_rule_config(rid).enabled is True
