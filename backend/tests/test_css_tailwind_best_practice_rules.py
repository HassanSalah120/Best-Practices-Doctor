from __future__ import annotations

from pathlib import Path

from core.context_profiles import ContextProfileMatrix
from core.ruleset import RuleConfig, Ruleset
from rules.react.css_tailwind_best_practice_rules import (
    CssFixedLayoutPxRule,
    CssFontSizePxRule,
    CssSpacingPxRule,
    TailwindArbitraryLayoutSizeRule,
    TailwindArbitraryRadiusShadowRule,
    TailwindArbitrarySpacingRule,
    TailwindArbitraryTextSizeRule,
    TailwindArbitraryValueOveruseRule,
)
from schemas.facts import Facts


def test_css_font_size_px_flags_px_typography():
    rule = CssFontSizePxRule(RuleConfig())
    facts = Facts(project_path=".")
    findings = rule.analyze_regex(
        "resources/css/app.css",
        ".title { font-size: 15px; line-height: 1.4; }",
        facts,
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "css-font-size-px"


def test_css_font_size_px_allows_rem():
    rule = CssFontSizePxRule(RuleConfig())
    facts = Facts(project_path=".")
    findings = rule.analyze_regex(
        "resources/css/app.css",
        ".title { font-size: 1rem; line-height: 1.5; }",
        facts,
    )
    assert findings == []


def test_css_spacing_px_flags_large_px_spacing():
    rule = CssSpacingPxRule(RuleConfig())
    facts = Facts(project_path=".")
    findings = rule.analyze_regex(
        "resources/css/app.css",
        ".card { padding: 16px; margin-top: 24px; }",
        facts,
    )
    assert len(findings) >= 1
    assert findings[0].rule_id == "css-spacing-px"


def test_css_fixed_layout_px_flags_rigid_dimensions():
    rule = CssFixedLayoutPxRule(RuleConfig())
    facts = Facts(project_path=".")
    findings = rule.analyze_regex(
        "resources/css/app.css",
        ".panel { width: 420px; }",
        facts,
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "css-fixed-layout-px"


def test_tailwind_arbitrary_value_overuse_flags_dense_arbitrary_class():
    rule = TailwindArbitraryValueOveruseRule(RuleConfig())
    facts = Facts(project_path=".")
    content = '<div className="p-[15px] rounded-[13px] text-[15px] w-[347px]">X</div>'
    findings = rule.analyze_regex("resources/js/pages/Example.tsx", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "tailwind-arbitrary-value-overuse"


def test_tailwind_arbitrary_value_overuse_skips_dynamic_template_interpolation():
    rule = TailwindArbitraryValueOveruseRule(RuleConfig())
    facts = Facts(project_path=".")
    content = '<div className={`p-[${size}px] rounded-lg`}>X</div>'
    findings = rule.analyze_regex("resources/js/pages/Example.tsx", content, facts)
    assert findings == []


def test_tailwind_specific_rules_detect_text_spacing_layout_and_surface_tokens():
    facts = Facts(project_path=".")
    content = (
        '<div className="text-[13px] p-[15px] w-[347px] rounded-[13px] shadow-[0_1px_2px_rgba(0,0,0,0.06)]">X</div>'
    )

    text_findings = TailwindArbitraryTextSizeRule(RuleConfig()).analyze_regex(
        "resources/js/pages/Example.tsx", content, facts
    )
    spacing_findings = TailwindArbitrarySpacingRule(RuleConfig()).analyze_regex(
        "resources/js/pages/Example.tsx", content, facts
    )
    layout_findings = TailwindArbitraryLayoutSizeRule(RuleConfig()).analyze_regex(
        "resources/js/pages/Example.tsx", content, facts
    )
    surface_findings = TailwindArbitraryRadiusShadowRule(RuleConfig()).analyze_regex(
        "resources/js/pages/Example.tsx", content, facts
    )

    assert len(text_findings) == 1
    assert text_findings[0].rule_id == "tailwind-arbitrary-text-size"
    assert len(spacing_findings) == 1
    assert spacing_findings[0].rule_id == "tailwind-arbitrary-spacing"
    assert len(layout_findings) == 1
    assert layout_findings[0].rule_id == "tailwind-arbitrary-layout-size"
    assert len(surface_findings) == 1
    assert surface_findings[0].rule_id == "tailwind-arbitrary-radius-shadow"


def test_css_tailwind_rules_registered_in_profiles():
    backend_root = Path(__file__).resolve().parents[1]
    startup = Ruleset.load(backend_root / "rulesets" / "startup.yaml")
    balanced = Ruleset.load(backend_root / "rulesets" / "balanced.yaml")
    strict = Ruleset.load(backend_root / "rulesets" / "strict.yaml")

    rule_ids = [
        "css-font-size-px",
        "css-spacing-px",
        "css-fixed-layout-px",
        "tailwind-arbitrary-value-overuse",
        "tailwind-arbitrary-text-size",
        "tailwind-arbitrary-spacing",
        "tailwind-arbitrary-layout-size",
        "tailwind-arbitrary-radius-shadow",
    ]
    for rid in rule_ids:
        assert startup.get_rule_config(rid).enabled is True
        assert balanced.get_rule_config(rid).enabled is True
        assert strict.get_rule_config(rid).enabled is True


def test_css_tailwind_context_matrix_calibration_is_conservative_for_realtime_dashboards():
    matrix = ContextProfileMatrix.load_default()
    default_ctx = matrix.resolve_context(
        explicit_profile="layered",
        explicit_project_type="portal_based_business_app",
    )
    realtime_ctx = matrix.resolve_context(
        explicit_profile="layered",
        explicit_project_type="realtime_game_control_platform",
        explicit_capabilities={"mixed_public_dashboard": True, "realtime": True},
    )

    default_cal = matrix.calibrate_rule("tailwind-arbitrary-value-overuse", default_ctx)
    realtime_cal = matrix.calibrate_rule("tailwind-arbitrary-value-overuse", realtime_ctx)

    assert default_cal["enabled"] is True
    assert default_cal["severity"] in {"medium", "high", "low"}
    assert realtime_cal["severity"] == "low"
    assert int(realtime_cal["thresholds"].get("min_arbitrary_count", 0)) >= 4
