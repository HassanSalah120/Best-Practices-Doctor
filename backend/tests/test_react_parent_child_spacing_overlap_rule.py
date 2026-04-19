from __future__ import annotations

from pathlib import Path

from core.context_profiles import ContextProfileMatrix
from core.ruleset import RuleConfig
from core.ruleset import Ruleset
from rules.react.react_parent_child_spacing_overlap import ReactParentChildSpacingOverlapRule
from schemas.facts import Facts


def test_spacing_overlap_valid_different_spacing_concerns():
    rule = ReactParentChildSpacingOverlapRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function Footer() {
  return (
    <div className="pt-6 px-4">
      <section className="pb-4">
        <span className="mt-2">OK</span>
      </section>
    </div>
  );
}
"""
    findings = rule.analyze_ast("resources/js/pages/Footer.tsx", content, facts)
    assert findings == []


def test_spacing_overlap_valid_skips_dynamic_class_interpolation():
    rule = ReactParentChildSpacingOverlapRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function Footer({ size }) {
  return (
    <div className={`pt-${size}`}>
      <section className={`pt-${size}`}>Content</section>
    </div>
  );
}
"""
    findings = rule.analyze_ast("resources/js/pages/Footer.tsx", content, facts)
    assert findings == []


def test_spacing_overlap_near_miss_different_responsive_scope():
    rule = ReactParentChildSpacingOverlapRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function Footer() {
  return (
    <div className="md:pt-4">
      <section className="lg:pt-4">Content</section>
    </div>
  );
}
"""
    findings = rule.analyze_ast("resources/js/pages/Footer.tsx", content, facts)
    assert findings == []


def test_spacing_overlap_near_miss_negative_vs_positive_margin():
    rule = ReactParentChildSpacingOverlapRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function Footer() {
  return (
    <div className="-mt-2">
      <section className="mt-2">Content</section>
    </div>
  );
}
"""
    findings = rule.analyze_ast("resources/js/pages/Footer.tsx", content, facts)
    assert findings == []


def test_spacing_overlap_invalid_same_scope_direct_parent_child():
    rule = ReactParentChildSpacingOverlapRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
export function Footer() {
  return (
    <div className="pt-4">
      <section className="pt-4">Content</section>
    </div>
  );
}
"""
    findings = rule.analyze_ast("resources/js/pages/Footer.tsx", content, facts)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "react-parent-child-spacing-overlap"
    assert "overlap_family=pt" in (finding.evidence_signals or [])
    assert finding.metadata["decision_profile"]["responsive_scope"] == "base"


def test_spacing_overlap_invalid_respects_max_findings_per_file_cap():
    rule = ReactParentChildSpacingOverlapRule(
        RuleConfig(
            thresholds={
                "max_findings_per_file": 1,
                "require_same_value": True,
                "allowed_responsive_scopes": ["base", "sm", "md", "lg", "xl", "2xl"],
            }
        )
    )
    facts = Facts(project_path=".")
    content = """
export function Layout() {
  return (
    <main>
      <div className="pt-4">
        <section className="pt-4">A</section>
      </div>
      <div className="md:gap-4">
        <section className="md:gap-4">B</section>
      </div>
    </main>
  );
}
"""
    findings = rule.analyze_ast("resources/js/pages/Layout.tsx", content, facts)
    assert len(findings) == 1


def test_spacing_overlap_context_matrix_calibration():
    matrix = ContextProfileMatrix.load_default()
    mvc_ctx = matrix.resolve_context(
        explicit_profile="mvc",
        explicit_project_type="internal_admin_system",
    )
    layered_portal_ctx = matrix.resolve_context(
        explicit_profile="layered",
        explicit_project_type="portal_based_business_app",
        explicit_capabilities={"multi_role_portal": True},
    )
    realtime_dashboard_ctx = matrix.resolve_context(
        explicit_profile="layered",
        explicit_project_type="realtime_game_control_platform",
        explicit_capabilities={"realtime": True, "mixed_public_dashboard": True},
    )

    mvc_cal = matrix.calibrate_rule("react-parent-child-spacing-overlap", mvc_ctx)
    portal_cal = matrix.calibrate_rule("react-parent-child-spacing-overlap", layered_portal_ctx)
    realtime_cal = matrix.calibrate_rule("react-parent-child-spacing-overlap", realtime_dashboard_ctx)

    assert mvc_cal["enabled"] is True
    assert isinstance(mvc_cal.get("thresholds"), dict)
    assert portal_cal["severity"] in {"medium", "high", "low"}
    assert realtime_cal["severity"] == "low"
    assert int(realtime_cal["thresholds"].get("max_findings_per_file", 0)) == 1


def test_spacing_overlap_rule_is_registered_in_profiles():
    backend_root = Path(__file__).resolve().parents[1]
    startup = Ruleset.load(backend_root / "rulesets" / "startup.yaml")
    balanced = Ruleset.load(backend_root / "rulesets" / "balanced.yaml")
    strict = Ruleset.load(backend_root / "rulesets" / "strict.yaml")

    assert startup.get_rule_config("react-parent-child-spacing-overlap").enabled is True
    assert balanced.get_rule_config("react-parent-child-spacing-overlap").enabled is True
    assert strict.get_rule_config("react-parent-child-spacing-overlap").enabled is True
