from core.ruleset import RuleConfig
from rules.react.form_label_association import FormLabelAssociationRule


def test_phase3_finding_enrichment_adds_evidence_and_fix_template():
    rule = FormLabelAssociationRule(RuleConfig())
    finding = rule.create_finding(
        title="x",
        context="ctx",
        file="resources/js/Pages/Form.tsx",
        line_start=10,
        description="desc",
        why_it_matters="why",
        suggested_fix="",
        evidence_signals=["signal_a", "signal_b"],
    )

    assert finding.evidence_signals == ["signal_a", "signal_b"]
    assert "Evidence signals:" in finding.why_it_matters
    assert "htmlFor" in finding.suggested_fix or "label" in finding.suggested_fix.lower()
