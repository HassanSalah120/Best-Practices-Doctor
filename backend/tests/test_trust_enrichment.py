from schemas.finding import Category, Finding, FindingClassification, Severity
from core.trust import enrich_findings_with_trust


def _sample_finding() -> Finding:
    return Finding(
        rule_id="controller-business-logic",
        file="app/Http/Controllers/UserController.php",
        line_start=42,
        title="Business logic in controller",
        description="Controller handles domain workflows directly",
        why_it_matters="Harder to test and maintain.",
        suggested_fix="Extract to service/action.",
        category=Category.ARCHITECTURE,
        severity=Severity.HIGH,
        classification=FindingClassification.RISK,
        confidence=0.82,
        evidence_signals=["controller_loc=130", "service_dependency_count=0"],
        metadata={"decision_profile": {"decision_summary": "context-calibrated emit decision"}},
    )


def test_trust_enrichment_adds_fields_and_metadata():
    finding = _sample_finding()
    out = enrich_findings_with_trust(
        [finding],
        confidence_floor_resolver=lambda _: 0.7,
        profile_name="balanced",
        suppressed_count=2,
        deduped_overlap_count=1,
        filtered_by_confidence=3,
    )
    assert len(out) == 1
    item = out[0]
    assert item.why_flagged
    assert item.why_not_ignored
    trust = item.metadata.get("trust", {})
    assert isinstance(trust, dict)
    assert trust.get("confidence_floor") == 0.71
    assert trust.get("profile") == "balanced"
    assert trust.get("filtered_by_confidence_in_run") == 3
