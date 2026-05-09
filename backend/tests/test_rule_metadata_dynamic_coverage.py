from core.rule_engine import ALL_RULES, INTERNAL_RULE_WRAPPERS
from core.rule_metadata import get_rule_ids, get_rules_grouped_for_ui


VALID_CONFIDENCE = {"high", "medium", "low"}
VALID_PRIORITY = {1, 2, 3, 4}
VALID_GROUPS = {
    "Security Hardening",
    "Authentication & Session",
    "Injection Risks",
    "Sensitive Data",
    "Access Control",
    "File Security",
    "Architecture Integrity",
    "Data Access",
    "Queue & Jobs",
    "API Design",
    "Performance",
    "Caching",
    "Code Quality",
    "Testing",
    "Dead Code",
    "React Stability",
    "React Performance",
    "React Accessibility",
    "PHP Quality",
    "PHP Security",
    "DevOps",
}
VALID_APPLIES_TO = {
    "controller",
    "model",
    "migration",
    "service",
    "job",
    "observer",
    "middleware",
    "route",
    "config",
    "blade",
    "provider",
    "react-component",
    "hook",
    "page",
    "form",
    "layout",
    "php-class",
    "php-function",
    "test",
    "global",
}
VALID_DETECTION_TYPES = {"regex", "ast", "process", "heuristic", "cross-file"}
VALID_ANALYSIS_COSTS = {"low", "medium", "high"}
VALID_TAG_DOMAINS = {"laravel", "react", "php", "general"}
VALID_TAG_TYPES = {"security", "performance", "architecture", "quality", "accessibility", "testing"}


def _flatten_ui_rule_ids(payload: dict) -> set[str]:
    ids: set[str] = set()
    for layer in payload.get("layers", []):
        for category in layer.get("categories", []):
            for rule in category.get("rules", []):
                rule_id = str(rule.get("id", "")).strip()
                if rule_id:
                    ids.add(rule_id)
    return ids


def test_rule_metadata_covers_all_registered_rules() -> None:
    assert set(get_rule_ids()) == set(ALL_RULES.keys())


def test_rule_metadata_ui_payload_includes_recent_rules() -> None:
    payload = get_rules_grouped_for_ui()
    ids = _flatten_ui_rule_ids(payload)
    assert "no-direct-useeffect" in ids
    assert "useeffect-cleanup-missing" in ids
    assert "missing-usememo-for-expensive-calc" in ids
    assert "missing-usecallback-for-event-handlers" in ids
    assert "error-pages-missing" in ids


def test_rule_metadata_reports_internal_alias_coverage() -> None:
    payload = get_rules_grouped_for_ui()
    summary = payload["summary"]

    assert summary["internal_alias_count"] == len(INTERNAL_RULE_WRAPPERS)
    assert summary["discovered_rule_count"] == summary["canonical_rule_count"] + len(INTERNAL_RULE_WRAPPERS)

    aliases = {item["id"]: item for item in summary["internal_aliases"]}
    assert set(aliases) == set(INTERNAL_RULE_WRAPPERS)
    assert aliases["debug-mode-exposure"]["target"] == "debug-exposure-risk"
    assert aliases["debug-mode-exposure"]["target_name"]


def test_registered_rules_have_v2_metadata_fields() -> None:
    required = {
        "severity_weight",
        "confidence",
        "fix_suggestion",
        "examples",
        "priority",
        "group",
        "applies_to",
        "references",
        "related_rules",
        "false_positive_notes",
        "detection_type",
        "analysis_cost",
        "auto_fixable",
        "tags",
    }

    for rule_id, rule_class in ALL_RULES.items():
        missing = required - set(rule_class.__dict__)
        assert not missing, f"{rule_id} missing direct v2 fields: {sorted(missing)}"
        assert rule_class.confidence in VALID_CONFIDENCE
        assert str(rule_class.fix_suggestion).strip(), f"{rule_id} has empty fix_suggestion"
        assert int(rule_class.priority) in VALID_PRIORITY
        assert rule_class.group in VALID_GROUPS
        assert set(rule_class.applies_to).issubset(VALID_APPLIES_TO)
        assert rule_class.detection_type in VALID_DETECTION_TYPES
        assert rule_class.analysis_cost in VALID_ANALYSIS_COSTS
        assert isinstance(rule_class.auto_fixable, bool)

        tags = rule_class.tags
        assert isinstance(tags, dict), f"{rule_id} tags must be structured"
        assert tags.get("domain") in VALID_TAG_DOMAINS
        assert tags.get("type") in VALID_TAG_TYPES
        assert "concern" in tags


def test_rule_metadata_ui_payload_returns_v2_shape() -> None:
    payload = get_rules_grouped_for_ui()
    summary = payload["summary"]
    assert set(summary["severity_counts"]) == {"critical", "high", "medium", "low"}
    assert set(summary["category_counts"]) == {"security", "performance", "architecture", "quality", "accessibility"}
    assert summary["score"] == {
        "overall": 0,
        "security": 0,
        "performance": 0,
        "architecture": 0,
        "quality": 0,
        "accessibility": 0,
    }

    sample = next(
        rule
        for layer in payload["layers"]
        for category in layer["categories"]
        for rule in category["rules"]
        if rule["id"] == "fat-controller"
    )
    for key in (
        "severity_weight",
        "confidence",
        "fix_suggestion",
        "examples",
        "priority",
        "group",
        "profiles",
        "applies_to",
        "references",
        "related_rules",
        "false_positive_notes",
        "detection_type",
        "analysis_cost",
        "auto_fixable",
        "tags",
        "tags_legacy",
    ):
        assert key in sample
    assert sample["severity_weight"] == 8
    assert sample["tags"]["domain"] in VALID_TAG_DOMAINS
