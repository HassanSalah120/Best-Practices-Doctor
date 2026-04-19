from core.rule_engine import ALL_RULES
from core.rule_metadata import get_rule_ids, get_rules_grouped_for_ui


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
