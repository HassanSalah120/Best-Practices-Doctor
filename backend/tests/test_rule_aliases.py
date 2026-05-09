from core.rule_engine import INTERNAL_RULE_WRAPPERS, LEGACY_RULE_ALIASES, RUNTIME_RULES, RULE_ALIASES, resolve_rule_alias


def test_rule_aliases_resolve_to_unified_ids():
    assert resolve_rule_alias("missing-throttle-on-auth-api-routes") == "missing-rate-limiting"
    assert resolve_rule_alias("sensitive-route-rate-limit-missing") == "missing-rate-limiting"
    assert resolve_rule_alias("debug-mode-exposure") == "debug-exposure-risk"
    assert resolve_rule_alias("unsafe-external-redirect") == "unsafe-redirect"


def test_runtime_registry_contains_unified_rules_only():
    assert "missing-rate-limiting" in RUNTIME_RULES
    assert "debug-exposure-risk" in RUNTIME_RULES
    assert "unsafe-redirect" in RUNTIME_RULES
    assert "missing-throttle-on-auth-api-routes" not in RUNTIME_RULES
    assert "sensitive-route-rate-limit-missing" not in RUNTIME_RULES
    assert "debug-mode-exposure" not in RUNTIME_RULES
    assert "unsafe-external-redirect" not in RUNTIME_RULES


def test_all_alias_targets_are_registered():
    for target in RULE_ALIASES.values():
        assert target in RUNTIME_RULES


def test_all_internal_wrapped_rules_resolve_to_runtime_ids():
    for internal_rule_id, runtime_rule_id in INTERNAL_RULE_WRAPPERS.items():
        assert resolve_rule_alias(internal_rule_id) == runtime_rule_id
        assert runtime_rule_id in RUNTIME_RULES


def test_legacy_alias_only_rules_resolve_to_runtime_ids():
    for alias_rule_id, runtime_rule_id in LEGACY_RULE_ALIASES.items():
        assert resolve_rule_alias(alias_rule_id) == runtime_rule_id
        assert runtime_rule_id in RUNTIME_RULES
