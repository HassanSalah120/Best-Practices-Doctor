from __future__ import annotations

import logging

import pytest

from core.rule_engine import (
    ALL_RULES,
    DISCOVERED_RULES,
    REGISTERED_RULES,
    RUNTIME_RULES,
    build_rule_registry,
    discover_rules,
)
from core.rule_registry_drift import get_rule_registry_drift
from rules.base import Rule
from schemas.finding import Category, Severity


def test_rule_discovery_finds_known_rules():
    discovered = discover_rules()
    assert "fat-controller" in discovered
    assert "god-class" in discovered
    assert set(ALL_RULES.keys()).issubset(set(discovered.keys()))


def test_registered_registry_keeps_manual_rules():
    assert set(ALL_RULES.keys()).issubset(set(REGISTERED_RULES.keys()))
    assert REGISTERED_RULES["fat-controller"] is ALL_RULES["fat-controller"]


def test_discovered_rules_snapshot_not_empty():
    assert DISCOVERED_RULES


def test_runtime_registry_is_manual_source_of_truth():
    assert RUNTIME_RULES == ALL_RULES


def test_manual_registry_precedence_on_conflict():
    class ManualRule(Rule):
        id = "conflict-id"
        name = "Manual"
        description = "manual"
        category = Category.SECURITY
        default_severity = Severity.HIGH

        def analyze(self, facts, metrics=None):
            return []

    class DiscoveredRule(Rule):
        id = "conflict-id"
        name = "Discovered"
        description = "discovered"
        category = Category.SECURITY
        default_severity = Severity.HIGH

        def analyze(self, facts, metrics=None):
            return []

    merged = build_rule_registry(
        manual_registry={"conflict-id": ManualRule},
        discovered_registry={"conflict-id": DiscoveredRule},
    )
    assert merged["conflict-id"] is ManualRule


def test_malformed_rule_missing_id_is_skipped_with_warning(monkeypatch, caplog):
    class MissingIdRule(Rule):
        id = ""
        name = "Missing"
        description = "missing"
        category = Category.SECURITY
        default_severity = Severity.HIGH

        def analyze(self, facts, metrics=None):
            return []

    class ValidRule(Rule):
        id = "discovery-test-valid"
        name = "Valid"
        description = "valid"
        category = Category.SECURITY
        default_severity = Severity.HIGH

        def analyze(self, facts, metrics=None):
            return []

    monkeypatch.setattr("core.rule_engine._import_discovery_modules", lambda: [])
    monkeypatch.setattr(
        "core.rule_engine._iter_rule_subclasses",
        lambda base: [MissingIdRule, ValidRule],
    )
    caplog.set_level(logging.WARNING)

    discovered = discover_rules()
    assert "discovery-test-valid" in discovered
    assert "" not in discovered
    assert "missing `id`" in caplog.text


def test_total_rule_count_matches_expected_after_merge():
    extra_discovered = set(DISCOVERED_RULES.keys()) - set(ALL_RULES.keys())
    assert len(REGISTERED_RULES) == len(ALL_RULES) + len(extra_discovered)


def test_rule_registry_drift_report_is_consistent():
    drift = get_rule_registry_drift()
    assert drift["manual_count"] == len(ALL_RULES)
    assert drift["discovered_count"] == len(DISCOVERED_RULES)
    assert set(drift["pending_discovered"]).issubset(set(DISCOVERED_RULES.keys()))
