"""
Test Suppression Manager

Tests for the suppression feature.
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import date, timedelta

from core.suppression import (
    SuppressionRule,
    SuppressionFile,
    SuppressionManager,
)
from schemas.finding import Finding, Category, Severity


@pytest.fixture
def temp_project():
    """Create a temporary project directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return Finding(
        rule_id="no-dangerously-set-inner-html",
        file="src/components/Unsafe.tsx",
        line_start=42,
        title="Test finding",
        description="Test description",
        why_it_matters="Test why it matters",
        suggested_fix="Test suggested fix",
        category=Category.SECURITY,
        severity=Severity.HIGH,
    )


def test_suppression_rule_matches_rule_id(sample_finding):
    """Rule matches by rule_id."""
    rule = SuppressionRule(
        id="test-1",
        rule_id="no-dangerously-set-inner-html",
    )
    assert rule.matches(sample_finding) is True


def test_suppression_rule_matches_wildcard(sample_finding):
    """Rule matches with wildcard."""
    rule = SuppressionRule(
        id="test-1",
        rule_id="*",
    )
    assert rule.matches(sample_finding) is True


def test_suppression_rule_no_match_rule_id(sample_finding):
    """Rule doesn't match different rule_id."""
    rule = SuppressionRule(
        id="test-1",
        rule_id="different-rule",
    )
    assert rule.matches(sample_finding) is False


def test_suppression_rule_matches_file_pattern(sample_finding):
    """Rule matches by file pattern."""
    rule = SuppressionRule(
        id="test-1",
        rule_id="*",
        file_pattern="src/components/*.tsx",
    )
    assert rule.matches(sample_finding) is True


def test_suppression_rule_no_match_file_pattern(sample_finding):
    """Rule doesn't match different file pattern."""
    rule = SuppressionRule(
        id="test-1",
        rule_id="*",
        file_pattern="src/utils/*.ts",
    )
    assert rule.matches(sample_finding) is False


def test_suppression_rule_matches_line(sample_finding):
    """Rule matches specific line."""
    rule = SuppressionRule(
        id="test-1",
        rule_id="*",
        line_start=42,
    )
    assert rule.matches(sample_finding) is True


def test_suppression_rule_matches_line_range(sample_finding):
    """Rule matches line range."""
    rule = SuppressionRule(
        id="test-1",
        rule_id="*",
        line_start=40,
        line_end=50,
    )
    assert rule.matches(sample_finding) is True


def test_suppression_rule_expired(sample_finding):
    """Expired rule doesn't match."""
    rule = SuppressionRule(
        id="test-1",
        rule_id="*",
        until=date.today() - timedelta(days=1),
    )
    assert rule.matches(sample_finding) is False


def test_suppression_rule_not_expired(sample_finding):
    """Non-expired rule matches."""
    rule = SuppressionRule(
        id="test-1",
        rule_id="*",
        until=date.today() + timedelta(days=30),
    )
    assert rule.matches(sample_finding) is True


def test_suppression_manager_add(temp_project, sample_finding):
    """Manager can add suppression."""
    manager = SuppressionManager(temp_project)
    
    rule = manager.add_suppression(
        rule_id="no-dangerously-set-inner-html",
        reason="Test suppression",
    )
    
    assert rule.id.startswith("suppress-")
    assert rule.rule_id == "no-dangerously-set-inner-html"
    
    # Check file was created
    suppressions_file = temp_project / ".bpd-suppressions.json"
    assert suppressions_file.exists()
    
    # Check it matches
    is_suppressed, matched = manager.is_suppressed(sample_finding)
    assert is_suppressed is True
    assert matched.id == rule.id


def test_suppression_manager_remove(temp_project):
    """Manager can remove suppression."""
    manager = SuppressionManager(temp_project)
    
    rule = manager.add_suppression(rule_id="test-rule")
    assert len(manager.list_suppressions()) == 1
    
    removed = manager.remove_suppression(rule.id)
    assert removed is True
    assert len(manager.list_suppressions()) == 0


def test_suppression_manager_apply_to_findings(temp_project, sample_finding):
    """Manager can filter findings."""
    manager = SuppressionManager(temp_project)
    
    manager.add_suppression(
        rule_id="no-dangerously-set-inner-html",
        file_pattern="src/components/Unsafe.tsx",
    )
    
    findings = [sample_finding]
    active, suppressed = manager.apply_to_findings(findings)
    
    assert len(active) == 0
    assert len(suppressed) == 1


def test_suppression_manager_clear_expired(temp_project, sample_finding):
    """Manager can clear expired suppressions."""
    manager = SuppressionManager(temp_project)
    
    # Add expired suppression
    manager.add_suppression(
        rule_id="*",
        until=date.today() - timedelta(days=1),
    )
    
    # Add active suppression
    manager.add_suppression(
        rule_id="test-rule",
        until=date.today() + timedelta(days=30),
    )
    
    assert len(manager.list_suppressions()) == 2
    
    removed = manager.clear_expired()
    assert removed == 1
    assert len(manager.list_suppressions()) == 1


def test_suppression_serialization():
    """Suppression can be serialized and deserialized."""
    rule = SuppressionRule(
        id="test-1",
        rule_id="test-rule",
        file_pattern="*.tsx",
        line_start=10,
        line_end=20,
        reason="Test reason",
        until=date(2025, 12, 31),
        created_by="test-user",
    )
    
    data = rule.to_dict()
    restored = SuppressionRule.from_dict(data)
    
    assert restored.id == rule.id
    assert restored.rule_id == rule.rule_id
    assert restored.file_pattern == rule.file_pattern
    assert restored.line_start == rule.line_start
    assert restored.line_end == rule.line_end
    assert restored.reason == rule.reason
    assert restored.until == rule.until
    assert restored.created_by == rule.created_by


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
