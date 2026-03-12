"""
Test Auto-Fix Engine

Tests for the auto-fix suggestion feature.
"""

import pytest
import tempfile
from pathlib import Path

from core.auto_fix import AutoFixEngine, FixSuggestion
from schemas.finding import Finding, Category, Severity


@pytest.fixture
def auto_fix_engine():
    """Create an auto-fix engine instance."""
    return AutoFixEngine()


@pytest.fixture
def sample_php_file():
    """Create a sample PHP file with issues."""
    return """<?php

namespace App\Services;

class PaymentService
{
    public function process($amount)
    {
        Log::debug("Processing payment");
        $apiKey = env('STRIPE_KEY');
        return $amount;
    }
}
"""


@pytest.fixture
def sample_finding_env():
    """Create a finding for env() usage."""
    return Finding(
        rule_id="env-outside-config",
        file="app/Services/PaymentService.php",
        line_start=10,
        line_end=10,
        title="env() used outside config",
        description="env() should only be used in config files",
        why_it_matters="env() returns null in production when config is cached",
        suggested_fix="Use config() instead",
        category=Category.LARAVEL_BEST_PRACTICE,
        severity=Severity.MEDIUM,
    )


@pytest.fixture
def sample_finding_log_debug():
    """Create a finding for Log::debug usage."""
    return Finding(
        rule_id="no-log-debug-in-app",
        file="app/Services/PaymentService.php",
        line_start=9,
        line_end=9,
        title="Log::debug in application code",
        description="Log::debug should not be used in production code",
        why_it_matters="Debug logs can expose sensitive information",
        suggested_fix="Use Log::info instead",
        category=Category.LARAVEL_BEST_PRACTICE,
        severity=Severity.LOW,
    )


def test_fix_suggestion_to_diff():
    """Test diff generation."""
    fix = FixSuggestion(
        rule_id="test-rule",
        title="Test fix",
        description="Test description",
        original_code="Log::debug('test');",
        fixed_code="Log::info('test');",
        line_start=10,
        line_end=10,
    )
    
    diff = fix.to_diff()
    assert "--- original" in diff
    assert "+++ fixed" in diff
    assert "-Log::debug" in diff
    assert "+Log::info" in diff


def test_auto_fix_env_outside_config(auto_fix_engine, sample_finding_env, sample_php_file):
    """Test fix for env() outside config."""
    fix = auto_fix_engine.get_fix_suggestion(sample_finding_env, sample_php_file)
    
    assert fix is not None
    assert fix.rule_id == "env-outside-config"
    assert "config('app.stripe_key')" in fix.fixed_code.lower()
    assert fix.confidence == 0.95


def test_auto_fix_log_debug(auto_fix_engine, sample_finding_log_debug, sample_php_file):
    """Test fix for Log::debug."""
    fix = auto_fix_engine.get_fix_suggestion(sample_finding_log_debug, sample_php_file)
    
    assert fix is not None
    assert fix.rule_id == "no-log-debug-in-app"
    assert "Log::info" in fix.fixed_code
    assert fix.auto_applicable is True


def test_auto_fix_no_fix_available(auto_fix_engine):
    """Test when no fix is available."""
    finding = Finding(
        rule_id="unknown-rule",
        file="test.php",
        line_start=1,
        title="Unknown issue",
        description="No fix pattern for this",
        why_it_matters="Test",
        suggested_fix="Manual fix",
        category=Category.COMPLEXITY,
        severity=Severity.LOW,
    )
    
    fix = auto_fix_engine.get_fix_suggestion(finding, "some code")
    assert fix is None


def test_auto_fix_apply_dry_run(auto_fix_engine, sample_finding_log_debug, sample_php_file):
    """Test applying fix in dry-run mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "test.php"
        file_path.write_text(sample_php_file)
        
        fix = auto_fix_engine.get_fix_suggestion(sample_finding_log_debug, sample_php_file)
        assert fix is not None
        
        success, result = auto_fix_engine.apply_fix(file_path, fix, dry_run=True)
        
        assert success is True
        assert "Log::info" in result
        
        # File should not be modified
        content = file_path.read_text()
        assert "Log::debug" in content


def test_auto_fix_apply_real(auto_fix_engine, sample_finding_log_debug, sample_php_file):
    """Test applying fix for real."""
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = Path(tmpdir) / "test.php"
        file_path.write_text(sample_php_file)
        
        fix = auto_fix_engine.get_fix_suggestion(sample_finding_log_debug, sample_php_file)
        assert fix is not None
        
        success, result = auto_fix_engine.apply_fix(file_path, fix, dry_run=False)
        
        assert success is True
        
        # File should be modified
        content = file_path.read_text()
        assert "Log::info" in content
        assert "Log::debug" not in content


def test_auto_fix_get_fixes_for_findings(auto_fix_engine, sample_php_file):
    """Test getting fixes for multiple findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        project_path = Path(tmpdir)
        
        # Create the file
        file_path = project_path / "app" / "Services" / "PaymentService.php"
        file_path.parent.mkdir(parents=True)
        file_path.write_text(sample_php_file)
        
        findings = [
            Finding(
                rule_id="no-log-debug-in-app",
                file="app/Services/PaymentService.php",
                line_start=9,
                title="Log::debug",
                description="Test",
                why_it_matters="Test",
                suggested_fix="Test",
                category=Category.LARAVEL_BEST_PRACTICE,
                severity=Severity.LOW,
            ),
            Finding(
                rule_id="env-outside-config",
                file="app/Services/PaymentService.php",
                line_start=10,
                title="env()",
                description="Test",
                why_it_matters="Test",
                suggested_fix="Test",
                category=Category.LARAVEL_BEST_PRACTICE,
                severity=Severity.MEDIUM,
            ),
        ]
        
        fixes = auto_fix_engine.get_fixes_for_findings(findings, project_path)
        
        assert "app/Services/PaymentService.php" in fixes
        assert len(fixes["app/Services/PaymentService.php"]) >= 1


def test_fix_suggestion_to_dict():
    """Test serialization."""
    fix = FixSuggestion(
        rule_id="test-rule",
        title="Test",
        description="Desc",
        original_code="before",
        fixed_code="after",
        line_start=1,
        line_end=1,
        confidence=0.8,
        auto_applicable=True,
    )
    
    data = fix.to_dict()
    
    assert data["rule_id"] == "test-rule"
    assert data["original_code"] == "before"
    assert data["fixed_code"] == "after"
    assert data["confidence"] == 0.8
    assert data["auto_applicable"] is True
    assert "diff" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
