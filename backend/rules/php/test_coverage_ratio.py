"""
Test Coverage Ratio Rule

Flags projects where the number of test files is disproportionately low compared
to the number of source classes (models, controllers, services).

This is an AST-level quality gate — it uses Facts data, not file parsing.
Threshold is configurable via ruleset (default 0.3 = 30% test-to-source ratio).
"""

from __future__ import annotations

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class TestCoverageRatioRule(Rule):
    id = "test-coverage-ratio"
    name = "Test Coverage Ratio"
    description = "Detects projects where test file count is low relative to source class count"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
    type = "ast"
    severity_weight = 5
    confidence = "high"
    fix_suggestion = (
        "Add focused tests around core domain logic, critical user workflows, "
        "and security-sensitive code paths:\n"
        "1. Unit tests for services, DTOs, and domain logic\n"
        "2. Feature/integration tests for controller actions\n"
        "3. Security tests for authorization, tenant isolation, and input validation\n"
        "4. Policy matrix tests covering role-based access scenarios"
    )
    examples = {}
    priority = 2
    group = "Testing"
    applies_to = ["php-class"]
    references = []
    related_rules = ["tests-missing"]
    false_positive_notes = (
        "Projects using Pest or PHPUnit with test files outside standard `tests/` "
        "directories, or with a single test file that covers many source classes, "
        "may be flagged. This is an advisory signal, not a precise coverage measurement."
    )
    detection_type = "process"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "php", "type": "quality", "concern": "test-coverage"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        test_files_count = int(getattr(facts, "test_files_count", 0) or 0)
        source_count = len(getattr(facts, "models", []) or []) + len(getattr(facts, "controllers", []) or []) + len(getattr(facts, "services", []) or [])

        if source_count < 10:
            return []

        min_ratio = float(self.get_threshold("min_test_ratio", 0.3) or 0.3)
        actual_ratio = test_files_count / source_count if source_count > 0 else 0

        if actual_ratio >= min_ratio:
            return []

        anchor = None
        for candidate in ["phpunit.xml", "phpunit.xml.dist", "pest.php", "composer.json", "artisan"]:
            from pathlib import Path
            root = Path(str(getattr(facts, "project_path", "") or "."))
            if (root / candidate).exists():
                anchor = candidate
                break
        if not anchor:
            anchor = "project"

        return [
            self.create_finding(
                title="Test coverage ratio is low",
                context=f"{test_files_count} tests / {source_count} source classes = {actual_ratio:.0%}",
                file=str(anchor),
                line_start=1,
                description=(
                    f"Project has {test_files_count} test file(s) for {source_count} source "
                    f"classes (models, controllers, services), giving a test-to-source ratio "
                    f"of {actual_ratio:.0%}. Recommended minimum is {min_ratio:.0%}."
                ),
                why_it_matters=(
                    "Low test coverage increases the risk of regressions during refactoring, "
                    "makes security auditing harder, and slows down onboarding of new developers."
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.85,
                tags=["quality_gate", "testing", "coverage"],
                evidence_signals=[
                    f"test_file_count={test_files_count}",
                    f"source_class_count={source_count}",
                    f"test_ratio={actual_ratio:.2f}",
                    f"min_ratio={min_ratio}",
                ],
            ),
        ]
