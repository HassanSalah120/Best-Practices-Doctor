"""Database test isolation trait rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class TestNoDatabaseTraitRule(Rule):
    __test__ = False
    id = "test-no-database-trait"
    name = "Test Missing Database Isolation Trait"
    description = "Detects database-touching tests without RefreshDatabase or transaction traits"
    category = Category.MAINTAINABILITY
    default_severity = Severity.HIGH
    type = "regex"
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Add use RefreshDatabase or use DatabaseTransactions to prevent test pollution between runs."
    examples = {"bad": "class UserTest extends TestCase { public function test_create() { User::create([...]); } }", "good": "class UserTest extends TestCase { use RefreshDatabase; ... }"}
    priority = 2
    group = "Testing"
    applies_to = ["test"]
    references = []
    related_rules = ["tests-missing", "missing-model-factory"]
    false_positive_notes = "Tests using DatabaseMigrations are skipped because they already reset database state."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "testing", "concern": "database-isolation"}
    _DB = re.compile(r"\bDB::|\b[A-Z][A-Za-z0-9_]*::(?:create|factory|query)\s*\(")

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        norm = file_path.replace("\\", "/").lower()
        if "/tests/" not in f"/{norm}" or "extends TestCase" not in content:
            return []
        if any(trait in content for trait in ["RefreshDatabase", "DatabaseTransactions", "DatabaseMigrations"]):
            return []
        if not self._DB.search(content):
            return []
        return [self.create_finding("Database test lacks isolation trait", file_path, 1, "This test touches the database but does not use a database reset/transaction trait.", "Database state can leak between tests and create order-dependent failures.", self.fix_suggestion, context=file_path, confidence=0.74, tags=["laravel", "testing", "database"])]
