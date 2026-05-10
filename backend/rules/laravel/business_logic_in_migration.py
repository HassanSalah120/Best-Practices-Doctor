"""Business logic in migration rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class BusinessLogicInMigrationRule(Rule):
    id = "business-logic-in-migration"
    name = "Business Logic In Migration"
    description = "Detects model usage or business loops inside migration up methods"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    type = "regex"
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Migrations must only contain schema changes. Move data transformations to seeders, artisan commands, or dedicated data migration jobs."
    examples = {"bad": "public function up() { foreach (User::all() as $u) { $u->update(['role' => 'user']); } }", "good": "public function up() { Schema::table('users', fn($t) => $t->string('role')->default('user')); }"}
    priority = 1
    group = "Architecture Integrity"
    applies_to = ["migration"]
    references = []
    related_rules = []
    false_positive_notes = "Schema-only migrations are not flagged; this rule targets application model/data workflows in migrations."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "migrations"}
    _UP = re.compile(r"function\s+up\s*\([^)]*\)\s*(?::\s*[^{]+)?\{(?P<body>.*?)\n\s*\}", re.DOTALL)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if "migrations/" not in file_path.replace("\\", "/").lower():
            return []
        findings: list[Finding] = []
        for m in self._UP.finditer(content):
            body = m.group("body")
            if not (("use App\\Models" in content) or re.search(r"\b(?!Schema\b|Blueprint\b)[A-Z][A-Za-z0-9_]*::", body) or "foreach" in body):
                continue
            line = content.count("\n", 0, m.start()) + 1
            findings.append(self.create_finding("Migration contains business/data logic", file_path, line, "The migration up() method contains model usage or iterative business logic.", "Migrations should be deterministic schema changes; app model logic can drift as code changes and break old deploys.", self.fix_suggestion, context=f"{file_path}:up", confidence=0.9, tags=["laravel", "architecture", "migration"]))
        return findings
