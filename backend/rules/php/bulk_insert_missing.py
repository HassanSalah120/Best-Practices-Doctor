"""Bulk insert missing rule."""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class BulkInsertMissingRule(Rule):
    id = "bulk-insert-missing"
    name = "Bulk Insert Missing"
    description = "Detects insert/create/save calls inside loops that should likely be batched"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Use Model::insert([]) or DB::table()->insert([]) with a batch array outside the loop. Single inserts in loops are orders of magnitude slower."
    examples = {"bad": "foreach ($items as $i) { DB::insert('INSERT...', $i); }", "good": "DB::table('items')->insert($items);"}
    priority = 2
    group = "PHP Quality"
    applies_to = ["php-class", "controller", "service"]
    references = []
    related_rules = ["array-unpacking-in-loop"]
    false_positive_notes = "Loops with branching or try/catch are skipped because row-by-row handling may be intentional."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "php", "type": "performance", "concern": "database"}

    _LOOP = re.compile(r"\b(?:foreach|for|while)\s*\([^)]*\)\s*\{(?P<body>.*?)\}", re.IGNORECASE | re.DOTALL)
    _WRITE = re.compile(r"\bDB::insert\s*\(|(?:->|::)create\s*\(|->save\s*\(", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for match in self._LOOP.finditer(content):
            body = match.group("body")
            if re.search(r"\b(if|try)\s*[({]", body):
                continue
            if not self._WRITE.search(body):
                continue
            line = content.count("\n", 0, match.start()) + 1
            findings.append(self.create_finding(
                title="Database writes inside loop should be batched",
                context=f"{file_path}:{line}",
                file=file_path,
                line_start=line,
                description="The loop performs individual database writes instead of collecting rows for a bulk operation.",
                why_it_matters="Single-row writes inside loops add query overhead and can make imports or sync jobs dramatically slower.",
                suggested_fix=self.fix_suggestion,
                confidence=0.74,
                tags=["php", "performance", "database"],
            ))
        return findings
