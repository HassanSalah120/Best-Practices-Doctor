"""Chunk missing for large datasets rule."""
from __future__ import annotations

import re
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

class ChunkMissingForLargeDatasetsRule(Rule):
    id = "chunk-missing-for-large-datasets"
    name = "Chunk Missing For Large Datasets"
    description = "Detects Model::all or get results iterated without chunk/cursor"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Use ->chunk(500, callback) or ->cursor() for large datasets. Model::all() loads everything into memory at once."
    examples = {"bad": "foreach (User::all() as $user) { process($user); }", "good": "User::chunk(500, fn($users) => $users->each(fn($u) => process($u)));"}
    priority = 2
    group = "Performance"
    applies_to = ["controller", "service", "job", "php-function"]
    references = []
    related_rules = ["missing-pagination", "missing-lazy-collection"]
    false_positive_notes = "Small lookup tables may be fine, but direct iteration of all model rows is risky in growing apps."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "performance", "concern": "large-datasets"}
    _FOREACH = re.compile(r"foreach\s*\([^)]*(?:[A-Z][A-Za-z0-9_]*::all\s*\(|->get\s*\()[^)]*\)", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if "/tests/" in ("/" + file_path.replace("\\", "/").lower()):
            return []
        findings: list[Finding] = []
        for m in self._FOREACH.finditer(content):
            snippet = content[m.start():m.start() + 180]
            if "->count(" in snippet or "->first(" in snippet or "chunk(" in snippet or "cursor(" in snippet:
                continue
            line = content.count("\n", 0, m.start()) + 1
            findings.append(self.create_finding("Large dataset query should use chunk or cursor", file_path, line, "This loop appears to iterate an unbounded query result.", "Loading all rows into memory can crash workers or slow requests as data grows.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.72, tags=["laravel", "performance", "database"]))
        return findings
