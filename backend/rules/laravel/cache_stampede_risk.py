"""Cache stampede risk rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class CacheStampedeRiskRule(Rule):
    id = "cache-stampede-risk"
    name = "Cache Stampede Risk"
    description = "Detects Cache::remember calls without nearby lock protection"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Wrap Cache::remember() with Cache::lock() to prevent thundering herd stampedes when cache expires under load."
    examples = {"bad": "Cache::remember('report', 3600, fn() => heavyQuery());", "good": "Cache::lock('report-lock')->get(fn() => Cache::remember('report', 3600, fn() => heavyQuery()));"}
    priority = 2
    group = "Performance"
    applies_to = ["controller", "service"]
    references = []
    related_rules = ["missing-cache-for-reference-data"]
    false_positive_notes = "Low-traffic cache keys may not need lock protection; review traffic and query cost before changing."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "performance", "concern": "cache"}
    _REMEMBER = re.compile(r"Cache::remember\s*\(")

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        lines = content.splitlines()
        findings: list[Finding] = []
        for i, line in enumerate(lines, start=1):
            if not self._REMEMBER.search(line):
                continue
            nearby = "\n".join(lines[max(0, i - 6): min(len(lines), i + 5)])
            if "Cache::lock(" in nearby or "atomic(" in nearby:
                continue
            findings.append(self.create_finding("Cache::remember lacks stampede protection", file_path, i, "This cache recomputation is not protected by a lock.", "When the key expires under load, many requests can recompute the same expensive value at once.", self.fix_suggestion, context=f"{file_path}:{i}", confidence=0.72, tags=["laravel", "performance", "cache"]))
        return findings
