"""Date format missing cast rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class DateFormatMissingCastRule(Rule):
    id = "date-format-missing-cast"
    name = "Date Format Missing Cast"
    description = "Detects manual date parsing/formatting where model datetime casts are preferred"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.LOW
    type = "regex"
    regex_file_extensions = [".php", ".blade.php"]
    severity_weight = 2
    confidence = "low"
    fix_suggestion = "Add date columns to model $casts array as 'datetime'. Then use $model->date->format() in Blade directly."
    examples = {"bad": "{{ Carbon::createFromFormat('Y-d-m', $order->ordered_at)->toDateString() }}", "good": "// In model: protected $casts = ['ordered_at' => 'datetime'];\n// In blade: {{ $order->ordered_at->toDateString() }}"}
    priority = 4
    group = "PHP Quality"
    applies_to = ["model", "blade"]
    references = []
    related_rules = []
    false_positive_notes = "Display-only formatting can be acceptable; this rule focuses on manual parsing that often belongs in model casts."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "quality", "concern": "date-casts"}
    _MANUAL = re.compile(r"Carbon::createFromFormat\s*\(|->format\s*\(", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if "$casts" in content and "datetime" in content:
            return []
        findings: list[Finding] = []
        for m in self._MANUAL.finditer(content):
            snippet = content[max(0, m.start() - 80):m.end() + 120]
            if "display" in snippet.lower() and "Carbon::createFromFormat" not in snippet:
                continue
            line = content.count("\n", 0, m.start()) + 1
            findings.append(self.create_finding("Manual date formatting may need a model cast", file_path, line, "Manual Carbon parsing or formatting was found where a datetime cast may be clearer.", "Datetime casts centralize parsing and keep Blade/controllers from duplicating date conversion rules.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.42, tags=["laravel", "quality", "dates"]))
        return findings
