"""String concatenation in loop rule."""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class StringConcatInLoopRule(Rule):
    id = "string-concat-in-loop"
    name = "String Concatenation In Loop"
    description = "Detects .= string concatenation inside loops"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Collect strings in an array then use implode() once outside the loop. String concatenation in loops is O(n?) memory."
    examples = {"bad": "foreach ($rows as $r) { $out .= $r['name'] . PHP_EOL; }", "good": "$parts = []; foreach ($rows as $r) { $parts[] = $r['name']; } $out = implode(PHP_EOL, $parts);"}
    priority = 2
    group = "PHP Quality"
    applies_to = ["php-function"]
    references = []
    related_rules = ["array-unpacking-in-loop"]
    false_positive_notes = "Short SQL/log fragments are skipped because readability can outweigh micro-optimizations there."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "php", "type": "performance", "concern": "loops"}

    _LOOP = re.compile(r"\b(?:foreach|for|while)\s*\([^)]*\)\s*\{(?P<body>.*?)\}", re.IGNORECASE | re.DOTALL)
    _CONCAT = re.compile(r"\$[A-Za-z_]\w*\s*\.=")

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for match in self._LOOP.finditer(content):
            body = match.group("body")
            concat = self._CONCAT.search(body)
            if not concat:
                continue
            line_text = body[concat.start():body.find("\n", concat.start()) if "\n" in body[concat.start():] else len(body)]
            if len(line_text.strip()) < 50 and re.search(r"\b(sql|query|log|debug)\b", line_text, re.IGNORECASE):
                continue
            line = content.count("\n", 0, match.start()) + 1
            findings.append(self.create_finding(
                title="String is repeatedly concatenated inside a loop",
                context=f"{file_path}:{line}",
                file=file_path,
                line_start=line,
                description="The loop appends to a string with .= on every iteration.",
                why_it_matters="Repeated string concatenation can copy increasingly large buffers; collecting parts and joining once is more predictable.",
                suggested_fix=self.fix_suggestion,
                confidence=0.86,
                tags=["php", "performance", "loops"],
            ))
        return findings
