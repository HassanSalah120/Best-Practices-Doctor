"""Array merge/spread in loop rule."""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class ArrayUnpackingInLoopRule(Rule):
    id = "array-unpacking-in-loop"
    name = "Array Unpacking In Loop"
    description = "Detects array_merge or array spread rebuilds inside loops"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Move array_merge outside the loop. Collect items in a temporary array then merge once, or use array_push() for appending."
    examples = {"bad": "foreach ($items as $i) { $r = array_merge($r, $i); }", "good": "$r = array_merge(...$items);"}
    priority = 2
    group = "PHP Quality"
    applies_to = ["php-class", "php-function"]
    references = []
    related_rules = ["string-concat-in-loop"]
    false_positive_notes = "Very small fixed loops may not matter, but this pattern scales poorly and is usually easy to avoid."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "php", "type": "performance", "concern": "loops"}

    _LOOP = re.compile(r"\b(?:foreach|for|while)\s*\([^)]*\)\s*\{(?P<body>.*?)\}", re.IGNORECASE | re.DOTALL)
    _BAD = re.compile(r"\barray_merge\s*\(|=\s*\[\s*\.\.\.", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for match in self._LOOP.finditer(content):
            if not self._BAD.search(match.group("body")):
                continue
            line = content.count("\n", 0, match.start()) + 1
            findings.append(self.create_finding(
                title="Array is repeatedly rebuilt inside a loop",
                context=f"{file_path}:{line}",
                file=file_path,
                line_start=line,
                description="The loop body rebuilds an array with array_merge or spread syntax on every iteration.",
                why_it_matters="Repeated array rebuilding creates avoidable allocations and turns simple appends into increasingly expensive work.",
                suggested_fix=self.fix_suggestion,
                confidence=0.88,
                tags=["php", "performance", "loops"],
            ))
        return findings
