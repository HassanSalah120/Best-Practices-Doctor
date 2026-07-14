"""Missing strict_types declaration rule."""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MissingStrictTypesRule(Rule):
    id = "missing-strict-types"
    name = "Missing strict_types Declaration"
    description = "Detects PHP class/function files missing declare(strict_types=1) near the top"
    category = Category.COMPATIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 5
    confidence = "high"
    fix_suggestion = "Add declare(strict_types=1) after the opening <?php tag to enable strict type enforcement."
    examples = {"bad": "<?php\nclass UserService {", "good": "<?php\ndeclare(strict_types=1);\nclass UserService {"}
    priority = 3
    group = "PHP Quality"
    applies_to = ["php-class", "php-function"]
    references = []
    related_rules = ["missing-type-declarations"]
    false_positive_notes = "Pure config array files are skipped because strict typing adds little value there."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "php", "type": "quality", "concern": "typing"}

    _CODE_MARKER = re.compile(r"\b(class|interface|trait|enum|function)\b")

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        text = content.lstrip("\ufeff\n\r\t ")
        if not text.startswith("<?php") or "declare(strict_types=1)" in text[:200]:
            return []
        if not self._CODE_MARKER.search(text):
            return []
        return [self.create_finding(
            title="PHP file is missing strict_types declaration",
            context=file_path,
            file=file_path,
            line_start=1,
            description="This PHP file contains executable class or function code but does not enable strict type enforcement.",
            why_it_matters="Without strict types, scalar type declarations can still be coerced unexpectedly at call boundaries.",
            suggested_fix=self.fix_suggestion,
            confidence=0.92,
            tags=["php", "quality", "types"],
        )]
