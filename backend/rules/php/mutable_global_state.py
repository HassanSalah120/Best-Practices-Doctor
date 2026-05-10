"""Mutable global state rule."""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MutableGlobalStateRule(Rule):
    id = "mutable-global-state"
    name = "Mutable Global State"
    description = "Detects use of PHP global variables and mutable static properties"
    category = Category.MAINTAINABILITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Replace global variables with dependency injection or service container bindings. Global state makes testing impossible."
    examples = {"bad": "function process() { global $config; $config['key'] = 'val'; }", "good": "function process(Config $config): void { $config->set('key','val'); }"}
    priority = 2
    group = "PHP Quality"
    applies_to = ["php-class", "php-function"]
    references = []
    related_rules = ["static-helper-abuse"]
    false_positive_notes = "Laravel bootstrap files and global $app in bootstrap context are skipped as framework wiring."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "php", "type": "quality", "concern": "global-state"}

    _GLOBAL = re.compile(r"\bglobal\s+\$([A-Za-z_]\w*)\s*;", re.IGNORECASE)
    _STATIC_PROP = re.compile(r"\b(?:public|protected|private)\s+static\s+(?!function\b)(?:[^;=]+\s+)?\$[A-Za-z_]\w*", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        norm = file_path.replace("\\", "/").lower()
        if norm.endswith(("bootstrap.php", "helpers.php")):
            return []
        findings: list[Finding] = []
        for match in self._GLOBAL.finditer(content):
            if match.group(1) == "app" and "bootstrap" in norm:
                continue
            line = content.count("\n", 0, match.start()) + 1
            findings.append(self._finding(file_path, line, "global variable"))
        for match in self._STATIC_PROP.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            findings.append(self._finding(file_path, line, "mutable static property"))
        return findings

    def _finding(self, file_path: str, line: int, kind: str) -> Finding:
        return self.create_finding(
            title="Mutable global state detected",
            context=f"{file_path}:{line}:{kind}",
            file=file_path,
            line_start=line,
            description=f"This file uses a {kind}, which creates hidden shared state.",
            why_it_matters="Hidden shared state makes requests and tests influence each other and makes behavior order-dependent.",
            suggested_fix=self.fix_suggestion,
            confidence=0.90,
            tags=["php", "quality", "state"],
        )
