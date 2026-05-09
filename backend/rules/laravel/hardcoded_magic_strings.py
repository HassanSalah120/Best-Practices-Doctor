"""Hardcoded magic strings rule."""
from __future__ import annotations

import re
from collections import Counter

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class HardcodedMagicStringsRule(Rule):
    id = "hardcoded-magic-strings"
    name = "Hardcoded Magic Strings"
    description = "Detects repeated status/type/role strings that should be constants or enums"
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW
    type = "regex"
    severity_weight = 2
    confidence = "low"
    fix_suggestion = "Extract repeated string literals to class constants or enums. Example: const STATUS_ACTIVE = 'active';"
    examples = {"bad": "if ($user->role === 'admin') { ... } // repeated 4 times", "good": "const ROLE_ADMIN = 'admin'; if ($user->role === self::ROLE_ADMIN) {}"}
    priority = 4
    group = "PHP Quality"
    applies_to = ["php-class", "model", "service"]
    references = []
    related_rules = ["enum-suggestion"]
    false_positive_notes = "Low confidence by design; translation keys, tests, booleans, nulls, and very short strings are skipped."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "quality", "concern": "magic-strings"}
    _STRINGS = re.compile(r"(?<![A-Za-z0-9_])['\"]([A-Za-z][A-Za-z0-9_-]{2,})['\"]")
    _LIKELY = {"active", "pending", "admin", "published", "draft", "cancelled", "paid", "failed", "approved", "rejected", "archived", "user"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if "/tests/" in ("/" + file_path.replace("\\", "/").lower()):
            return []
        vals = [m.group(1) for m in self._STRINGS.finditer(content) if m.group(1).lower() not in {"true", "false", "null"} and "." not in m.group(1) and "/" not in m.group(1)]
        counts = Counter(v for v in vals if v.lower() in self._LIKELY)
        findings: list[Finding] = []
        for value, count in counts.items():
            if count < 3:
                continue
            first = content.find(repr(value))
            if first < 0:
                first = content.find(f'"{value}"')
            line = content.count("\n", 0, max(first, 0)) + 1
            findings.append(self.create_finding("Repeated magic string should be a constant or enum", file_path, line, f"String literal `{value}` appears {count} times in this file.", "Repeated domain strings drift over time and hide valid states from the type system.", self.fix_suggestion, context=f"{file_path}:{value}", confidence=0.45, tags=["laravel", "quality", "constants"]))
        return findings
