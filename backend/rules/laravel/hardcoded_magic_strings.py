"""Hardcoded magic strings rule."""
from __future__ import annotations

import re
from collections import defaultdict

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
    _DOMAIN_USE_RE = re.compile(
        r"(?:===|!==|==|!=|\bcase\b|\bmatch\b|->\s*(?:where|wherein|status|role|type|state|permission|ability)\s*\(|"
        r"\b(?:status|role|type|state|permission|ability)\b\s*(?:=>|=))",
        re.IGNORECASE,
    )

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if "/tests/" in ("/" + file_path.replace("\\", "/").lower()):
            return []
        raw_counts: dict[str, int] = defaultdict(int)
        meaningful: dict[str, list[re.Match[str]]] = defaultdict(list)
        for match in self._STRINGS.finditer(content):
            value = match.group(1)
            if value.lower() not in self._LIKELY:
                continue
            raw_counts[value] += 1
            if self._is_domain_decision_use(content, match):
                meaningful[value].append(match)
        findings: list[Finding] = []
        for value, matches in meaningful.items():
            count = len(matches)
            if count < 3:
                continue
            line = content.count("\n", 0, matches[0].start()) + 1
            findings.append(
                self.create_finding(
                    "Repeated magic string should be a constant or enum",
                    file_path,
                    line,
                    f"String literal `{value}` is used in {count} domain decisions in this file.",
                    "Repeated domain strings drift over time and hide valid states from the type system.",
                    self.fix_suggestion,
                    context=f"{file_path}:{value}",
                    confidence=0.68,
                    tags=["laravel", "quality", "constants"],
                    evidence_signals=[
                        f"domain_decision_uses={count}",
                        f"raw_literal_uses={raw_counts[value]}",
                    ],
                ),
            )
        return findings

    @classmethod
    def _is_domain_decision_use(cls, content: str, match: re.Match[str]) -> bool:
        line_start = content.rfind("\n", 0, match.start()) + 1
        line_end = content.find("\n", match.end())
        if line_end < 0:
            line_end = len(content)
        line = content[line_start:line_end]
        stripped = line.lstrip()
        if stripped.startswith(("//", "#", "*", "/*")):
            return False
        after = content[match.end():line_end]
        if re.match(r"\s*=>", after) and not re.search(r"\bmatch\s*\(", line, re.IGNORECASE):
            # Array/object keys are labels, not duplicated state values.
            return False
        prefix = content[line_start:match.start()]
        if re.search(r"\b(?:const|case)\s*$", prefix, re.IGNORECASE) and "case" not in prefix.lower():
            return False
        return bool(cls._DOMAIN_USE_RE.search(line))
