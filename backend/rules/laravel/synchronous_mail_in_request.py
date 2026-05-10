"""Synchronous mail in request rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class SynchronousMailInRequestRule(Rule):
    id = "synchronous-mail-in-request"
    name = "Synchronous Mail In Request"
    description = "Detects synchronous Mail::send or Mail::to()->send calls in request path code"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Use Mail::to()->queue() or implement ShouldQueue on the Mailable class to avoid blocking the HTTP response."
    examples = {"bad": "Mail::to($user)->send(new WelcomeMail($user));", "good": "Mail::to($user)->queue(new WelcomeMail($user));"}
    priority = 2
    group = "Performance"
    applies_to = ["controller", "service"]
    references = []
    related_rules = ["notification-shouldqueue-missing", "listener-shouldqueue-missing-for-io-bound-handler"]
    false_positive_notes = "Console commands and seeders are skipped because response latency is not user-facing there."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "performance", "concern": "mail"}
    _SEND = re.compile(r"\bMail::send\s*\(|->send\s*\(\s*new\s+", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        norm = file_path.replace("\\", "/").lower()
        if "/console/" in norm or "/commands/" in norm or "seeder" in norm or "ShouldQueue" in content:
            return []
        normalized = file_path.replace("\\", "/")
        if "app/Http/Controllers/" not in normalized and "app/Services/" not in normalized:
            return []
        findings: list[Finding] = []
        for m in self._SEND.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            findings.append(self.create_finding("Mail is sent synchronously in request code", file_path, line, "This request-path code sends mail synchronously.", "Synchronous mail delivery blocks the response and makes transient mail provider failures visible to users.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.76, tags=["laravel", "performance", "mail"]))
        return findings
