"""Missing HTTP timeout/circuit breaker rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MissingCircuitBreakerRule(Rule):
    id = "missing-circuit-breaker"
    name = "Missing Circuit Breaker"
    description = "Detects Laravel HTTP client calls without timeout or fallback handling"
    category = Category.RELIABILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    severity_weight = 5
    confidence = "medium"
    fix_suggestion = "Always set a timeout on HTTP calls and wrap in try/catch. Consider a circuit breaker package for repeated failures."
    examples = {"bad": "Http::post('https://payment.api/charge', $data);", "good": "Http::timeout(5)->retry(2)->post('https://payment.api/charge', $data);"}
    priority = 3
    group = "Architecture Integrity"
    applies_to = ["service", "controller", "job"]
    references = []
    related_rules = ["job-http-call-missing-timeout"]
    false_positive_notes = "Local in-memory fakes and tests may not need full resilience handling."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "external-http"}
    _HTTP = re.compile(r"Http::(?:post|get|put)\s*\(|Http::(?!timeout\()[^;\n]*->(?:post|get|put)\s*\(", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for m in self._HTTP.finditer(content):
            end = content.find(";", m.start())
            stmt = content[m.start(): end if end != -1 else min(len(content), m.start() + 160)]
            prefix = content[max(0, m.start() - 120):m.start()]
            if "->timeout(" in stmt or "Http::timeout(" in stmt or "try {" in prefix:
                continue
            line = content.count("\n", 0, m.start()) + 1
            findings.append(self.create_finding("HTTP call lacks timeout/fallback guard", file_path, line, "This outbound HTTP call does not set a timeout or appear to have local fallback handling.", "External services fail slowly; without timeouts and fallback handling, one provider can tie up request or worker capacity.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.72, tags=["laravel", "architecture", "http"]))
        return findings
