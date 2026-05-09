"""Missing domain event rule."""
from __future__ import annotations

import re
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

class MissingDomainEventRule(Rule):
    id = "missing-domain-event"
    name = "Missing Domain Event"
    description = "Suggests dispatching domain events after critical model writes"
    category = Category.ARCHITECTURE
    default_severity = Severity.LOW
    type = "regex"
    severity_weight = 2
    confidence = "low"
    fix_suggestion = "Dispatch a domain event after significant business actions so listeners can react without tight coupling."
    examples = {"bad": "$order->save(); // no event dispatched", "good": "$order->save(); OrderPlaced::dispatch($order);"}
    priority = 4
    group = "Architecture Integrity"
    applies_to = ["service", "controller"]
    references = []
    related_rules = []
    false_positive_notes = "Low confidence by design; skip test files and models that already declare dispatchesEvents/HasEvents."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "domain-events"}
    _WRITE = re.compile(r"\b(Order|Payment|Invoice|User)::(?:create|update|delete)\s*\(|\$(?:order|payment|invoice|user)->(?:save|update|delete)\s*\(", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        norm = file_path.replace("\\", "/").lower()
        if "/tests/" in f"/{norm}" or "$dispatchesEvents" in content or "HasEvents" in content:
            return []
        findings: list[Finding] = []
        for m in self._WRITE.finditer(content):
            nearby = content[m.end():m.end() + 180]
            if re.search(r"\b(event\s*\(|Event::|dispatch\s*\(|::dispatch\s*\()", nearby):
                continue
            line = content.count("\n", 0, m.start()) + 1
            findings.append(self.create_finding("Critical model write has no nearby domain event", file_path, line, "A critical Order/Payment/Invoice/User write has no nearby event dispatch.", "Domain events decouple side effects such as notifications, auditing, and projections from the write workflow.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.45, tags=["laravel", "architecture", "events"]))
        return findings
