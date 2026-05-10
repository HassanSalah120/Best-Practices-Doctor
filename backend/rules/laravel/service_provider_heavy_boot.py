"""Heavy ServiceProvider boot rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class ServiceProviderHeavyBootRule(Rule):
    id = "service-provider-heavy-boot"
    name = "Heavy ServiceProvider Boot"
    description = "Detects DB, HTTP, or filesystem work inside ServiceProvider::boot"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    type = "regex"
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Never perform DB queries or HTTP calls in ServiceProvider::boot(). Use lazy loading or deferred providers instead."
    examples = {"bad": "public function boot() { $settings = DB::table('settings')->get(); }", "good": "public function boot() { $this->app->singleton(Settings::class, fn() => DB::table('settings')->get()); }"}
    priority = 2
    group = "Architecture Integrity"
    applies_to = ["provider"]
    references = []
    related_rules = []
    false_positive_notes = "A deferred singleton closure is acceptable because the expensive work runs only when resolved."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "provider-boot"}
    _BOOT = re.compile(r"function\s+boot\s*\([^)]*\)\s*(?::\s*[^{]+)?\{(?P<body>.*?)\n\s*\}", re.DOTALL)
    _HEAVY = re.compile(r"\b(?:DB::|Http::|file_get_contents\s*\()")

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if "ServiceProvider.php" not in file_path:
            return []
        findings: list[Finding] = []
        for m in self._BOOT.finditer(content):
            body = m.group("body")
            if "singleton(" in body and ("fn()" in body or "function" in body):
                continue
            if not self._HEAVY.search(body):
                continue
            line = content.count("\n", 0, m.start()) + 1
            findings.append(self.create_finding("ServiceProvider::boot performs heavy work", file_path, line, "The boot method performs DB, HTTP, or filesystem work during application startup.", "Provider boot runs early and broadly; heavy work here slows every request and can break bootstrapping.", self.fix_suggestion, context=f"{file_path}:boot", confidence=0.9, tags=["laravel", "architecture", "provider"]))
        return findings
