"""
No Log::debug In App Rule

Detects Log::debug(...) usage in app code.
This is a lightweight lint rule implemented as regex scanning.
"""

from __future__ import annotations

import re

from core.regex_scan import regex_scan
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class NoLogDebugInAppRule(Rule):
    id = "no-log-debug-in-app"
    name = "Avoid Log::debug in app code"
    description = "Detects Log::debug(...) calls in application code"
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW
    type = "regex"
    applicable_project_types: list[str] = []  # all
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Address the avoid log::debug in app code by making the framework contract explicit and keeping the change local to the affected boundary.'
    examples = {}
    priority = 4
    group = 'Code Quality'
    applies_to = ['global']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'quality', 'concern': 'log-debug-in'}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        fp = (file_path or "").replace("\\", "/")
        if not fp.startswith("app/"):
            return []

        pats = [re.compile(r"\bLog::debug\s*\(", re.IGNORECASE)]
        hits = []
        for hit in regex_scan(content, pats):
            s = hit.line.strip()
            if not s or s.startswith(("//", "*", "/*", "#")):
                continue
            hits.append(hit)

        out: list[Finding] = []
        for h in hits:
            out.append(
                self.create_finding(
                    title="Remove Log::debug from production code",
                    context="Log::debug",
                    file=file_path,
                    line_start=h.line_number,
                    description="Detected `Log::debug(...)` in app code.",
                    why_it_matters=(
                        "Debug logs add noise, can leak sensitive information, and increase log volume/cost. "
                        "Prefer structured info logs for meaningful events and keep debug logs behind feature flags if needed."
                    ),
                    suggested_fix=(
                        "1. Remove the debug log or lower verbosity\n"
                        "2. If needed, guard it behind an environment flag\n"
                        "3. Prefer structured logging for real business events (info/warn/error)"
                    ),
                    tags=["logging", "maintainability"],
                    confidence=0.8,
                ),
            )

        return out

