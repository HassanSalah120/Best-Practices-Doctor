"""
No Closure Routes Rule

Detects closure-based route handlers.
This is a lightweight lint rule implemented as regex scanning.
"""

from __future__ import annotations

import re

from core.regex_scan import regex_scan
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class NoClosureRoutesRule(Rule):
    id = "no-closure-routes"
    name = "Avoid Closure Routes"
    description = "Detects closure-based route handlers (prefer controllers)"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

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
        if not fp.startswith("routes/"):
            return []

        # Matches:
        # Route::get('/x', function (...) { ... })
        # Route::middleware(...)->get('/x', fn (...) => ...)
        pats = [
            re.compile(r"\bRoute::\w+\s*\(.*\b(function\s*\(|fn\s*\()", re.IGNORECASE),
            re.compile(r"->\s*(get|post|put|patch|delete|any|match)\s*\(.*\b(function\s*\(|fn\s*\()", re.IGNORECASE),
        ]
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
                    title="Avoid closure routes (use controllers)",
                    context="closure_route",
                    file=file_path,
                    line_start=h.line_number,
                    description="Detected a route defined with a closure handler.",
                    why_it_matters=(
                        "Closure routes make code harder to test, reuse, and organize. "
                        "Controllers keep entrypoints thin and allow reuse across HTTP/CLI/jobs."
                    ),
                    suggested_fix=(
                        "1. Create a controller (or invokable controller)\n"
                        "2. Move the closure logic into a controller method\n"
                        "3. Keep route definitions declarative"
                    ),
                    tags=["laravel", "routes", "architecture"],
                    confidence=0.7,
                )
            )
        return out

