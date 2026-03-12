"""
Heavy Logic In Routes Rule

Detects DB queries or service/repository instantiation inside routes files.
This is a lightweight lint rule implemented as regex scanning.
"""

from __future__ import annotations

import re

from core.regex_scan import regex_scan
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class HeavyLogicInRoutesRule(Rule):
    id = "heavy-logic-in-routes"
    name = "Heavy Logic In Routes"
    description = "Detects DB queries or service instantiation inside routes files"
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

        pats = [
            re.compile(r"\bDB::(table|select|statement|raw)\s*\(", re.IGNORECASE),
            # Exclude Route::get/post/etc from "Model::where(...)" detection.
            re.compile(r"\b(?!Route\b)[A-Z]\w*::(where|query|find|all|first|get|paginate|pluck|count|exists|create|update|delete)\s*\(", re.IGNORECASE),
            re.compile(r"\bnew\s+\\?App\\(Services|Repositories)\\", re.IGNORECASE),
            re.compile(r"\b(app|resolve)\s*\(\s*\\?App\\", re.IGNORECASE),
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
                    title="Avoid heavy logic in routes files",
                    context="routes_heavy_logic",
                    file=file_path,
                    line_start=h.line_number,
                    description="Detected database/service logic inside a routes file.",
                    why_it_matters=(
                        "Routes should be declarative wiring. Logic in routes is hard to test, reuse, and maintain. "
                        "Prefer controllers that call services/actions."
                    ),
                    suggested_fix=(
                        "1. Move logic into a controller method\n"
                        "2. Extract workflow into a Service and steps into Actions\n"
                        "3. Keep routes as wiring only: URI -> controller"
                    ),
                    tags=["laravel", "routes", "architecture"],
                    confidence=0.65,
                )
            )
        return out
