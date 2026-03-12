"""
API Resource Usage Rule

Heuristic rule: in API controllers, flag returning arrays/response()->json([...]) without using Resources.
This is a lightweight lint rule implemented as regex scanning.
"""

from __future__ import annotations

import re

from core.regex_scan import regex_scan
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ApiResourceUsageRule(Rule):
    id = "api-resource-usage"
    name = "Prefer API Resources"
    description = "Suggests using Laravel API Resources instead of returning raw arrays from API controllers"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = [
        "laravel_api",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_blade",
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
        if "/http/controllers/api/" not in fp.lower():
            return []

        # If file already references Resources, don't flag.
        if re.search(r"Http\\Resources\\Json\\JsonResource|ResourceCollection|JsonResource", content):
            return []

        pats = [
            re.compile(r"\breturn\s*\[", re.IGNORECASE),
            re.compile(r"\breturn\s+array\s*\(", re.IGNORECASE),
            re.compile(r"response\s*\(\s*\)\s*->\s*json\s*\(\s*\[", re.IGNORECASE),
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
                    title="Use API Resources instead of returning raw arrays",
                    context="api_resource_usage",
                    file=file_path,
                    line_start=h.line_number,
                    description="Detected an API controller returning an array/JSON payload directly.",
                    why_it_matters=(
                        "API Resources centralize response transformation, ensure consistent serialization, "
                        "and make changes safer across endpoints."
                    ),
                    suggested_fix=(
                        "1. Create a Resource: `php artisan make:resource ...Resource`\n"
                        "2. Return `new ...Resource($model)` or `...Resource::collection($models)`\n"
                        "3. Keep controller response mapping thin and consistent"
                    ),
                    tags=["laravel", "api", "resources"],
                    confidence=0.6,
                )
            )
        return out

