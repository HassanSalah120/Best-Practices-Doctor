"""
No JSON Encode In Controllers Rule

Detects json_encode() / ->toJson() usage in controllers.
This is a lightweight lint rule implemented as regex scanning.
"""

from __future__ import annotations

import re

from core.regex_scan import regex_scan
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class NoJsonEncodeInControllersRule(Rule):
    id = "no-json-encode-in-controllers"
    name = "Avoid json_encode/toJson in Controllers"
    description = "Detects json_encode() / ->toJson() usage inside controllers (prefer Response/Resources)"
    category = Category.LARAVEL_BEST_PRACTICE
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
        controller_files = {c.file_path for c in facts.controllers}
        if file_path not in controller_files:
            return []

        pats = [
            re.compile(r"\bjson_encode\s*\(", re.IGNORECASE),
            re.compile(r"->\s*toJson\s*\(", re.IGNORECASE),
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
                    title="Avoid json_encode()/toJson() in controllers",
                    context="json_encode_or_toJson",
                    file=file_path,
                    line_start=h.line_number,
                    description=(
                        "Detected manual JSON serialization in a controller. "
                        "Controllers should return Responses (response()->json) or API Resources instead."
                    ),
                    why_it_matters=(
                        "Manual JSON encoding is easy to get wrong (headers, encoding flags, escaping) and "
                        "bypasses Laravel's response/serialization conventions. Resources also centralize transformation."
                    ),
                    suggested_fix=(
                        "1. Return `response()->json($data)` instead of `json_encode(...)`\n"
                        "2. For APIs, prefer `JsonResource` / `ResourceCollection` for consistent serialization\n"
                        "3. Keep controllers thin: delegate transformation to Resources/DTOs"
                    ),
                    tags=["laravel", "controllers", "json", "resources"],
                    confidence=0.7,
                )
            )
        return out

