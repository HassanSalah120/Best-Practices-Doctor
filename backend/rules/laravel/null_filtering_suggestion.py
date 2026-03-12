"""
Null Filtering Suggestion Rule

Suggests filtering null values from response arrays for cleaner JSON output.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class NullFilteringSuggestionRule(Rule):
    id = "null-filtering-suggestion"
    name = "Null Filtering Suggestion"
    description = "Suggests filtering null values from response arrays"
    category = Category.PERFORMANCE
    default_severity = Severity.LOW
    type = "regex"
    applicable_project_types = [
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
    ]
    regex_file_extensions = [".php"]

    # Inertia middleware class
    _INERTIA_MIDDLEWARE = "HandleInertiaRequests"

    # Patterns that suggest null values in arrays
    _NULL_ASSIGNMENT_PATTERNS = [
        re.compile(r"['\"][\w]+['\"]\s*=>\s*\$[a-zA-Z_]+\s*\?\s*[^:]+\s*:\s*null", re.IGNORECASE),
        re.compile(r"['\"][\w]+['\"]\s*=>\s*\$[a-zA-Z_]+\s*\?\?\s*null", re.IGNORECASE),
        re.compile(r"['\"][\w]+['\"]\s*=>\s*null\b", re.IGNORECASE),
    ]

    # Filter patterns (good practices)
    _FILTER_PATTERNS = [
        re.compile(r"array_filter\s*\(", re.IGNORECASE),
        re.compile(r"Arr::whereNotNull\s*\(", re.IGNORECASE),
        re.compile(r"filterNulls\s*\(", re.IGNORECASE),
        re.compile(r"->filter\s*\(", re.IGNORECASE),
    ]

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/vendor/",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Check if project uses Inertia
        has_inertia = any(
            self._INERTIA_MIDDLEWARE.lower() in (c.name or "").lower()
            for c in facts.middleware
        )

        if not has_inertia:
            return findings

        # Check if project already uses null filtering
        has_filtering = False
        for m in facts.methods:
            for call in m.call_sites or []:
                if any(pattern.search(call) for pattern in self._FILTER_PATTERNS):
                    has_filtering = True
                    break
            if has_filtering:
                break

        # If no filtering found, suggest it for the middleware
        if not has_filtering:
            # Find HandleInertiaRequests file
            inertia_file = None
            for c in facts.middleware:
                if "HandleInertiaRequests" in (c.name or ""):
                    inertia_file = c.file_path
                    break

            findings.append(
                self.create_finding(
                    title="Consider filtering null values in Inertia responses",
                    context="HandleInertiaRequests::share()",
                    file=inertia_file or "app/Http/Middleware/HandleInertiaRequests.php",
                    line_start=1,
                    description=(
                        "No null filtering detected in Inertia middleware. "
                        "Filtering null values from response arrays reduces JSON payload size "
                        "and prevents unnecessary null fields in frontend state."
                    ),
                    why_it_matters=(
                        "Null values in responses:\n"
                        "- Increase JSON payload size unnecessarily\n"
                        "- Create clutter in frontend state\n"
                        "- May cause confusion (null vs undefined vs missing)\n"
                        "- Can affect type checking in TypeScript frontends"
                    ),
                    suggested_fix=(
                        "1. Create a filterNulls helper:\n"
                        "   protected function filterNulls(array $data): array\n"
                        "   {\n"
                        "       return array_filter($data, fn($v) => $v !== null);\n"
                        "   }\n\n"
                        "2. Apply in share() method:\n"
                        "   return [\n"
                        "       'flash' => $this->filterNulls([\n"
                        "           'success' => session('success'),\n"
                        "           'error' => session('error'),\n"
                        "       ]),\n"
                        "   ];\n\n"
                        "3. Or use Laravel's Arr helper:\n"
                        "   Arr::whereNotNull($data)"
                    ),
                    code_example=(
                        "// app/Http/Middleware/HandleInertiaRequests.php\n\n"
                        "public function share(Request $request): array\n"
                        "{\n"
                        "    return array_merge(parent::share($request), [\n"
                        "        'flash' => $this->filterNulls([\n"
                        "            'success' => session('success'),\n"
                        "            'error' => session('error'),\n"
                        "            'warning' => session('warning'),\n"
                        "        ]),\n"
                        "    ]);\n"
                        "}\n\n"
                        "protected function filterNulls(array $data): array\n"
                        "{\n"
                        "    return array_filter($data, fn($v) => $v !== null);\n"
                        "}"
                    ),
                    confidence=0.55,
                    tags=["performance", "inertia", "json", "frontend"],
                )
            )

        return findings

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []
