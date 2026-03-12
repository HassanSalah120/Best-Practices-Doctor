"""
Missing Throttle On Auth API Routes Rule

Detects sensitive auth endpoints in routes/api.php without explicit throttle middleware.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingThrottleOnAuthApiRoutesRule(Rule):
    id = "missing-throttle-on-auth-api-routes"
    name = "Missing Throttle On Auth API Routes"
    description = "Detects sensitive auth API routes without explicit throttle middleware"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _route_stmt = re.compile(r"Route::.*?;", re.IGNORECASE | re.DOTALL)
    _route_uri = re.compile(
        r"(?:Route::|->)\s*(get|post|put|patch|delete|any)\s*\(\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE,
    )
    _route_match_uri = re.compile(
        r"(?:Route::|->)\s*match\s*\(\s*\[[^\]]*\]\s*,\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE,
    )
    _sensitive_uri = re.compile(
        r"(^|/)(auth|login|logout|register|password|reset|verification|verify|token|otp|2fa|session)(/|$)",
        re.IGNORECASE,
    )

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
        if not (fp == "routes/api.php" or fp.endswith("/routes/api.php")):
            return []

        out: list[Finding] = []
        for m in self._route_stmt.finditer(content):
            stmt = m.group(0)
            lowered = stmt.lower()

            # Only enforce on explicit auth-like endpoints.
            uris: list[str] = []
            uris.extend(x.group(2) for x in self._route_uri.finditer(stmt))
            uris.extend(x.group(1) for x in self._route_match_uri.finditer(stmt))
            if not uris:
                continue
            if not any(self._sensitive_uri.search(u.strip("/")) for u in uris):
                continue

            # Require explicit throttle middleware to protect brute-force endpoints.
            if "middleware(" in lowered and "throttle" in lowered:
                continue

            line = content.count("\n", 0, m.start()) + 1
            out.append(
                self.create_finding(
                    title="Add throttle middleware to sensitive auth API route",
                    context="auth_api_missing_throttle",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected sensitive auth endpoint(s) without explicit throttling: "
                        f"{', '.join(sorted(set(uris)))}."
                    ),
                    why_it_matters=(
                        "Auth endpoints are common brute-force targets. "
                        "Rate limiting reduces credential stuffing and abuse risk."
                    ),
                    suggested_fix=(
                        "Add explicit throttle middleware to these routes, e.g. "
                        "`->middleware('throttle:login')` or `->middleware('throttle:api')`.\n"
                        "For grouped routes, ensure the surrounding middleware group includes throttle."
                    ),
                    tags=["laravel", "routes", "security", "throttle"],
                    confidence=0.7,
                )
            )

        return out

