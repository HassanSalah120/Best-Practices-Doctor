"""
Missing Auth On Mutating API Routes Rule

Detects state-changing routes in routes/api.php that appear to be missing auth middleware.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingAuthOnMutatingApiRoutesRule(Rule):
    id = "missing-auth-on-mutating-api-routes"
    name = "Missing Auth On Mutating API Routes"
    description = "Detects mutating API routes that are not protected by auth middleware"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _public_uri = re.compile(
        r"(^|/)(login|logout|register|password|forgot|reset|verification|verify|token|otp|2fa|"
        r"sanctum/csrf-cookie|webhook|health|status|up|ping)(/|$)",
        re.IGNORECASE,
    )
    _state_changing = {"post", "put", "patch", "delete", "any"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        routes = [r for r in (facts.routes or []) if self._is_api_routes_file(r.file_path or "")]
        return self._analyze_routes(routes)

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        # Preferred path: consume enriched Facts routes (includes group inheritance).
        from_facts = [r for r in (facts.routes or []) if self._is_same_file(r.file_path or "", file_path)]
        if from_facts:
            return self._analyze_routes(from_facts)

        # Fallback for direct unit tests that only provide regex input.
        return []

    def _is_state_changing_method(self, method: str) -> bool:
        m = (method or "").strip().lower()
        if not m:
            return False
        if m in self._state_changing:
            return True
        if m == "match":
            return True
        return False

    def _is_public_uri(self, uri: str) -> bool:
        u = (uri or "").strip().strip("/")
        if not u:
            return False
        return bool(self._public_uri.search(u))

    def _is_api_routes_file(self, file_path: str) -> bool:
        fp = (file_path or "").replace("\\", "/").lower()
        return fp == "routes/api.php" or fp.endswith("/routes/api.php")

    def _is_same_file(self, a: str, b: str) -> bool:
        return (a or "").replace("\\", "/").lower() == (b or "").replace("\\", "/").lower()

    def _has_auth_middleware(self, middleware: list[str]) -> bool:
        txt = " ".join([str(x).lower() for x in (middleware or [])])
        return any(tok in txt for tok in ["auth", "sanctum", "passport"])

    def _analyze_routes(self, routes: list) -> list[Finding]:
        out: list[Finding] = []
        for route in routes:
            if not self._is_api_routes_file(route.file_path or ""):
                continue

            method = str(route.method or "").strip().lower()
            uri = str(route.uri or "").strip()
            if not self._is_state_changing_method(method):
                continue
            if self._is_public_uri(uri):
                continue
            if self._has_auth_middleware(route.middleware or []):
                continue

            controller = str(route.controller or "").strip()
            action = str(route.action or "").strip()
            context = f"{method.upper()} {uri}"
            if controller and action:
                context = f"{context} -> {controller}@{action}"

            evidence = [
                f"route_file={route.file_path}",
                f"method={method.upper()}",
                f"uri={uri}",
                "auth_middleware_missing",
            ]

            out.append(
                self.create_finding(
                    title="Mutating API route appears to be missing auth middleware",
                    context=context,
                    file=route.file_path or "routes/api.php",
                    line_start=int(getattr(route, "line_number", 1) or 1),
                    description=(
                        f"Detected state-changing API route `{method.upper()} {uri}` without auth middleware."
                    ),
                    why_it_matters=(
                        "Unprotected mutating endpoints can allow unauthorized data changes. "
                        "In multi-tenant SaaS, this increases cross-tenant access risk."
                    ),
                    suggested_fix=(
                        "Protect this route with auth middleware (for example `auth:sanctum`) "
                        "or move it under an authenticated group."
                    ),
                    tags=["laravel", "routes", "security", "auth", "multi-tenant"],
                    confidence=0.78 if controller and action else 0.72,
                    related_methods=[f"{controller}@{action}"] if controller and action else [],
                    evidence_signals=evidence,
                )
            )

        return out
