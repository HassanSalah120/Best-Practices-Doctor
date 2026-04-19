"""
Missing Throttle On Auth API Routes Rule

Detects sensitive auth endpoints in routes/api.php without explicit throttle middleware.
"""

from __future__ import annotations

import re

from schemas.facts import Facts, RouteInfo
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
    _route_uri = re.compile(r"(?:Route::|->)\s*(get|post|put|patch|delete|any)\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
    _route_match_uri = re.compile(r"(?:Route::|->)\s*match\s*\(\s*\[[^\]]*\]\s*,\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
    _sensitive_uri = re.compile(
        r"(^|/)(auth|login|logout|register|password|reset|verification|verify|token|otp|2fa|session)(/|$)",
        re.IGNORECASE,
    )
    _sensitive_action = re.compile(
        r"(login|logout|register|forgot|reset|verify|verification|password|otp|twofactor|token|session)",
        re.IGNORECASE,
    )
    _mutating_methods = {"post", "put", "patch", "delete", "any", "match"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        routes = [r for r in (facts.routes or []) if self._is_api_routes_file(r.file_path or "")]
        return self._analyze_routes(routes)

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        # Preferred path: consume Facts routes (includes middleware inheritance from route groups).
        from_facts = [r for r in (facts.routes or []) if self._is_same_file(r.file_path or "", file_path)]
        if from_facts:
            return self._analyze_routes(from_facts)

        fp = (file_path or "").replace("\\", "/").lower()
        if not self._is_api_routes_file(fp):
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        require_sensitive_intent = bool(self.get_threshold("require_sensitive_auth_intent", True))
        out: list[Finding] = []
        for m in self._route_stmt.finditer(content):
            stmt = m.group(0)
            lowered = stmt.lower()

            uris: list[str] = []
            uris.extend(x.group(2) for x in self._route_uri.finditer(stmt))
            uris.extend(x.group(1) for x in self._route_match_uri.finditer(stmt))
            if not uris:
                continue
            if require_sensitive_intent and not any(self._sensitive_uri.search(u.strip("/")) for u in uris):
                continue

            if "middleware(" in lowered and "throttle" in lowered:
                continue

            line = content.count("\n", 0, m.start()) + 1
            confidence = 0.72 if require_sensitive_intent else 0.66
            if confidence + 1e-9 < min_confidence:
                continue
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
                    confidence=confidence,
                    evidence_signals=["route_file=routes/api.php", "auth_route_intent=regex", "throttle_middleware_missing"],
                )
            )

        return out

    def _is_api_routes_file(self, file_path: str) -> bool:
        fp = (file_path or "").replace("\\", "/").lower()
        return fp == "routes/api.php" or fp.endswith("/routes/api.php")

    def _is_same_file(self, a: str, b: str) -> bool:
        return (a or "").replace("\\", "/").lower() == (b or "").replace("\\", "/").lower()

    def _has_throttle_middleware(self, middleware: list[str]) -> bool:
        txt = " ".join([str(x).lower() for x in (middleware or [])])
        return "throttle" in txt

    def _is_mutating_method(self, method: str) -> bool:
        m = (method or "").strip().lower()
        if not m:
            return False
        if m in self._mutating_methods:
            return True
        if "match" in m and any(tok in m for tok in ("post", "put", "patch", "delete")):
            return True
        if any(tok in m for tok in ("post", "put", "patch", "delete")) and ("|" in m or "," in m):
            return True
        return False

    def _is_sensitive_route(self, route: RouteInfo) -> bool:
        uri = (route.uri or "").strip().strip("/")
        if uri and self._sensitive_uri.search(uri):
            return True
        payload = f"{route.controller or ''}@{route.action or ''}"
        return bool(self._sensitive_action.search(payload))

    def _analyze_routes(self, routes: list[RouteInfo]) -> list[Finding]:
        out: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        require_sensitive_intent = bool(self.get_threshold("require_sensitive_auth_intent", True))

        for route in routes:
            if not self._is_api_routes_file(route.file_path or ""):
                continue
            if not self._is_mutating_method(str(route.method or "")):
                continue
            if require_sensitive_intent and not self._is_sensitive_route(route):
                continue
            if self._has_throttle_middleware(route.middleware or []):
                continue

            uri = str(route.uri or "").strip()
            method = str(route.method or "").strip().upper()
            controller = str(route.controller or "").strip()
            action = str(route.action or "").strip()
            context = f"{method} {uri}"
            if controller and action:
                context = f"{context} -> {controller}@{action}"

            confidence = 0.8 if (controller and action and require_sensitive_intent) else 0.72
            if confidence + 1e-9 < min_confidence:
                continue

            evidence = [
                f"route_file={route.file_path}",
                f"method={method}",
                f"uri={uri}",
                "throttle_middleware_missing",
            ]
            if require_sensitive_intent:
                evidence.append("auth_route_intent=true")

            out.append(
                self.create_finding(
                    title="Add throttle middleware to sensitive auth API route",
                    context=context,
                    file=route.file_path or "routes/api.php",
                    line_start=int(getattr(route, "line_number", 1) or 1),
                    description=(
                        f"Detected sensitive auth API route `{method} {uri}` without explicit throttling."
                    ),
                    why_it_matters=(
                        "Auth endpoints are common brute-force targets. "
                        "Rate limiting reduces credential stuffing and abuse risk."
                    ),
                    suggested_fix=(
                        "Add explicit throttle middleware to this route (for example `throttle:login` or `throttle:api`) "
                        "or ensure the parent route group includes throttle."
                    ),
                    tags=["laravel", "routes", "security", "throttle"],
                    confidence=confidence,
                    related_methods=[f"{controller}@{action}"] if controller and action else [],
                    evidence_signals=evidence,
                )
            )

        return out
