"""
IDOR Risk Missing Ownership Check Rule

Detects authenticated route handlers that fetch mutable resources by ID
without visible ownership/policy checks.
"""

from __future__ import annotations

from schemas.facts import Facts, MethodInfo, QueryUsage, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class IdorRiskMissingOwnershipCheckRule(Rule):
    id = "idor-risk-missing-ownership-check"
    name = "IDOR Risk Missing Ownership Check"
    description = "Detects authenticated resource fetch/update handlers missing ownership or policy checks"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    _RESOURCE_FETCH_MARKERS = ("find(", "findorfail", "first(", "firstorfail", "where(")
    _OWNERSHIP_MARKERS = (
        "authorize(",
        "authorizeresource(",
        "gate::",
        "policy(",
        "->can(",
        "->cannot(",
        "where('user_id'",
        "where(\"user_id\"",
        "where('owner_id'",
        "where(\"owner_id\"",
        "where('tenant_id'",
        "where(\"tenant_id\"",
        "where('clinic_id'",
        "where(\"clinic_id\"",
        "wherebelongsto(",
    )
    _PARAM_EXCLUSIONS = ("token", "signature", "hash", "slug")
    _MUTATING_METHODS = {"post", "put", "patch", "delete"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        require_multi_role_portal = bool(self.get_threshold("require_multi_role_portal_capability", False))
        if require_multi_role_portal and not self._capability_enabled(facts, "multi_role_portal"):
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        findings: list[Finding] = []
        routes_by_target = self._routes_by_target(facts.routes or [])
        methods_by_key = {
            (str(method.class_name or "").replace("Controller", "").lower(), str(method.name or "").lower()): method
            for method in (facts.methods or [])
        }
        queries_by_method: dict[tuple[str, str], list[QueryUsage]] = {}
        for query in facts.queries or []:
            key = (str(query.file_path or "").lower(), str(query.method_name or "").lower())
            queries_by_method.setdefault(key, []).append(query)

        for target, routes in routes_by_target.items():
            method = methods_by_key.get(target)
            if method is None:
                continue
            if self._method_has_ownership_guard(method):
                continue

            method_queries = queries_by_method.get((str(method.file_path or "").lower(), str(method.name or "").lower()), [])
            if not any(self._looks_like_resource_fetch(query) for query in method_queries):
                continue
            if self._queries_have_ownership_scope(method_queries):
                continue

            risky_routes = [route for route in routes if self._route_is_idor_candidate(route)]
            if not risky_routes:
                continue

            confidence = 0.82
            if any(str(route.method or "").strip().lower() in self._MUTATING_METHODS for route in risky_routes):
                confidence += 0.05
            confidence = min(0.92, confidence)
            if confidence + 1e-9 < min_confidence:
                continue

            route = risky_routes[0]
            findings.append(
                self.create_finding(
                    title="Authenticated resource handler may miss ownership check",
                    context=method.method_fqn,
                    file=method.file_path,
                    line_start=method.line_start,
                    line_end=method.line_end,
                    description=(
                        f"Method `{method.method_fqn}` appears to fetch resource records by route identifier for "
                        f"`{route.method.upper()} {route.uri}` without visible policy/ownership constraints."
                    ),
                    why_it_matters=(
                        "Missing ownership checks can lead to insecure direct object references (IDOR), allowing users to access other users' records."
                    ),
                    suggested_fix=(
                        "Apply policy checks (`authorize`, `can`, `authorizeResource`) and/or ownership query constraints "
                        "(for example `where('user_id', auth()->id())`) before returning or mutating the resource."
                    ),
                    related_methods=[method.method_fqn],
                    tags=["laravel", "security", "idor", "authorization", "ownership"],
                    confidence=confidence,
                    evidence_signals=[
                        f"method={method.method_fqn}",
                        f"route={route.method.upper()} {route.uri}",
                        "auth_route=true",
                        "ownership_guard_missing=true",
                    ],
                )
            )

        return findings

    def _routes_by_target(self, routes: list[RouteInfo]) -> dict[tuple[str, str], list[RouteInfo]]:
        grouped: dict[tuple[str, str], list[RouteInfo]] = {}
        for route in routes:
            controller = str(route.controller or "").split("\\")[-1].replace("Controller", "").lower()
            action = str(route.action or "").strip()
            if "@" in action:
                action = action.rsplit("@", 1)[-1]
            action = action.lower()
            if not controller or not action:
                continue
            grouped.setdefault((controller, action), []).append(route)
        return grouped

    def _route_is_idor_candidate(self, route: RouteInfo) -> bool:
        middleware_text = " ".join(str(item or "").lower() for item in (route.middleware or []))
        if "auth" not in middleware_text and "sanctum" not in middleware_text:
            return False

        uri = str(route.uri or "").lower()
        if "{" not in uri:
            return False
        if any(f"{{{marker}" in uri for marker in self._PARAM_EXCLUSIONS):
            return False
        return True

    def _looks_like_resource_fetch(self, query: QueryUsage) -> bool:
        chain = str(query.method_chain or "").lower()
        if not chain:
            return False
        return any(marker in chain for marker in self._RESOURCE_FETCH_MARKERS)

    def _method_has_ownership_guard(self, method: MethodInfo) -> bool:
        calls = [str(call or "").lower() for call in (method.call_sites or [])]
        if not calls:
            return False
        return any(any(marker in call for marker in self._OWNERSHIP_MARKERS) for call in calls)

    def _queries_have_ownership_scope(self, queries: list[QueryUsage]) -> bool:
        ownership_tokens = ("where('user_id'", 'where("user_id"', "where('owner_id'", 'where("owner_id"', "where('tenant_id'", 'where("tenant_id"', "where('clinic_id'", 'where("clinic_id"', "wherebelongsto(")
        for query in queries:
            chain = str(query.method_chain or "").lower()
            if any(token in chain for token in ownership_tokens):
                return True
        return False

    def _capability_enabled(self, facts: Facts, key: str) -> bool:
        project_context = getattr(facts, "project_context", None)
        payload = None
        if project_context is not None:
            payload = (getattr(project_context, "capabilities", {}) or {}).get(key)
            if payload is None:
                payload = (getattr(project_context, "backend_capabilities", {}) or {}).get(key)
        return bool(isinstance(payload, dict) and payload.get("enabled"))
