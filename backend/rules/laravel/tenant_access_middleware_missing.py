"""
Tenant Access Middleware Missing Rule

Detects tenant/clinic-sensitive routes that are authenticated but missing route-level
tenant access middleware.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class TenantAccessMiddlewareMissingRule(Rule):
    id = "tenant-access-middleware-missing"
    name = "Tenant Access Middleware Missing"
    description = "Detects tenant-sensitive routes missing clinic/tenant access middleware"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _STRONG_TENANT_MARKERS = (
        "clinic",
        "clinic_id",
        "tenant",
        "tenant_id",
        "workspace",
        "workspace_id",
        "organization",
        "organization_id",
    )
    _WEAK_TENANT_MARKERS = ("account", "account_id", "practice", "branch")
    _ACCESS_TOKENS = (
        "clinic_access",
        "tenant_access",
        "workspace_access",
        "organization_access",
        "account_access",
        "scope",
        "can:",
        "permission:",
        "role:",
    )
    _AUTH_TOKENS = ("auth", "sanctum", "passport", "verified")
    _PUBLIC_ROUTE_TOKENS = ("login", "logout", "register", "password", "reset", "forgot", "webhook", "health", "status")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_signals = int(self.get_threshold("min_project_signals", 5) or 5)
        tenant_mode = str(getattr(getattr(facts, "project_context", None), "tenant_mode", "unknown") or "unknown").lower()
        if tenant_mode == "non_tenant":
            return findings
        project_signal_score, project_strong_hits = self._project_tenant_signals(facts)
        if tenant_mode != "tenant" and project_strong_hits == 0:
            return findings

        for route in facts.routes or []:
            descriptor = " ".join(
                [
                    str(route.uri or "").lower(),
                    str(route.controller or "").lower(),
                    str(route.action or "").lower(),
                    str(route.name or "").lower(),
                ]
            )
            route_score, route_strong_hits = self._tenant_marker_score(descriptor)
            if route_strong_hits == 0:
                continue
            if project_signal_score < min_signals and route_score < 2:
                continue
            if any(tok in descriptor for tok in self._PUBLIC_ROUTE_TOKENS):
                continue

            mw_text = " ".join(str(x).lower() for x in (route.middleware or []))
            if not any(tok in mw_text for tok in self._AUTH_TOKENS):
                continue
            if any(tok in mw_text for tok in self._ACCESS_TOKENS):
                continue

            confidence = min(0.9, 0.68 + (0.05 * min(route_strong_hits, 3)) + (0.02 if "verified" in mw_text else 0.0))
            findings.append(
                self.create_finding(
                    title="Tenant-sensitive route may be missing route-level access middleware",
                    context=f"{str(route.method or '').upper()} {route.uri}",
                    file=route.file_path or "routes/web.php",
                    line_start=int(getattr(route, "line_number", 1) or 1),
                    description=(
                        f"Detected tenant-sensitive route `{str(route.method or '').upper()} {route.uri}`"
                        " protected by auth but without an obvious clinic/tenant access middleware."
                    ),
                    why_it_matters=(
                        "In clinic or multi-tenant systems, auth alone does not enforce membership or"
                        " object-level access. Missing tenant middleware can lead to IDOR-style access."
                    ),
                    suggested_fix=(
                        "Add route-level tenant access middleware (for example `clinic_access`,"
                        " `tenant_access`, or an ability middleware such as `can:access-clinic`)."
                    ),
                    tags=["laravel", "security", "routes", "multi-tenant", "idor"],
                    confidence=confidence,
                    evidence_signals=[
                        f"uri={route.uri}",
                        f"middleware={mw_text}",
                        f"route_tenant_signal_score={route_score}",
                        "tenant_access_middleware_missing=true",
                    ],
                )
            )
        return findings

    def _project_tenant_signals(self, facts: Facts) -> tuple[int, int]:
        score = 0
        strong_hits = 0
        for file_path in facts.files or []:
            item_score, item_strong_hits = self._tenant_marker_score(file_path)
            score += item_score
            strong_hits += item_strong_hits
        for route in facts.routes or []:
            route_text = " ".join(
                [
                    str(getattr(route, "uri", "") or ""),
                    str(getattr(route, "controller", "") or ""),
                    " ".join(str(x or "") for x in (getattr(route, "middleware", []) or [])),
                ]
            )
            item_score, item_strong_hits = self._tenant_marker_score(route_text)
            score += item_score
            strong_hits += item_strong_hits
        return score, strong_hits

    def _tenant_marker_score(self, text: str) -> tuple[int, int]:
        low = str(text or "").lower().replace("\\", "/")
        strong = sum(1 for marker in self._STRONG_TENANT_MARKERS if marker in low)
        weak = sum(1 for marker in self._WEAK_TENANT_MARKERS if marker in low)
        return (strong * 2) + weak, strong
