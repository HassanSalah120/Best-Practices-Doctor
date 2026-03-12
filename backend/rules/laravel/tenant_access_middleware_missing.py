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

    _TENANT_TOKENS = ("clinic", "tenant", "workspace", "organization", "account", "practice", "branch")
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

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for route in facts.routes or []:
            descriptor = " ".join(
                [
                    str(route.uri or "").lower(),
                    str(route.controller or "").lower(),
                    str(route.action or "").lower(),
                    str(route.name or "").lower(),
                ]
            )
            if not any(tok in descriptor for tok in self._TENANT_TOKENS):
                continue

            mw_text = " ".join(str(x).lower() for x in (route.middleware or []))
            if "auth" not in mw_text:
                continue
            if any(tok in mw_text for tok in self._ACCESS_TOKENS):
                continue

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
                    confidence=0.77,
                    evidence_signals=[
                        f"uri={route.uri}",
                        f"middleware={mw_text}",
                        "tenant_access_middleware_missing=true",
                    ],
                )
            )
        return findings
