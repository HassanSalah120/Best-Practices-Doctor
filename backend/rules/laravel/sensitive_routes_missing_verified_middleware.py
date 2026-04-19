"""
Sensitive Routes Missing Verified Middleware Rule

Detects auth-protected web routes for sensitive modules that do not require verified emails.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from core.project_recommendations import (
    enabled_capabilities,
    enabled_team_standards,
    project_aware_guidance,
    recommendation_context_tags,
)


class SensitiveRoutesMissingVerifiedMiddlewareRule(Rule):
    id = "sensitive-routes-missing-verified-middleware"
    name = "Sensitive Routes Missing Verified Middleware"
    description = "Detects sensitive web routes missing verified middleware"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_livewire",
    ]

    _SENSITIVE_TOKENS = (
        "billing",
        "subscription",
        "portal",
        "account",
        "profile",
        "settings",
        "clinic",
        "patient",
        "claim",
        "survey",
        "message",
        "campaign",
        "inventory",
        "lab",
        "order",
    )
    _PUBLIC_TOKENS = ("login", "register", "password", "reset", "verification", "verify", "webhook")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        capabilities = enabled_capabilities(facts)
        team_standards = enabled_team_standards(facts)
        for route in facts.routes or []:
            if not self._is_web_route(route.file_path or ""):
                continue
            uri = str(route.uri or "").strip().lower()
            if not uri or any(tok in uri for tok in self._PUBLIC_TOKENS):
                continue

            descriptor = " ".join(
                [
                    uri,
                    str(route.controller or "").lower(),
                    str(route.action or "").lower(),
                    str(route.name or "").lower(),
                ]
            )
            if not any(tok in descriptor for tok in self._SENSITIVE_TOKENS):
                continue

            mw_text = self._mw_text(route.middleware or [])
            if "auth" not in mw_text:
                continue
            if "verified" in mw_text:
                continue
            guidance = project_aware_guidance(facts, focus="orchestration_boundaries")

            findings.append(
                self.create_finding(
                    title="Sensitive route appears to be missing verified middleware",
                    context=f"{str(route.method or '').upper()} {route.uri}",
                    file=route.file_path or "routes/web.php",
                    line_start=int(getattr(route, "line_number", 1) or 1),
                    description=(
                        f"Detected sensitive route `{str(route.method or '').upper()} {route.uri}`"
                        " with auth protection but without `verified` middleware."
                    ),
                    why_it_matters=(
                        "Email verification is commonly used to harden billing, account, clinic,"
                        " and operational modules against unverified-user access."
                    ),
                    suggested_fix=(
                        "Add `verified` middleware to the enclosing route group or route definition,"
                        " or keep only explicitly public onboarding flows outside verified groups."
                    ) + (f"\n\nProject-aware guidance:\n{guidance}" if guidance else ""),
                    tags=["laravel", "security", "routes", "email-verification", *recommendation_context_tags(facts)],
                    confidence=0.81,
                    evidence_signals=[
                        f"uri={route.uri}",
                        f"middleware={mw_text}",
                        "verified_middleware_missing=true",
                    ],
                    metadata={
                        "decision_profile": {
                            "decision": "emit",
                            "project_business_context": str(getattr(getattr(facts, "project_context", None), "project_business_context", "unknown") or "unknown"),
                            "capabilities": sorted(capabilities),
                            "team_standards": sorted(team_standards),
                            "decision_summary": "Sensitive account/billing route requires verified middleware under current project context.",
                            "decision_reasons": [
                                f"descriptor_sensitive={int(any(tok in descriptor for tok in self._SENSITIVE_TOKENS))}",
                                "verified_middleware_missing=true",
                            ],
                        }
                    },
                )
            )
        return findings

    def _is_web_route(self, file_path: str) -> bool:
        low = (file_path or "").replace("\\", "/").lower()
        return low == "routes/web.php" or low.endswith("/routes/web.php")

    @staticmethod
    def _mw_text(middleware: list[str]) -> str:
        return " ".join(str(x).lower() for x in middleware)
