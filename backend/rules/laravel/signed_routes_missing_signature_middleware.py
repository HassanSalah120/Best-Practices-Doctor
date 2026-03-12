"""
Signed Routes Missing Signature Middleware Rule

Detects tracked-link / redirect / invitation style routes that likely should require
Laravel's signed middleware.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class SignedRoutesMissingSignatureMiddlewareRule(Rule):
    id = "signed-routes-missing-signature-middleware"
    name = "Signed Routes Missing Signature Middleware"
    description = "Detects routes that likely need signed middleware but do not have it"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _SIGNED_TOKENS = ("track", "redirect", "unsubscribe", "verify", "invitation", "invite", "magic-link", "magiclink")
    
    # Patterns that indicate a notice/info page (not actual action)
    _NOTICE_TOKENS = ("notice", "info", "landing", "page", "show", "display")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for route in facts.routes or []:
            method = str(route.method or "").lower().strip()
            if method not in {"get", "any"}:
                continue

            descriptor = " ".join(
                [
                    str(route.uri or "").lower(),
                    str(route.controller or "").lower(),
                    str(route.action or "").lower(),
                    str(route.name or "").lower(),
                ]
            )
            if not any(tok in descriptor for tok in self._SIGNED_TOKENS):
                continue
            
            # Skip notice/info pages that don't need signature (e.g., verify-email notice)
            if any(tok in descriptor for tok in self._NOTICE_TOKENS):
                continue

            mw_text = " ".join(str(x).lower() for x in (route.middleware or []))
            if "signed" in mw_text:
                continue

            findings.append(
                self.create_finding(
                    title="Route likely handling signed links is missing signed middleware",
                    context=f"{str(route.method or '').upper()} {route.uri}",
                    file=route.file_path or "routes/web.php",
                    line_start=int(getattr(route, "line_number", 1) or 1),
                    description=(
                        f"Detected route `{str(route.method or '').upper()} {route.uri}` that looks like"
                        " a tracked-link, invitation, verification, or redirect handler without `signed` middleware."
                    ),
                    why_it_matters=(
                        "Tracked links and one-click actions often rely on signed URLs. Without signature"
                        " validation, attackers may tamper with redirect targets or protected actions."
                    ),
                    suggested_fix=(
                        "Protect the route with Laravel's `signed` middleware or validate signatures"
                        " explicitly with `hasValidSignature()` before processing the request."
                    ),
                    tags=["laravel", "security", "signed-urls", "routes"],
                    confidence=0.79,
                    evidence_signals=[
                        f"uri={route.uri}",
                        f"middleware={mw_text}",
                        "signed_middleware_missing=true",
                    ],
                )
            )
        return findings
