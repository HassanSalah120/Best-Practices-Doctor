"""
Signed Routes Missing Signature Middleware Rule

Detects tracked-link / redirect / invitation style routes that likely should require
Laravel's signed middleware.
"""

from __future__ import annotations

import re

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
    _INTERNAL_AUTH_TOKENS = ("auth", "verified", "password", "emailverification", "verification")
    _PUBLIC_LINK_TOKENS = ("track", "redirect", "unsubscribe", "magic-link", "magiclink")
    _ROUTE_PARAM_HINTS = ("token", "signature", "hash", "code", "invite", "invitation")
    _ROUTE_PARAM_RE = re.compile(r"\{(?P<name>[^}:]+)")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_signal_count = int(self.get_threshold("min_signal_count", 2))
        min_confidence = float(self.get_threshold("min_confidence", 0.75))
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
            if self._is_internal_auth_route(descriptor, mw_text):
                continue
            signal_count, signal_evidence = self._intent_signals(route, descriptor)
            if signal_count < min_signal_count:
                continue

            confidence = min(0.95, 0.55 + (0.11 * signal_count))
            if "auth" in mw_text or "verified" in mw_text:
                confidence = max(0.5, confidence - 0.12)
            if confidence < min_confidence:
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
                    confidence=confidence,
                    evidence_signals=[
                        f"uri={route.uri}",
                        f"middleware={mw_text}",
                        f"signal_count={signal_count}",
                        f"min_signal_count={min_signal_count}",
                        *signal_evidence,
                        "signed_middleware_missing=true",
                    ],
                )
            )
        return findings

    def _is_internal_auth_route(self, descriptor: str, middleware_text: str) -> bool:
        if any(tok in descriptor for tok in self._PUBLIC_LINK_TOKENS):
            return False
        if "signed" in middleware_text:
            return False
        if "auth" in middleware_text or "verified" in middleware_text:
            return True
        return any(tok in descriptor for tok in self._INTERNAL_AUTH_TOKENS)

    def _intent_signals(self, route, descriptor: str) -> tuple[int, list[str]]:
        signals: list[str] = []
        route_name = str(getattr(route, "name", "") or "").lower()
        uri = str(getattr(route, "uri", "") or "").lower()

        if any(tok in descriptor for tok in self._PUBLIC_LINK_TOKENS):
            signals.append("public_link_token=true")
        if "invitation" in descriptor or "invite" in descriptor:
            signals.append("invitation_token=true")
        if "verify" in descriptor and "email/verify" not in uri:
            signals.append("verify_token=true")
        if route_name and any(tok in route_name for tok in self._SIGNED_TOKENS):
            signals.append("route_name_hint=true")

        params = [str(m.groupdict().get("name") or "").lower() for m in self._ROUTE_PARAM_RE.finditer(uri)]
        if any(any(hint in param for hint in self._ROUTE_PARAM_HINTS) for param in params):
            signals.append("route_param_hint=true")

        unique = list(dict.fromkeys(signals))
        return len(unique), unique
