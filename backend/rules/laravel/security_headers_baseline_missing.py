"""
Security Headers Baseline Missing Rule

Detects projects without visible baseline security-header middleware/config.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class SecurityHeadersBaselineMissingRule(Rule):
    id = "security-headers-baseline-missing"
    name = "Security Headers Baseline Missing"
    description = "Detects missing baseline security headers handling for web apps"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "ast"

    _HEADER_MARKERS = (
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
        "referrer-policy",
    )
    _WEB_SIGNAL_FILES = ("routes/web.php", "resources/views/", "resources/js/pages/")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        files = [str(p or "").replace("\\", "/").lower() for p in (facts.files or [])]
        if not files:
            return []
        if not any(any(sig in path for sig in self._WEB_SIGNAL_FILES) for path in files):
            return []
        if self._has_security_headers_handling(facts):
            return []

        confidence = 0.79
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []

        return [
            self.create_finding(
                title="No visible baseline security headers enforcement",
                context="web-surface-security-headers",
                file="app/Http/Middleware",
                line_start=1,
                description="Could not detect baseline security header handling on web surfaces.",
                why_it_matters="Missing browser security headers increases risk for clickjacking, MIME confusion, and weak transport guarantees.",
                suggested_fix=(
                    "Add middleware (or trusted package) that sets baseline headers: HSTS, X-Content-Type-Options, "
                    "X-Frame-Options/frame-ancestors, Referrer-Policy, and CSP as appropriate."
                ),
                confidence=confidence,
                tags=["laravel", "security", "headers", "hardening"],
                evidence_signals=["security_headers_baseline_missing=true"],
            )
        ]

    def _has_security_headers_handling(self, facts: Facts) -> bool:
        for method in facts.methods or []:
            calls = [str(c or "").lower() for c in (method.call_sites or [])]
            if any(any(marker in call for marker in self._HEADER_MARKERS) for call in calls):
                return True
        return False

