"""
Security Headers Baseline Missing Rule

Detects projects without visible baseline security-header middleware/config.
"""

from __future__ import annotations

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


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
    _WEB_SIGNAL_PATTERNS = ("/views/", "/pages/", "routes/web")
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Remove the security headers baseline missing risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 3
    group = 'Security Hardening'
    applies_to = ['config']
    references = ['OWASP A05:2021 - Security Misconfiguration']
    related_rules = []
    false_positive_notes = 'May be a false positive when protection is enforced by upstream middleware, shared policy, or infrastructure not visible to the scanner.'
    detection_type = 'cross-file'
    analysis_cost = 'high'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'security', 'concern': 'security-headers-baseline'}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        files = [str(p or "").replace("\\", "/").lower() for p in (facts.files or [])]
        if not files:
            return []
        if not any(any(sig in path for sig in self._WEB_SIGNAL_PATTERNS) for path in files):
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
                file="",
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
            ),
        ]

    def _has_security_headers_handling(self, facts: Facts) -> bool:
        for method in facts.methods or []:
            calls = [str(c or "").lower() for c in (method.call_sites or [])]
            if any(any(marker in call for marker in self._HEADER_MARKERS) for call in calls):
                return True
        return False

