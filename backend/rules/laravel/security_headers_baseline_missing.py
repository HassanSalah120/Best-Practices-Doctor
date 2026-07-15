"""
Security Headers Baseline Missing Rule

Detects projects without visible baseline security-header middleware/config.
"""

from __future__ import annotations

from rules.base import Rule
from rules.laravel._security_header_evidence import iter_project_texts, written_security_headers
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

    _BASELINE_HEADERS = (
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
        "referrer-policy",
    )
    severity_weight = 0
    confidence = "high"
    fix_suggestion = "Remove the security headers baseline missing risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected."
    examples = {}
    priority = 3
    group = "Security Hardening"
    applies_to = ["config"]
    references = ["OWASP A05:2021 - Security Misconfiguration"]
    related_rules = []
    false_positive_notes = "May be a false positive when protection is enforced by upstream middleware, shared policy, or infrastructure not visible to the scanner."
    detection_type = "cross-file"
    analysis_cost = "high"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "security-headers-baseline"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        files = [str(p or "").replace("\\", "/").lower() for p in (facts.files or [])]
        if not files:
            return []
        if not self._has_web_surface(facts, files):
            return []

        present = self._visible_security_headers(facts)
        if len(present) < 2:
            # With no visible ownership boundary, missing headers may be managed by deployment infrastructure.
            return []
        missing = set(self._BASELINE_HEADERS) - present
        if len(missing) < 2:
            return []

        confidence = 0.79
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []

        return [
            self.create_finding(
                title="Application security-header baseline appears incomplete",
                context="partial application security-header boundary",
                file="",
                line_start=1,
                description=(
                    "The application visibly writes some browser security headers, but its baseline appears incomplete. "
                    f"Present: {', '.join(sorted(present))}. Missing: {', '.join(sorted(missing))}."
                ),
                why_it_matters="Missing browser security headers increases risk for clickjacking, MIME confusion, and weak transport guarantees.",
                suggested_fix=(
                    "Add middleware (or trusted package) that sets baseline headers: HSTS, X-Content-Type-Options, "
                    "X-Frame-Options/frame-ancestors, Referrer-Policy, and CSP as appropriate."
                ),
                confidence=confidence,
                tags=["laravel", "security", "headers", "hardening"],
                evidence_signals=[
                    "security_headers_baseline_incomplete=true",
                    "header_ownership=application",
                    f"present_headers={','.join(sorted(present))}",
                    f"missing_headers={','.join(sorted(missing))}",
                ],
            ),
        ]

    def _visible_security_headers(self, facts: Facts) -> set[str]:
        found: set[str] = set()
        for method in facts.methods or []:
            found.update(
                written_security_headers(
                    "\n".join(str(call or "") for call in method.call_sites or [])
                )
            )
        for _, text in iter_project_texts(facts, current_path="", current_content=""):
            found.update(written_security_headers(text))
        return found

    @staticmethod
    def _has_web_surface(facts: Facts, files: list[str]) -> bool:
        if any(path.endswith((".blade.php", ".tsx", ".jsx", ".vue")) for path in files):
            return True
        return any(
            str(route.method or "").upper() == "GET"
            and not str(route.uri or "").lstrip("/").lower().startswith("api/")
            for route in facts.routes or []
        )
