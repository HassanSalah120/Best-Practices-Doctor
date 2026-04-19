"""
Host Header Poisoning Risk Rule

Detects request host usage in redirect/URL construction without clear trust boundary.
"""

from __future__ import annotations

from schemas.facts import Facts, MethodInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class HostHeaderPoisoningRiskRule(Rule):
    id = "host-header-poisoning-risk"
    name = "Host Header Poisoning Risk"
    description = "Detects host header-derived URL/redirect construction without trusted host guard"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    _HOST_SOURCE_SIGNALS = (
        "->gethost(",
        "request()->gethost(",
        "header('host'",
        'header("host"',
        "$_server['http_host']",
        '$_server["http_host"]',
    )
    _URL_SINK_SIGNALS = (
        "redirect()->to(",
        "redirect::to(",
        "url::to(",
        "url()->to(",
        "response()->redirectto(",
    )
    _SAFE_SIGNALS = ("trusthosts", "trustedproxy", "isallowedhost", "allowlist", "whitelist")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for method in facts.methods or []:
            if not self._method_uses_host_source(method):
                continue
            if not self._method_uses_redirect_sink(method):
                continue
            if self._method_has_safe_guard(method):
                continue

            confidence = 0.86
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Host header value reaches redirect/URL sink",
                    context=method.method_fqn,
                    file=method.file_path,
                    line_start=int(method.line_start or 1),
                    description="Detected host-derived input used to construct redirect/URL response without visible trusted-host guard.",
                    why_it_matters="Host header poisoning can produce open redirects, cache poisoning, and password reset link poisoning.",
                    suggested_fix=(
                        "Avoid building redirect targets from request host headers. Use trusted config hosts or explicit host allowlists."
                    ),
                    related_methods=[method.method_fqn],
                    confidence=confidence,
                    tags=["laravel", "security", "host-header", "redirect"],
                    evidence_signals=["host_source=true", "redirect_sink=true", "trusted_host_guard=false"],
                )
            )
        return findings

    def _method_uses_host_source(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(any(sig in c for sig in self._HOST_SOURCE_SIGNALS) for c in calls)

    def _method_uses_redirect_sink(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(any(sig in c for sig in self._URL_SINK_SIGNALS) for c in calls)

    def _method_has_safe_guard(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(any(sig in c for sig in self._SAFE_SIGNALS) for c in calls)

