"""
Missing Content Security Policy rule.
"""

from __future__ import annotations

from rules.base import Rule
from rules.laravel._security_header_evidence import (
    has_enforcing_csp,
    iter_project_texts,
    normalize_path,
    written_security_headers,
)
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MissingContentSecurityPolicyRule(Rule):
    id = "missing-content-security-policy"
    name = "Missing Content Security Policy"
    description = "Detects CSP omissions in an application-owned security-header boundary"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    severity_weight = 0
    confidence = "high"
    fix_suggestion = "Remove the missing content security policy risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected."
    examples = {}
    priority = 1
    group = "Access Control"
    applies_to = ["global"]
    references = ["OWASP A05:2021 - Security Misconfiguration"]
    related_rules = []
    false_positive_notes = "May be a false positive when protection is enforced by upstream middleware, shared policy, or infrastructure not visible to the scanner."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "content-security-policy"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        norm = normalize_path(file_path)
        current_headers = written_security_headers(content or "")
        if len(current_headers) < 2:
            return []
        project_texts = list(
            iter_project_texts(
                facts,
                current_path=file_path,
                current_content=content,
            )
        )
        if any(has_enforcing_csp(text) for _, text in project_texts):
            return []

        owners = [
            (path, headers)
            for path, text in project_texts
            if len(headers := written_security_headers(text)) >= 2
        ]
        if not owners:
            # Absence is not evidence: CSP may be set by a CDN, load balancer, or web server.
            return []
        owner_path, present_headers = sorted(
            owners,
            key=lambda item: (-len(item[1]), item[0]),
        )[0]
        if norm != owner_path:
            return []

        return [
            self.create_finding(
                title="Content Security Policy appears missing",
                context="application-owned security-header boundary",
                file=file_path,
                line_start=1,
                description=(
                    "The application visibly writes browser security headers at this boundary, but no enforcing "
                    "`Content-Security-Policy` header or CSP middleware registration was found anywhere in the project."
                ),
                why_it_matters="CSP reduces XSS blast radius by constraining allowed script/style sources.",
                suggested_fix=(
                    "Register CSP middleware or set `Content-Security-Policy` response headers in your security middleware stack."
                ),
                confidence=0.8,
                tags=["laravel", "security", "headers", "csp"],
                evidence_signals=[
                    "csp_header_missing=true",
                    "header_ownership=application",
                    f"existing_headers={','.join(sorted(present_headers))}",
                ],
            ),
        ]
