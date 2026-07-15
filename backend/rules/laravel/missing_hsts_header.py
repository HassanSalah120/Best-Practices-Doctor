"""
Missing HSTS header rule.
"""

from __future__ import annotations

from rules.base import Rule
from rules.laravel._security_header_evidence import (
    iter_project_texts,
    normalize_path,
    written_security_headers,
)
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MissingHstsHeaderRule(Rule):
    id = "missing-hsts-header"
    name = "Missing HSTS Header"
    description = "Detects HSTS omissions at an application-owned security-header boundary"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    severity_weight = 0
    confidence = "high"
    fix_suggestion = "Remove the missing hsts header risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected."
    examples = {}
    priority = 1
    group = "Security Hardening"
    applies_to = ["config"]
    references = ["OWASP A05:2021 - Security Misconfiguration"]
    related_rules = []
    false_positive_notes = "May be a false positive when protection is enforced by upstream middleware, shared policy, or infrastructure not visible to the scanner."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "hsts-header"}

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
        inventories = [(path, written_security_headers(text)) for path, text in project_texts]
        if any("strict-transport-security" in headers for _, headers in inventories):
            return []
        owners = [(path, headers) for path, headers in inventories if len(headers) >= 2]
        if not owners:
            # HSTS is commonly and correctly owned by a TLS terminator outside the repository.
            return []
        owner_path, present_headers = sorted(
            owners,
            key=lambda item: (-len(item[1]), item[0]),
        )[0]
        if norm != owner_path:
            return []

        return [
            self.create_finding(
                title="HSTS header hardening appears missing",
                context="application-owned security-header boundary",
                file=file_path,
                line_start=1,
                description=(
                    "The application visibly owns a multi-header browser security boundary, but no "
                    "`Strict-Transport-Security` header was found in application or infrastructure configuration."
                ),
                why_it_matters=(
                    "Without HSTS, browsers may downgrade to insecure HTTP, enabling man-in-the-middle attacks."
                ),
                suggested_fix=(
                    "Add a security headers middleware that sets `Strict-Transport-Security` for HTTPS responses."
                ),
                confidence=0.82,
                tags=["laravel", "security", "headers", "hsts"],
                evidence_signals=[
                    "hsts_header_missing=true",
                    "header_ownership=application",
                    f"existing_headers={','.join(sorted(present_headers))}",
                ],
            ),
        ]
