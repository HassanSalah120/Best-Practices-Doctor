"""
Unified unsafe redirect rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule
from rules.laravel.unvalidated_login_redirect import UnvalidatedLoginRedirectRule
from rules.laravel.unsafe_external_redirect import UnsafeExternalRedirectRule


class UnsafeRedirectRule(Rule):
    id = "unsafe-redirect"
    name = "Unsafe Redirect"
    description = "Detects redirects that appear to trust unvalidated external or user-provided targets"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Remove the unsafe redirect risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'Security Hardening'
    applies_to = ['global']
    references = ['OWASP A01:2021 - Broken Access Control', 'CWE-601']
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'security', 'concern': 'unsafe-redirect'}

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
        findings: list[Finding] = []
        findings.extend(UnsafeExternalRedirectRule(self.config).analyze_regex(file_path, content, facts, metrics))
        findings.extend(UnvalidatedLoginRedirectRule(self.config).analyze_regex(file_path, content, facts, metrics))
        findings.extend(self._detect_self_approving_redirect_allowlist(file_path, content))

        normalized: list[Finding] = []
        seen: set[str] = set()
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        for finding in findings:
            confidence = float(getattr(finding, "confidence", 0.0) or 0.0)
            if confidence + 1e-9 < min_confidence:
                continue
            metadata = dict(getattr(finding, "metadata", {}) or {})
            metadata["source_rule_id"] = finding.rule_id
            updated = finding.model_copy(
                update={
                    "rule_id": self.id,
                    "severity": Severity.HIGH,
                    "title": "Redirect target appears unvalidated",
                    "description": (
                        "Detected redirect logic that may trust unvalidated external or user-provided URLs."
                    ),
                    "metadata": metadata,
                }
            )
            fp = updated.compute_fingerprint()
            if fp in seen:
                continue
            seen.add(fp)
            normalized.append(updated.model_copy(update={"fingerprint": fp, "id": f"finding_{fp}"}))
        return normalized

    def _detect_self_approving_redirect_allowlist(self, file_path: str, content: str) -> list[Finding]:
        lines = content.splitlines()
        findings: list[Finding] = []
        parse_re = re.compile(
            r"(?P<host>\$\w+)\s*=\s*parse_url\s*\(\s*(?P<input>\$\w+)\s*,\s*PHP_URL_HOST\s*\)",
            re.IGNORECASE,
        )
        for idx, line_text in enumerate(lines):
            match = parse_re.search(line_text)
            if not match:
                continue
            host_var = re.escape(match.group("host"))
            window = "\n".join(lines[idx + 1:idx + 11])
            if not re.search(
                rf"(\$\w*AllowedHosts\w*\s*\[\]\s*=\s*{host_var}|array_push\s*\(\s*\$\w*AllowedHosts\w*\s*,\s*{host_var}|"
                rf"\$\w*AllowedHosts\w*\s*=\s*\[\s*{host_var}\s*\])",
                window,
                re.IGNORECASE,
            ):
                continue
            findings.append(
                self.create_finding(
                    title="Redirect allowlist is built from the user supplied URL host",
                    file=file_path,
                    line_start=idx + 1,
                    line_end=idx + 1,
                    context=match.group("input"),
                    description=(
                        "The redirect host is parsed from user input and then added to the allowlist used to validate that same redirect."
                    ),
                    why_it_matters=(
                        "A self-approving allowlist defeats open redirect protection because an attacker can approve "
                        "the host they supplied."
                    ),
                    suggested_fix=(
                        "Use a static, trusted host allowlist from configuration or tenant settings. Never derive allowed "
                        "hosts from the URL currently being validated."
                    ),
                    tags=["laravel", "security", "redirect", "allowlist"],
                    confidence=0.92,
                    metadata={"source_rule_id": "self-approving-redirect-allowlist"},
                )
            )
        return findings
