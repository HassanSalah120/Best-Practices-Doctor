"""
Unified unsafe redirect rule.
"""

from __future__ import annotations

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
