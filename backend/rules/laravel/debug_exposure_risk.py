"""
Unified debug exposure risk rule.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule
from rules.laravel.api_debug_trace_leak import ApiDebugTraceLeakRule
from rules.laravel.debug_mode_exposure import DebugModeExposureRule


class DebugExposureRiskRule(Rule):
    id = "debug-exposure-risk"
    name = "Debug Exposure Risk"
    description = "Detects debug settings that can expose stack traces, secrets, or internal internals"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php", ".env", ".env.example"]
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Remove the debug exposure risk risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'Security Hardening'
    applies_to = ['global']
    references = ['OWASP A05:2021 - Security Misconfiguration']
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'security', 'concern': 'debug-exposure'}

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
        findings.extend(DebugModeExposureRule(self.config).analyze_regex(file_path, content, facts, metrics))
        findings.extend(ApiDebugTraceLeakRule(self.config).analyze_regex(file_path, content, facts, metrics))

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
                    "title": "Debug exposure risk in production-facing configuration",
                    "description": (
                        "Debug-related configuration appears unsafe for production and may expose traces or sensitive internals."
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
