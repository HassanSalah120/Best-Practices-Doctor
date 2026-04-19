"""
Zip Bomb Risk Rule

Detects archive extraction without size/entry-count guardrails.
"""

from __future__ import annotations

from schemas.facts import Facts, MethodInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ZipBombRiskRule(Rule):
    id = "zip-bomb-risk"
    name = "Zip Bomb Risk"
    description = "Detects archive extraction flows without decompression/entry safety checks"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    _ARCHIVE_OPEN = ("ziparchive", "->open(")
    _ARCHIVE_EXTRACT = ("->extractto(",)
    _SAFE_SIGNALS = ("numfiles", "statindex(", "filesize(", "maxentries", "maxuncompressed", "totaluncompressed")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for method in facts.methods or []:
            if not self._has_archive_flow(method):
                continue
            if self._has_safety_checks(method):
                continue
            confidence = 0.83
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Archive extraction without zip-bomb guardrails",
                    context=method.method_fqn,
                    file=method.file_path,
                    line_start=int(method.line_start or 1),
                    description="Detected ZipArchive extraction without visible entry-count or uncompressed-size checks.",
                    why_it_matters="Zip bombs can exhaust CPU, memory, or disk and cause denial-of-service in upload pipelines.",
                    suggested_fix=(
                        "Before extraction, validate entry count and cumulative uncompressed size, and enforce strict limits."
                    ),
                    related_methods=[method.method_fqn],
                    confidence=confidence,
                    tags=["laravel", "security", "upload", "archive"],
                    evidence_signals=["zip_extract=true", "zip_bomb_guard=false"],
                )
            )
        return findings

    def _has_archive_flow(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        has_open = any("->open(" in call for call in calls)
        has_extract = any(any(token in call for token in self._ARCHIVE_EXTRACT) for call in calls)
        return has_open and has_extract

    def _has_safety_checks(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(any(sig in call for sig in self._SAFE_SIGNALS) for call in calls)
