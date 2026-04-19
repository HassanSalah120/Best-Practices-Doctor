"""
XML XXE Risk Rule

Detects XML parser usage without clear external-entity/network hardening.
"""

from __future__ import annotations

from schemas.facts import Facts, MethodInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class XmlXxeRiskRule(Rule):
    id = "xml-xxe-risk"
    name = "Potential XML External Entity Risk"
    description = "Detects XML parsing calls without XXE hardening signals"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    _XML_PARSE_SIGNALS = (
        "simplexml_load_string(",
        "simplexml_load_file(",
        "->loadxml(",
        "->xml(",
        "xmlreader::xml(",
    )
    _SAFE_SIGNALS = ("libxml_nonet", "resolveexternals = false", "substituteentities = false", "xmllint_safe")
    _UNSAFE_SIGNALS = ("libxml_noent", "resolveexternals = true", "substituteentities = true")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for method in facts.methods or []:
            if not self._uses_xml_parser(method):
                continue
            if self._has_safe_signal(method) and not self._has_unsafe_signal(method):
                continue

            confidence = 0.85 if self._has_unsafe_signal(method) else 0.78
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="XML parsing without explicit XXE hardening",
                    context=method.method_fqn,
                    file=method.file_path,
                    line_start=int(method.line_start or 1),
                    description="Detected XML parse calls without clear external entity/network restrictions.",
                    why_it_matters="Unsafe XML parsing can allow XXE to read local files or pivot to internal network targets.",
                    suggested_fix="Use safe XML parser settings (disable external entities, block network fetches, avoid unsafe libxml flags).",
                    related_methods=[method.method_fqn],
                    confidence=confidence,
                    tags=["laravel", "security", "xxe", "xml"],
                    evidence_signals=[
                        "xml_parser_call=true",
                        f"safe_signal={int(self._has_safe_signal(method))}",
                        f"unsafe_signal={int(self._has_unsafe_signal(method))}",
                    ],
                )
            )
        return findings

    def _uses_xml_parser(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(any(sig in call for sig in self._XML_PARSE_SIGNALS) for call in calls)

    def _has_safe_signal(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(any(sig in call for sig in self._SAFE_SIGNALS) for call in calls)

    def _has_unsafe_signal(self, method: MethodInfo) -> bool:
        calls = [str(c or "").lower() for c in (method.call_sites or [])]
        return any(any(sig in call for sig in self._UNSAFE_SIGNALS) for call in calls)

