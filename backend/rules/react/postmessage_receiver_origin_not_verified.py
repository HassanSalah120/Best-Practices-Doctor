"""
PostMessage Receiver Origin Not Verified Rule

Detects `message` event listeners that do not verify `event.origin`.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class PostMessageReceiverOriginNotVerifiedRule(Rule):
    id = "postmessage-receiver-origin-not-verified"
    name = "postMessage Receiver Missing Origin Verification"
    description = "Detects message event listeners that handle cross-window messages without origin checks"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    regex_file_extensions = [".tsx", ".ts", ".jsx", ".js"]

    _WINDOW_MESSAGE_LISTENER = re.compile(
        r"(?:\bwindow\s*\.|\bglobalThis\s*\.|(?<![.$\w])\b)"
        r"addEventListener\s*\(\s*['\"]message['\"]|\bwindow\s*\.\s*onmessage\s*=",
        re.IGNORECASE,
    )
    _ORIGIN_CHECK_SIGNALS = (
        "event.origin",
        "e.origin",
        "origin ===",
        "allowedOrigins",
        "includes(event.origin)",
        "startsWith(",
    )
    _SAFE_LOCAL_ONLY_SIGNAL = "new URL("
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Remove the postmessage receiver missing origin verification risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'Access Control'
    applies_to = ['react-component']
    references = ['OWASP A05:2021 - Security Misconfiguration']
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'security', 'concern': 'postmessage-receiver-origin'}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        text = content or ""
        listener = self._WINDOW_MESSAGE_LISTENER.search(text)
        if not listener:
            return []
        if any(sig in text for sig in self._ORIGIN_CHECK_SIGNALS):
            return []
        if self._SAFE_LOCAL_ONLY_SIGNAL in text and "window.location.origin" in text:
            return []

        line = text.count("\n", 0, listener.start()) + 1
        confidence = 0.9
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []
        return [
            self.create_finding(
                title="Message event receiver does not verify event.origin",
                context=f"{file_path}:{line}:message-listener",
                file=file_path,
                line_start=line,
                description="Detected cross-window message listener without explicit sender origin verification.",
                why_it_matters="Unchecked postMessage origins can allow hostile frames/windows to inject commands or tokens.",
                suggested_fix="Check `event.origin` against an explicit allowlist before processing message data.",
                confidence=confidence,
                tags=["react", "security", "postmessage", "origin"],
                evidence_signals=["postmessage_listener=true", "origin_check=false"],
            ),
        ]

