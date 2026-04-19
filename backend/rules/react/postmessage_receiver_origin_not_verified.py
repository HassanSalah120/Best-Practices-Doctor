"""
PostMessage Receiver Origin Not Verified Rule

Detects `message` event listeners that do not verify `event.origin`.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class PostMessageReceiverOriginNotVerifiedRule(Rule):
    id = "postmessage-receiver-origin-not-verified"
    name = "postMessage Receiver Missing Origin Verification"
    description = "Detects message event listeners that handle cross-window messages without origin checks"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    regex_file_extensions = [".tsx", ".ts", ".jsx", ".js"]

    _LISTENER_SIGNALS = (
        "addEventListener('message'",
        'addEventListener("message"',
        "window.onmessage",
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
        if not any(sig in text for sig in self._LISTENER_SIGNALS):
            return []
        if any(sig in text for sig in self._ORIGIN_CHECK_SIGNALS):
            return []
        if self._SAFE_LOCAL_ONLY_SIGNAL in text and "window.location.origin" in text:
            return []

        line = self._find_line(text)
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
            )
        ]

    def _find_line(self, text: str) -> int:
        candidates = [text.find(sig) for sig in self._LISTENER_SIGNALS if text.find(sig) != -1]
        if not candidates:
            return 1
        start = min(candidates)
        return text.count("\n", 0, start) + 1

