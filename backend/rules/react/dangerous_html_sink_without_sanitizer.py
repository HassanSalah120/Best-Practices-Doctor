"""
Dangerous HTML Sink Without Sanitizer Rule

Detects `dangerouslySetInnerHTML` usage without obvious sanitizer signals.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class DangerousHtmlSinkWithoutSanitizerRule(Rule):
    id = "dangerous-html-sink-without-sanitizer"
    name = "Dangerous HTML Sink Without Sanitizer"
    description = "Detects dangerouslySetInnerHTML usage without sanitizer guard"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"

    regex_file_extensions = [".tsx", ".ts", ".jsx", ".js"]

    _SINK_PATTERN = re.compile(
        r"dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:",
        re.IGNORECASE | re.DOTALL,
    )
    _STYLE_SINK_PATTERN = re.compile(
        r"<style\b[^>]*dangerouslySetInnerHTML\s*=",
        re.IGNORECASE | re.DOTALL,
    )
    _SANITIZER_SIGNALS = ("dompurify.sanitize", "sanitizehtml(", "xss(", "sanitizer.sanitize(", "sanitize(")

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
        if "dangerouslySetInnerHTML" not in text:
            return []

        text_lower = text.lower()
        sink_matches = list(self._SINK_PATTERN.finditer(text))
        style_sinks = {m.start() for m in self._STYLE_SINK_PATTERN.finditer(text)}
        if not sink_matches:
            return []

        sink_match: re.Match[str] | None = None
        sink_line = 1
        is_style_sink = False

        for match in sink_matches:
            start = match.start()
            end = match.end()
            window_start = max(0, start - 280)
            window_end = min(len(text_lower), end + 280)
            sink_window = text_lower[window_start:window_end]

            if any(sig in sink_window for sig in self._SANITIZER_SIGNALS):
                continue

            sink_match = match
            sink_line = self._find_line(text, start)
            is_style_sink = start in style_sinks
            break

        if sink_match is None:
            return []

        confidence = 0.94 if is_style_sink else 0.9
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        if confidence + 1e-9 < min_confidence:
            return []
        return [
            self.create_finding(
                title="dangerouslySetInnerHTML used without sanitizer",
                context=f"{file_path}:{sink_line}:dangerous-html-sink",
                file=file_path,
                line_start=sink_line,
                description="Detected HTML sink usage without visible sanitization step.",
                why_it_matters="Unsanitized HTML rendering can introduce DOM XSS and account/session compromise.",
                suggested_fix="Sanitize untrusted HTML with a trusted sanitizer (for example DOMPurify) before rendering.",
                confidence=confidence,
                tags=["react", "security", "xss", "html-sink"],
                evidence_signals=[
                    "dangerous_html_sink=true",
                    "sanitizer_missing=true",
                    f"style_tag_sink={str(is_style_sink).lower()}",
                ],
            )
        ]

    def _find_line(self, text: str, idx_hint: int | None = None) -> int:
        idx = idx_hint if idx_hint is not None else text.find("dangerouslySetInnerHTML")
        if idx == -1:
            idx = text.find("__html")
        if idx == -1:
            return 1
        return text.count("\n", 0, idx) + 1
