"""Unthrottled scroll/resize handler rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class UnthrottledScrollResizeHandlerRule(Rule):
    id = "unthrottled-scroll-resize-handler"
    name = "Unthrottled Scroll/Resize Handler"
    description = "Detects scroll or resize listeners without throttle/debounce protection"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Wrap scroll/resize handlers in throttle() or debounce() from lodash. These events fire hundreds of times per second and will cause frame drops without rate limiting."
    examples = {"bad": "window.addEventListener('scroll', expensiveHandler);", "good": "window.addEventListener('scroll', throttle(expensiveHandler, 100));"}
    priority = 2
    group = "React Performance"
    applies_to = ["react-component", "hook"]
    references = []
    related_rules = []
    false_positive_notes = "Handlers with explicit cleanup nearby are skipped to avoid flagging lifecycle wiring examples."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "performance", "concern": "events"}
    _EVENT = re.compile(r"addEventListener\s*\(\s*['\"](?:scroll|resize)['\"]", re.IGNORECASE)
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        lines = content.splitlines(); findings=[]
        for i, line in enumerate(lines, start=1):
            if not self._EVENT.search(line): continue
            nearby = "\n".join(lines[max(0, i-6):min(len(lines), i+5)])
            if re.search(r"throttle\s*\(|debounce\s*\(|useThrottle|useDebounce|removeEventListener", nearby): continue
            findings.append(self.create_finding("Scroll/resize handler is not throttled", file_path, i, "A high-frequency browser event listener is registered without rate limiting.", "Scroll and resize events can fire many times per frame and cause visible jank when the handler is expensive.", self.fix_suggestion, context=f"{file_path}:{i}", confidence=0.9, tags=["react", "performance", "events"]))
        return findings
