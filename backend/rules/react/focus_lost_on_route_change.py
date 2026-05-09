"""Focus lost on route change rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class FocusLostOnRouteChangeRule(Rule):
    id = "focus-lost-on-route-change"
    name = "Focus Lost On Route Change"
    description = "Detects SPA route navigation without visible focus restoration logic"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx"]
    severity_weight = 5
    confidence = "low"
    fix_suggestion = "Reset focus to main content or page heading after route transitions. Keyboard users lose context on SPA navigation."
    examples = {}
    priority = 3
    group = "React Accessibility"
    applies_to = ["page", "layout"]
    references = ["WCAG 2.4.3 Focus Order"]
    related_rules = []
    false_positive_notes = "Low confidence; projects with custom focus management hooks or router listeners are skipped."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "accessibility", "concern": "focus-management"}
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if re.search(r"useFocus|focus\s*\(|document\.activeElement|router\.on\(|onNavigate", content): return []
        if 'router.visit(' not in content and '<Link' not in content: return []
        line=content.find('router.visit(')
        if line < 0: line=content.find('<Link')
        return [self.create_finding("SPA navigation lacks focus restoration", file_path, content.count('\n',0,line)+1, "Navigation is present but no focus management is visible in this file.", "Keyboard and screen reader users need focus moved to new page content after client-side navigation.", self.fix_suggestion, context=file_path, confidence=0.42, tags=["react", "accessibility", "focus"])]
