"""Missing fieldset legend rule."""
from __future__ import annotations

import re
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

class MissingFieldsetLegendRule(Rule):
    id = "missing-fieldset-legend"
    name = "Missing Fieldset Legend"
    description = "Detects radio/checkbox groups without fieldset and legend"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx"]
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Wrap related radio/checkbox groups in <fieldset> with a <legend> describing the group. Screen readers announce the legend when entering the group."
    examples = {"bad": "<div><input type=\"radio\" name=\"size\" value=\"s\"/><input type=\"radio\" name=\"size\" value=\"l\"/></div>", "good": "<fieldset><legend>Size</legend><input type=\"radio\" name=\"size\" value=\"s\"/></fieldset>"}
    priority = 2
    group = "React Accessibility"
    applies_to = ["form", "react-component"]
    references = ["WCAG 1.3.1 Info and Relationships"]
    related_rules = []
    false_positive_notes = "Single radio/checkbox controls are skipped; the rule targets groups."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "accessibility", "concern": "forms"}
    _INPUT = re.compile(r"<input\b[^>]*type=['\"](?:radio|checkbox)['\"][^>]*>", re.IGNORECASE)
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if '<fieldset' in content.lower() and '<legend' in content.lower(): return []
        matches=list(self._INPUT.finditer(content))
        if len(matches) < 2: return []
        line=content.count('\n',0,matches[0].start())+1
        return [self.create_finding("Radio/checkbox group lacks fieldset and legend", file_path, line, "Multiple related choice controls are present without a fieldset/legend wrapper.", "Screen readers announce legends to provide group context for related inputs.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.72, tags=["react", "accessibility", "forms"])]
