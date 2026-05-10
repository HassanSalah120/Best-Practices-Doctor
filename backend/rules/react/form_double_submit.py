"""Form double-submit rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class FormDoubleSubmitRule(Rule):
    id = "form-double-submit"
    name = "Form Double Submit"
    description = "Detects submit buttons without disabled state during submission"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx"]
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Add disabled={isSubmitting} or disabled={loading} to submit buttons. Double-clicks cause duplicate API requests."
    examples = {"bad": "<button type=\"submit\">Save</button>", "good": "<button type=\"submit\" disabled={isSubmitting}>Save</button>"}
    priority = 2
    group = "React Stability"
    applies_to = ["form", "react-component"]
    references = []
    related_rules = []
    false_positive_notes = "Inertia useForm components using processing are skipped because the framework state usually controls submit disabling."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "quality", "concern": "forms"}
    _BUTTON = re.compile(r"<button\b(?P<attrs>[^>]*type=['\"]submit['\"][^>]*)>", re.IGNORECASE)
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if 'useForm' in content and 'processing' in content: return []
        findings=[]
        for m in self._BUTTON.finditer(content):
            if 'disabled' in m.group('attrs'): continue
            line=content.count('\n',0,m.start())+1
            findings.append(self.create_finding("Submit button is not disabled while submitting", file_path, line, "A submit button has no disabled state.", "Users can double-click and send duplicate requests unless submission state disables the control.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.72, tags=["react", "stability", "forms"]))
        return findings
