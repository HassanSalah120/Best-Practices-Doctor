"""Missing general error boundary rule."""
from __future__ import annotations

import re
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

class MissingErrorBoundaryGeneralRule(Rule):
    id = "missing-error-boundary-general"
    name = "Missing Error Boundary General"
    description = "Detects large data-heavy feature component trees without ErrorBoundary wrapping"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx"]
    severity_weight = 8
    confidence = "low"
    fix_suggestion = "Wrap independent feature sections in ErrorBoundary components. An unhandled render error in one feature should not crash the entire page."
    examples = {}
    priority = 2
    group = "React Stability"
    applies_to = ["react-component", "page"]
    references = []
    related_rules = ["route-shell-missing-error-boundary"]
    false_positive_notes = "Low confidence; only large, data-heavy component files are flagged and tests are skipped."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "quality", "concern": "error-boundary"}
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        norm=file_path.replace('\\','/').lower()
        if '/tests/' in '/' + norm or 'ErrorBoundary' in content or len(content.splitlines()) < 50: return []
        if not re.search(r"\b(useQuery|fetch\s*\(|axios\.|DataGrid|Chart|<table)\b", content): return []
        return [self.create_finding("Large feature tree has no ErrorBoundary", file_path, 1, "This large data-heavy component has no visible ErrorBoundary wrapper.", "Render errors in independent widgets should be contained so the entire page does not crash.", self.fix_suggestion, context=file_path, confidence=0.45, tags=["react", "stability", "error-boundary"])]
