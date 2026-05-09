"""Table missing headers rule."""
from __future__ import annotations

import re
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

class TableMissingHeadersRule(Rule):
    id = "table-missing-headers"
    name = "Table Missing Headers"
    description = "Detects tables whose first row uses td cells instead of th headers"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx"]
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Use <th scope=\"col\"> for column headers and <th scope=\"row\"> for row headers. Screen readers use these to announce cell context."
    examples = {"bad": "<tr><td>Name</td><td>Email</td></tr>", "good": "<tr><th scope=\"col\">Name</th><th scope=\"col\">Email</th></tr>"}
    priority = 2
    group = "React Accessibility"
    applies_to = ["react-component", "page"]
    references = ["WCAG 1.3.1 Info and Relationships", "WCAG 2.1 SC 1.3.1"]
    related_rules = []
    false_positive_notes = "Tables that already contain any <th> are skipped."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "accessibility", "concern": "tables"}
    _TABLE = re.compile(r"<table\b.*?</table>", re.DOTALL | re.IGNORECASE)
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings=[]
        for m in self._TABLE.finditer(content):
            table=m.group(0)
            if '<th' in table.lower(): continue
            first=re.search(r"<tr\b.*?</tr>", table, re.DOTALL | re.IGNORECASE)
            if first and re.search(r"<td\b[^>]*>\s*[A-Z][A-Za-z]{1,20}\s*</td>", first.group(0)):
                line=content.count('\n',0,m.start())+1
                findings.append(self.create_finding("Table header row uses td cells", file_path, line, "The first table row looks like headers but uses <td> cells.", "Screen readers rely on table header cells to announce row/column context.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.72, tags=["react", "accessibility", "table"]))
        return findings
