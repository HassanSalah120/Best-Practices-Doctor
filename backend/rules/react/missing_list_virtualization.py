"""Missing list virtualization rule."""
from __future__ import annotations

import re
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

class MissingListVirtualizationRule(Rule):
    id = "missing-list-virtualization"
    name = "Missing List Virtualization"
    description = "Detects large-looking list renders without virtualization imports"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx"]
    severity_weight = 8
    confidence = "low"
    fix_suggestion = "Use react-window or @tanstack/virtual-core for lists that may exceed 100 items. Rendering all DOM nodes at once causes severe performance degradation."
    examples = {"bad": "{allUsers.map(u => <UserRow key={u.id} user={u}/>)}", "good": "<VirtualList items={allUsers} renderItem={u => <UserRow user={u}/>}/>"}
    priority = 2
    group = "React Performance"
    applies_to = ["react-component", "page"]
    references = []
    related_rules = ["missing-pagination"]
    false_positive_notes = "Low confidence: it only flags list variable names that strongly suggest large datasets."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "performance", "concern": "lists"}
    _MAP = re.compile(r"\b(?:allUsers|users|products|items|orders|records)\.map\s*\(")
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if re.search(r"react-window|@tanstack/virtual|VirtualList", content): return []
        findings=[]
        for m in self._MAP.finditer(content):
            line=content.count("\n",0,m.start())+1
            findings.append(self.create_finding("Large list render may need virtualization", file_path, line, "A collection with a large-data name is rendered with .map() and no virtualization library is imported.", "Rendering hundreds of rows at once increases DOM size and slows interactions.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.45, tags=["react", "performance", "lists"]))
        return findings
