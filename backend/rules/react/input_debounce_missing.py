"""Input debounce missing rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class InputDebounceMissingRule(Rule):
    id = "input-debounce-missing"
    name = "Input Debounce Missing"
    description = "Detects input search/change handlers that call fetch/search without debounce"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx"]
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Debounce search/filter onChange handlers by 300-500ms. Every keystroke should not trigger an API call."
    examples = {"bad": "onChange={e => fetchResults(e.target.value)}", "good": "onChange={useMemo(() => debounce(e => fetchResults(e.target.value), 300), [])}"}
    priority = 2
    group = "React Performance"
    applies_to = ["react-component", "form"]
    references = []
    related_rules = []
    false_positive_notes = "Selects, checkboxes, hidden inputs, and already-debounced handlers are skipped."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "performance", "concern": "forms"}
    _INPUT = re.compile(r"<input\b", re.IGNORECASE)
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if re.search(r"debounce\s*\(|useDebounce", content): return []
        findings=[]
        for m in self._INPUT.finditer(content):
            end = content.find("/>", m.start())
            if end < 0:
                end = content.find(">", m.start())
            attrs = content[m.start():end if end >= 0 else min(len(content), m.start() + 240)]
            if re.search(r"type=['\"](?:hidden|checkbox)['\"]", attrs): continue
            if not re.search(r"onChange=\{[^}]*\b(fetch|search|axios|filter)\w*\s*\(", attrs): continue
            line=content.count("\n",0,m.start())+1
            findings.append(self.create_finding("Input change handler should be debounced", file_path, line, "An input onChange handler appears to call search/fetch logic immediately.", "Every keystroke can produce network or expensive filtering work, creating lag and unnecessary backend load.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.72, tags=["react", "performance", "forms"]))
        return findings
