"""Unhandled promise in handler rule."""
from __future__ import annotations

import re
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

class UnhandledPromiseInHandlerRule(Rule):
    id = "unhandled-promise-in-handler"
    name = "Unhandled Promise In Handler"
    description = "Detects async event handlers with await but no local error handling"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx", ".ts", ".js"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Wrap async handler bodies in try/catch. Unhandled promise rejections in event handlers fail silently in production."
    examples = {"bad": "const handleSave = async () => { await save(data); };", "good": "const handleSave = async () => { try { await save(data); } catch(e) { setError(e.message); } };"}
    priority = 2
    group = "React Stability"
    applies_to = ["react-component", "form"]
    references = []
    related_rules = []
    false_positive_notes = "React Query mutation handlers and explicit .catch() usage are skipped."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "quality", "concern": "async-handlers"}
    _HANDLER = re.compile(r"(?:const|function)\s+(handle\w+)\s*=?.*?async\s*(?:\([^)]*\)|[^=]*)\s*=>?\s*\{(?P<body>.*?)\n\s*\}", re.DOTALL)
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if 'useMutation' in content or 'mutateAsync' in content: return []
        findings=[]
        for m in self._HANDLER.finditer(content):
            body=m.group('body')
            if 'await ' not in body or 'try {' in body or '.catch(' in body: continue
            line=content.count('\n',0,m.start())+1
            findings.append(self.create_finding("Async handler lacks error handling", file_path, line, "This async event handler awaits work without try/catch or .catch().", "Unhandled rejections are easy to miss in production and leave users without a clear error state.", self.fix_suggestion, context=m.group(1), confidence=0.86, tags=["react", "stability", "async"] ))
        return findings
