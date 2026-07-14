"""
Anonymous Default Export Component Rule

Detects React components exported as anonymous default functions or arrows.
"""

from __future__ import annotations

import os
import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class AnonymousDefaultExportComponentRule(Rule):
    id = "anonymous-default-export-component"
    name = "Anonymous Default Export Component"
    description = "Detects anonymous default-exported React components"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ANON_FN = re.compile(r"export\s+default\s+function\s*\(", re.IGNORECASE)
    _ANON_ARROW = re.compile(
        r"export\s+default\s+(?:memo\s*\(\s*|forwardRef\s*\(\s*)?(?:async\s*)?\(?[A-Za-z0-9_,\s]*\)?\s*=>",
        re.IGNORECASE,
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the anonymous default export component pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'anonymous-default-export'}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        norm = (file_path or "").replace("\\", "/").lower()
        if any(x in norm for x in [".test.", ".spec.", "__tests__", ".stories."]):
            return []

        ext = os.path.splitext(norm)[1]
        text = content or ""
        # Keep plain .ts/.js modules out unless they visibly contain JSX or React hooks.
        if ext in {".ts", ".js"} and not any(hint in text for hint in ("<", "useState(", "useEffect(", "React.")):
            return []

        match = self._ANON_FN.search(text) or self._ANON_ARROW.search(text)
        if not match:
            return []

        line = text.count("\n", 0, match.start()) + 1
        label = os.path.splitext(os.path.basename(file_path))[0] or "Component"
        return [
            self.create_finding(
                title="Anonymous default-exported component",
                context=f"{file_path}:{line}:default-export",
                file=file_path,
                line_start=line,
                description=(
                    "Detected a React component exported as an anonymous default function or arrow instead of a "
                    "named component."
                ),
                why_it_matters=(
                    "Anonymous component exports make stack traces, React DevTools labels, and searchability worse. "
                    "Named components are easier to debug and refactor."
                ),
                suggested_fix=(
                    f"Give the component a stable name, for example `function {label}()` or "
                    f"`const {label} = (...) => ...; export default {label};`."
                ),
                tags=["react", "structure", "exports", "debuggability"],
                confidence=0.92,
                evidence_signals=["anonymous_default_export=true", f"file={file_path}"],
            ),
        ]
