"""
React Hooks In Conditional Or Loop Rule

Detects hook calls inside conditionals/loops/callback loops.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class HooksInConditionalOrLoopRule(Rule):
    id = "hooks-in-conditional-or-loop"
    name = "Hooks In Conditional Or Loop"
    description = "Detects React hooks inside conditionals, loops, or callback loops"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _PATTERNS = [
        re.compile(r"\bif\s*\([^)]*\)\s*{[^{}]{0,500}\b(use[A-Z][A-Za-z0-9_]*)\s*\(", re.DOTALL),
        re.compile(r"\b(for|while)\s*\([^)]*\)\s*{[^{}]{0,500}\b(use[A-Z][A-Za-z0-9_]*)\s*\(", re.DOTALL),
        re.compile(r"(?:\?|&&)\s*(use[A-Z][A-Za-z0-9_]*)\s*\(", re.DOTALL),
        re.compile(
            r"\.(map|forEach|filter|reduce)\s*\([^)]*=>\s*{[^{}]{0,500}\b(use[A-Z][A-Za-z0-9_]*)\s*\(",
            re.DOTALL,
        ),
    ]

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
        if "use" not in (content or ""):
            return []

        hits: set[tuple[int, str]] = set()
        for pat in self._PATTERNS:
            for m in pat.finditer(content):
                hook_name = ""
                if m.groups():
                    for g in m.groups():
                        if g and g.startswith("use"):
                            hook_name = g
                            break
                line = content.count("\n", 0, m.start()) + 1
                hits.add((line, hook_name or "hook"))

        findings: list[Finding] = []
        for line, hook_name in sorted(hits):
            findings.append(
                self.create_finding(
                    title="Hook call appears inside conditional/loop",
                    context=f"{file_path}:{line}:{hook_name}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected `{hook_name}(...)` in a conditional/loop-like context. "
                        "Hooks must be called unconditionally and in a stable order."
                    ),
                    why_it_matters=(
                        "Conditional hook calls break React's hook ordering and can cause runtime bugs "
                        "that are hard to reproduce."
                    ),
                    suggested_fix=(
                        "Move hook calls to the top level of the component/custom hook.\n"
                        "Put conditions inside the hook callback or after computing values."
                    ),
                    tags=["react", "hooks", "correctness"],
                    confidence=0.9,
                )
            )
        return findings
