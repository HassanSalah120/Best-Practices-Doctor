"""
Unsafe include/require variable rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class UnsafeFileIncludeVariableRule(Rule):
    id = "unsafe-file-include-variable"
    name = "Unsafe File Include Variable"
    description = "Detects include/require calls that use unsanitized variable paths"
    category = Category.SECURITY
    default_severity = Severity.CRITICAL
    type = "regex"
    regex_file_extensions = [".php"]

    _INCLUDE = re.compile(
        r"\b(include|require|include_once|require_once)\b\s*(?:\(\s*)?(?P<expr>\$[A-Za-z_][A-Za-z0-9_]*)",
        re.IGNORECASE,
    )
    _WHITELIST_SIGNAL = re.compile(
        r"(in_array|whitelist|allowed_files|allowed_templates|safe_include)",
        re.IGNORECASE,
    )
    _TYPE_HINT_SIGNAL = re.compile(r"\b(string|class-string)\s+\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)

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
        lines = (content or "").splitlines()
        findings: list[Finding] = []
        for i, line in enumerate(lines, start=1):
            match = self._INCLUDE.search(line)
            if not match:
                continue
            expr = str(match.groupdict().get("expr") or "")
            var_name = expr.lstrip("$")
            if "__dir__" in line.lower() or "'" in line or '"' in line:
                continue
            window = "\n".join(lines[max(0, i - 5):i + 1])
            if self._WHITELIST_SIGNAL.search(window):
                continue
            # Guard: allow when same variable is explicitly type-hinted nearby.
            typed = False
            for hint in self._TYPE_HINT_SIGNAL.finditer(window):
                if str(hint.groupdict().get("var") or "") == var_name:
                    typed = True
                    break
            if typed:
                continue

            findings.append(
                self.create_finding(
                    title="Variable-driven include/require detected",
                    context=line.strip()[:100],
                    file=file_path,
                    line_start=i,
                    description="Detected include/require using a variable path without visible allowlist safeguards.",
                    why_it_matters="Dynamic includes can enable local file inclusion or arbitrary code execution chains.",
                    suggested_fix=(
                        "Resolve includes from a fixed allowlist/map and avoid direct user-influenced include paths."
                    ),
                    confidence=0.9,
                    tags=["php", "security", "include", "lfi"],
                    evidence_signals=["include_variable_unvalidated=true"],
                )
            )
        return findings
