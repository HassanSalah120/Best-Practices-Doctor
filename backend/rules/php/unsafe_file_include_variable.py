"""
Unsafe include/require variable rule.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


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
    _SAFE_RESOLVER_CALL = re.compile(r"\b(base_path|app_path|resource_path|storage_path)\s*\(", re.IGNORECASE)
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Remove the unsafe file include variable risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'File Security'
    applies_to = ['php-class', 'php-function']
    references = ['OWASP A01:2021 - Broken Access Control', 'CWE-22']
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'php', 'type': 'security', 'concern': 'unsafe-file-include'}

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
            if self._safe_static_path_assignment(var_name, window):
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
                ),
            )
        return findings

    def _safe_static_path_assignment(self, variable_name: str, window: str) -> bool:
        if not variable_name:
            return False
        escaped = re.escape(variable_name)
        direct_dir_assign = re.compile(
            rf"\${escaped}\s*=\s*(?:realpath\(\s*)?__dir__\b",
            re.IGNORECASE,
        )
        if direct_dir_assign.search(window):
            return True
        resolver_assign = re.compile(
            rf"\${escaped}\s*=\s*(?:realpath\(\s*)?(?:base_path|app_path|resource_path|storage_path)\s*\(",
            re.IGNORECASE,
        )
        if resolver_assign.search(window):
            return True
        return bool(self._SAFE_RESOLVER_CALL.search(window) and "__dir__" in window.lower())
