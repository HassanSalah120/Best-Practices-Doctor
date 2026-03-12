"""
Command Injection Risk Rule

Detects shell execution functions with non-literal arguments (potentially user-controlled).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule

from ._parse_utils import extract_paren_content, split_top_level_args, is_simple_string_literal, string_literal_is_interpolated


_CMD_FUNCS = re.compile(r"\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\(", re.IGNORECASE)
_REQUESTISH = re.compile(r"(\$request\b|request\s*\(|\$_(get|post|request)\b)", re.IGNORECASE)


def _is_non_literal_arg(arg: str) -> bool:
    a = (arg or "").strip()
    if not a:
        return True
    if is_simple_string_literal(a) and not string_literal_is_interpolated(a):
        return False
    # Concatenation or variables are treated as non-literal.
    if "$" in a or "." in a:
        return True
    # Anything else (function call, etc.) => non-literal.
    return True


class CommandInjectionRiskRule(Rule):
    id = "command-injection-risk"
    name = "Command injection risk"
    description = "Detects shell execution functions called with non-literal arguments"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types: list[str] = []  # all

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for m in facts.methods:
            funcs: set[str] = set()
            req_hits = 0

            for cs in m.call_sites or []:
                call = str(cs)
                mm = _CMD_FUNCS.search(call)
                if not mm:
                    continue

                inside = extract_paren_content(call, mm.end() - 1) or ""
                args = split_top_level_args(inside)
                if not args:
                    continue

                first = args[0]
                if not _is_non_literal_arg(first):
                    # Literal command; still potentially dangerous, but not "injection risk" per our heuristic.
                    continue

                funcs.add(mm.group(1).lower())
                if _REQUESTISH.search(first):
                    req_hits += 1

            if not funcs:
                continue

            conf = 0.85 if req_hits else 0.7
            extra = " (request input detected)" if req_hits else ""
            funcs_list = ", ".join(sorted(funcs))

            findings.append(
                self.create_finding(
                    title="Potential command injection risk",
                    context=m.method_fqn,
                    file=m.file_path,
                    line_start=m.line_start or 1,
                    line_end=m.line_end or None,
                    description=(
                        f"Method `{m.method_fqn}` calls shell execution functions with non-literal input: {funcs_list}"
                        + extra
                        + "."
                    ),
                    why_it_matters=(
                        "Passing untrusted input to shell execution can lead to command injection, allowing attackers "
                        "to execute arbitrary commands on the server."
                    ),
                    suggested_fix=(
                        "1. Avoid shell execution when possible (use native PHP APIs)\n"
                        "2. If required, use strict allowlists and avoid passing raw user input\n"
                        "3. Use escapeshellarg/escapeshellcmd carefully (still prefer allowlists)\n"
                        "4. Add tests for malicious input (e.g., `; rm -rf /` style payloads)"
                    ),
                    tags=["security", "command_injection", "rce"],
                    confidence=conf,
                )
            )

        return findings

