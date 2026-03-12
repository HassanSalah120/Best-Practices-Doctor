"""
Unsafe Eval Rule

Detects eval-like code execution patterns:
- eval()
- assert() with a string argument
- preg_replace() with the deprecated /e modifier

These are high-risk patterns and should be avoided in production code.
"""

from __future__ import annotations

import re

from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule

from ._parse_utils import extract_paren_content, split_top_level_args, is_simple_string_literal


_EVAL = re.compile(r"\beval\s*\(", re.IGNORECASE)
_ASSERT = re.compile(r"\bassert\s*\(", re.IGNORECASE)
_PREG_REPLACE = re.compile(r"\bpreg_replace\s*\(", re.IGNORECASE)


def _has_e_modifier(pat: str) -> bool:
    """Best-effort detection for `/e`-style modifiers inside a regex pattern literal."""
    s = (pat or "").strip()
    if not s:
        return False
    delim = s[0]
    last = s.rfind(delim)
    if last <= 0 or last >= len(s) - 1:
        return False
    mods = s[last + 1 :]
    return "e" in mods


class UnsafeEvalRule(Rule):
    id = "unsafe-eval"
    name = "Unsafe code execution (eval/assert/preg_replace /e)"
    description = "Detects eval/assert(string)/preg_replace(/e) which can lead to code execution"
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
            hits: list[str] = []

            for cs in m.call_sites or []:
                call = str(cs)
                if _EVAL.search(call):
                    hits.append("eval(...)")
                    continue

                am = _ASSERT.search(call)
                if am:
                    inside = extract_paren_content(call, am.end() - 1)
                    args = split_top_level_args(inside or "")
                    if args and is_simple_string_literal(args[0]):
                        hits.append("assert(<string>)")
                        continue

                pm = _PREG_REPLACE.search(call)
                if pm:
                    inside = extract_paren_content(call, pm.end() - 1)
                    args = split_top_level_args(inside or "")
                    if args and is_simple_string_literal(args[0]):
                        pat = args[0].strip()[1:-1]  # drop quotes (best-effort)
                        if _has_e_modifier(pat):
                            hits.append("preg_replace(/.../e, ...)")
                            continue

            if not hits:
                continue

            # De-dupe and keep description stable.
            uniq = []
            seen = set()
            for h in hits:
                if h in seen:
                    continue
                seen.add(h)
                uniq.append(h)

            findings.append(
                self.create_finding(
                    title="Unsafe code execution detected",
                    context=m.method_fqn,
                    file=m.file_path,
                    line_start=m.line_start or 1,
                    line_end=m.line_end or None,
                    description=(
                        f"Method `{m.method_fqn}` contains eval-like code execution patterns: "
                        + ", ".join(uniq)
                        + "."
                    ),
                    why_it_matters=(
                        "These patterns can lead to remote code execution (RCE) if user-controlled input reaches them. "
                        "They are difficult to audit and frequently exploited."
                    ),
                    suggested_fix=(
                        "1. Remove `eval()` and avoid asserting string expressions\n"
                        "2. Replace `preg_replace(.../e...)` with `preg_replace_callback()`\n"
                        "3. If dynamic behavior is required, implement explicit whitelists and safe parsers\n"
                        "4. Add tests covering malicious input cases"
                    ),
                    tags=["security", "rce", "eval"],
                    confidence=0.85,
                )
            )

        return findings

