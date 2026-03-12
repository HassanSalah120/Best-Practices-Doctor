"""
SQL Injection Risk Rule (Heuristic)

Detects common patterns where raw SQL is built with variables/interpolation/concatenation.

Examples:
- DB::select("... $var ...")
- DB::select('...'.$var)
- ->whereRaw("x = $var")

We intentionally keep this conservative to avoid noise:
- If the query uses placeholders AND has bindings, we do not flag.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule

from ._parse_utils import extract_paren_content, split_top_level_args, string_literal_is_interpolated


_DB_RAW = re.compile(r"\bDB::\s*(select|statement|unprepared|raw)\s*\(", re.IGNORECASE)
_RAW_CHAIN = re.compile(r"(?:->|::)\s*(whereRaw|orWhereRaw|havingRaw|orderByRaw|selectRaw)\s*\(", re.IGNORECASE)
_REQUESTISH = re.compile(r"(\$request\b|request\s*\(|\$_(get|post|request)\b)", re.IGNORECASE)


def _arg_has_concat_or_var(arg: str) -> bool:
    a = (arg or "").strip()
    if not a:
        return False
    if string_literal_is_interpolated(a):
        return True
    if "$" in a:
        return True
    # Simple concatenation heuristic.
    if "." in a and re.search(r"\$\w+", a):
        return True
    if a.startswith("$"):
        return True
    return False


def _arg_has_placeholder(arg: str) -> bool:
    if not arg:
        return False
    # Support '?' placeholders (most common). Named placeholders are out of scope for now.
    return "?" in arg


class SqlInjectionRiskRule(Rule):
    id = "sql-injection-risk"
    name = "SQL injection risk (raw SQL with variables)"
    description = "Detects raw SQL built with variables/interpolation/concatenation"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    applicable_project_types: list[str] = []  # all

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for m in facts.methods:
            risky: list[str] = []
            req_hits = 0

            for cs in m.call_sites or []:
                call = str(cs)

                # DB::select/statement/raw(...) etc
                dm = _DB_RAW.search(call)
                if dm:
                    inside = extract_paren_content(call, dm.end() - 1) or ""
                    args = split_top_level_args(inside)
                    if args:
                        first = args[0]
                        has_bindings = len(args) >= 2

                        if _arg_has_concat_or_var(first):
                            # Parameterized placeholder + bindings => do not flag unless the SQL itself embeds vars.
                            if has_bindings and _arg_has_placeholder(first) and not string_literal_is_interpolated(first) and "." not in first:
                                continue
                            risky.append(f"DB::{dm.group(1).lower()}(...)")
                            if _REQUESTISH.search(inside):
                                req_hits += 1
                    continue

                # ->whereRaw / ::whereRaw
                rm = _RAW_CHAIN.search(call)
                if rm:
                    inside = extract_paren_content(call, rm.end() - 1) or ""
                    args = split_top_level_args(inside)
                    if not args:
                        continue
                    first = args[0]
                    has_bindings = len(args) >= 2

                    if not _arg_has_concat_or_var(first):
                        continue

                    if has_bindings and _arg_has_placeholder(first) and not string_literal_is_interpolated(first) and "." not in first:
                        continue

                    risky.append(f"{rm.group(1)}(...)")
                    if _REQUESTISH.search(inside):
                        req_hits += 1

            if not risky:
                continue

            # Stabilize list ordering.
            uniq = []
            seen = set()
            for r in risky:
                if r in seen:
                    continue
                seen.add(r)
                uniq.append(r)

            conf = 0.75 if req_hits else 0.6
            extra = " (request input detected)" if req_hits else ""

            findings.append(
                self.create_finding(
                    title="Possible SQL injection risk",
                    context=m.method_fqn,
                    file=m.file_path,
                    line_start=m.line_start or 1,
                    line_end=m.line_end or None,
                    description=(
                        f"Method `{m.method_fqn}` appears to build raw SQL with variables/interpolation: "
                        + ", ".join(uniq)
                        + extra
                        + "."
                    ),
                    why_it_matters=(
                        "Interpolating variables into SQL strings can lead to SQL injection. Parameter binding "
                        "prevents attackers from altering query structure."
                    ),
                    suggested_fix=(
                        "1. Use query builder/Eloquent methods instead of raw SQL\n"
                        "2. If raw SQL is required, use placeholders and bindings (e.g., `whereRaw('id = ?', [$id])`)\n"
                        "3. Never concatenate raw user input into SQL strings\n"
                        "4. Add tests for malicious inputs (quotes, comments, UNION patterns)"
                    ),
                    tags=["security", "sql", "injection"],
                    confidence=conf,
                )
            )

        return findings
