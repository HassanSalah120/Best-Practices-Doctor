from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class EloquentRawWhereStringRule(Rule):
    id = "eloquent-raw-where-string"
    name = "Eloquent Raw Where String"
    description = "Detects Eloquent where() calls that build SQL predicates inside the first string argument"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = (
        "Use separate arguments in where(): ->where('column', $value) instead of building the condition as a "
        "string. Laravel handles binding safely."
    )
    examples = {
        "bad": "User::where('status = ' . $status)->get();",
        "good": "User::where('status', $status)->get();",
    }
    priority = 1
    group = "Injection Risks"
    applies_to = ["controller", "service", "model"]
    references = ["OWASP A03:2021 - Injection", "CWE-89"]
    related_rules = ["raw-sql", "sql-injection-risk"]
    false_positive_notes = "Does not inspect whereRaw(), which is covered by raw SQL rules. Review custom query macros manually."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "eloquent-where-binding"}

    _OPERATOR = re.compile(r"(?:!=|<>|>=|<=|=|>|<|\blike\b)", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in re.finditer(r"->where\s*\(", content or "", re.IGNORECASE):
            call = self._call_text(content, match.start())
            if not call:
                continue
            first_arg = self._first_arg(call)
            if not first_arg or not self._is_unsafe_first_arg(first_arg, call):
                continue
            line = (content or "").count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="where() builds a raw SQL predicate string",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:{line}",
                    description="The first where() argument appears to contain a SQL predicate rather than a column name.",
                    why_it_matters="Building SQL conditions as strings can bypass parameter binding and create injection risk.",
                    suggested_fix=self.fix_suggestion,
                    confidence=0.9,
                    tags=["laravel", "sql", "injection"],
                    evidence_signals=["eloquent_where=true", "predicate_in_first_argument=true"],
                ),
            )
        return findings

    def _call_text(self, content: str, start: int) -> str:
        depth = 0
        for idx in range(start, len(content)):
            ch = content[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return content[start : idx + 1]
        return content[start:]

    def _first_arg(self, call: str) -> str:
        inside = call[call.find("(") + 1 : call.rfind(")")]
        quote: str | None = None
        depth = 0
        for idx, ch in enumerate(inside):
            if quote:
                if ch == quote and (idx == 0 or inside[idx - 1] != "\\"):
                    quote = None
                continue
            if ch in {"'", '"'}:
                quote = ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)
            elif ch == "," and depth == 0:
                return inside[:idx].strip()
        return inside.strip()

    def _is_unsafe_first_arg(self, first_arg: str, call: str) -> bool:
        if not (first_arg.startswith("'") or first_arg.startswith('"')):
            return False
        literal = first_arg.strip()
        quote = literal[0]
        end = literal.find(quote, 1)
        while end > 0 and literal[end - 1] == "\\":
            end = literal.find(quote, end + 1)
        literal_text = literal[1:end] if end > 0 else literal[1:]
        has_operator = bool(self._OPERATOR.search(literal_text))
        has_interpolation = quote == '"' and "$" in literal_text
        has_concat = "." in call[call.find("(") : call.find(")") if ")" in call else len(call)]
        return has_operator or has_interpolation or (has_concat and "$" in call)
