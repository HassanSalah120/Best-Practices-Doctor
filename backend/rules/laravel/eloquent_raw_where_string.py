"""Detect dynamic raw SQL expressions passed through Eloquent ``where()``."""

from __future__ import annotations

import re

from rules.base import Rule
from rules.php.php_tree_sitter import PhpTreeSitterHelper
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class EloquentRawWhereStringRule(Rule):
    """Report only expressions that can actually bypass query binding.

    A normal ``where('column', $value)`` call never executes its first string as
    raw SQL. Even malformed strings such as ``where('status = '.$status)`` are
    not SQL-injection sinks. This rule therefore requires an explicit raw SQL
    expression (``DB::raw``/``Expression``) whose contents are dynamic.
    """

    id = "eloquent-raw-where-string"
    name = "Dynamic Raw Expression in Eloquent Where"
    description = "Detects dynamic DB::raw/Expression values passed to Eloquent where()"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = (
        "Keep column names/operators static and pass values through normal where() arguments. "
        "For unavoidable raw fragments, use a static expression plus explicit bindings."
    )
    examples = {
        "bad": "User::where(DB::raw($request->input('predicate')))->get();",
        "good": "User::where('status', $request->string('status'))->get();",
    }
    priority = 1
    group = "Injection Risks"
    applies_to = ["controller", "service", "model", "php-class"]
    references = ["OWASP A03:2021 - Injection", "CWE-89"]
    related_rules = ["raw-sql", "sql-injection-risk"]
    false_positive_notes = (
        "Static DB::raw expressions are not reported here. Other raw-query rules may still review them."
    )
    detection_type = "ast"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "eloquent-where-binding"}

    _RAW_CALL = re.compile(
        r"^(?:\\?[A-Za-z_][A-Za-z0-9_]*\\)*(?:DB|Database)::raw\s*\(",
        re.IGNORECASE,
    )
    _NEW_EXPRESSION = re.compile(
        r"^new\s+(?:\\?[A-Za-z_][A-Za-z0-9_]*\\)*Expression\s*\(",
        re.IGNORECASE,
    )
    _DYNAMIC_INPUT = re.compile(
        r"\$[A-Za-z_][A-Za-z0-9_]*|\$_(?:GET|POST|REQUEST)|\b(?:request|input|query)\s*\(",
        re.IGNORECASE,
    )

    def __init__(self, config=None):
        super().__init__(config)
        self._php = PhpTreeSitterHelper()

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        tree = self._php.parse_tree(content or "")
        if tree is None:
            # Security findings must fail closed on evidence quality: without a
            # syntax tree we cannot distinguish executable calls from examples.
            return []

        source = (content or "").encode("utf-8")
        raw_assignments: dict[str, tuple[str, int]] = {}

        for node in self._php.walk(tree.root_node):
            if node.type != "assignment_expression":
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None or left.type != "variable_name":
                continue
            right_text = self._text(right, source).strip()
            if self._is_dynamic_raw_expression(right_text):
                raw_assignments[self._text(left, source).strip()] = (
                    right_text,
                    int(getattr(node.start_point, "row", 0)) + 1,
                )

        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        for node in self._php.walk(tree.root_node):
            if len(findings) >= max_findings or node.type != "member_call_expression":
                continue
            name = node.child_by_field_name("name") or node.child_by_field_name("property")
            if name is None or self._text(name, source).strip().lower() != "where":
                continue
            first_expression = self._first_argument_expression(node)
            if first_expression is None:
                continue
            first_text = self._text(first_expression, source).strip()
            raw_text = ""
            origin_line = int(getattr(node.start_point, "row", 0)) + 1
            if self._is_dynamic_raw_expression(first_text):
                raw_text = first_text
            elif first_expression.type == "variable_name" and first_text in raw_assignments:
                raw_text, origin_line = raw_assignments[first_text]
            if not raw_text:
                continue

            line = int(getattr(node.start_point, "row", 0)) + 1
            findings.append(
                self.create_finding(
                    title="Dynamic raw SQL expression passed to where()",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:{line}",
                    description=(
                        "Eloquent where() receives a DB::raw/Expression value containing dynamic data. "
                        "That raw fragment is outside Laravel's normal value binding."
                    ),
                    why_it_matters=(
                        "Dynamic SQL syntax or values inside a raw expression can change query semantics and create injection risk."
                    ),
                    suggested_fix=self.fix_suggestion,
                    confidence=0.97,
                    tags=["laravel", "sql", "injection", "ast"],
                    evidence_signals=[
                        "eloquent_where=true",
                        "explicit_raw_expression=true",
                        "dynamic_raw_content=true",
                        f"raw_origin_line={origin_line}",
                        f"raw_expression={raw_text[:120]}",
                    ],
                ),
            )
        return findings

    def _first_argument_expression(self, call_node):
        arguments = next(
            (child for child in getattr(call_node, "children", []) or [] if child.type == "arguments"),
            None,
        )
        if arguments is None:
            return None
        first_argument = next(
            (child for child in getattr(arguments, "children", []) or [] if child.type == "argument"),
            None,
        )
        if first_argument is None:
            return None
        return next(
            (child for child in getattr(first_argument, "children", []) or [] if getattr(child, "is_named", False)),
            None,
        )

    def _is_dynamic_raw_expression(self, expression: str) -> bool:
        text = str(expression or "").strip()
        if not (self._RAW_CALL.search(text) or self._NEW_EXPRESSION.search(text)):
            return False
        open_paren = text.find("(")
        if open_paren >= 0 and ")" in text:
            inner = text[open_paren + 1 : text.rfind(")")]
        else:
            inner = text
        return bool(self._DYNAMIC_INPUT.search(inner))

    @staticmethod
    def _text(node, source: bytes) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
