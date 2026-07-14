"""Cache missing fallback rule."""

from __future__ import annotations

from collections.abc import Iterable

import tree_sitter
import tree_sitter_php

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class CacheMissingFallbackRule(Rule):
    id = "cache-missing-fallback"
    name = "Cache Missing Fallback"
    description = "Detects Cache::get calls whose nullable result is dereferenced without a fallback"
    category = Category.RELIABILITY
    default_severity = Severity.HIGH
    type = "ast"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = (
        "Provide a default value to Cache::get(), use Cache::remember(), or guard the nullable cache result with "
        "??, isset(), empty(), or an explicit null check before dereferencing it."
    )
    examples = {
        "bad": "$user = Cache::get('user'); return $user['name'];",
        "good": "$user = Cache::get('user') ?? []; return $user['name'] ?? null;",
    }
    priority = 1
    group = "Caching"
    applies_to = ["controller", "service", "job"]
    references = ["Laravel Cache"]
    related_rules = ["cache-stampede-risk", "missing-cache-for-reference-data"]
    false_positive_notes = "May be a false positive when the cache key is guaranteed warm by infrastructure or bootstrap code."
    detection_type = "ast"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "performance", "concern": "cache-fallback"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if not content or not file_path.endswith(".php"):
            return []

        source = content.encode("utf-8", errors="ignore")
        tree = self._parse(source)
        root = tree.root_node
        findings: list[Finding] = []
        seen_locations: set[tuple[int, int]] = set()

        for call in self._find_nodes(root, {"scoped_call_expression"}):
            if not self._is_cache_get_without_default(call, source):
                continue
            if self._has_null_coalescing_ancestor(call, source):
                continue

            assignment = self._enclosing_assignment(call)
            if assignment is None:
                report_node = self._direct_unsafe_usage(call) or call
                location = (report_node.start_point.row, report_node.start_point.column)
                if location not in seen_locations:
                    findings.append(self._finding(file_path, report_node.start_point.row + 1))
                    seen_locations.add(location)
                continue

            variable = self._assignment_variable(assignment, source)
            if not variable:
                continue
            method = self._enclosing_node(call, "method_declaration")
            scope = method or root
            if self._has_cache_guard(variable, assignment, scope, source):
                continue
            unsafe_usage = self._first_unsafe_usage(variable, assignment, scope, source)
            if unsafe_usage is None:
                continue

            location = (unsafe_usage.start_point.row, unsafe_usage.start_point.column)
            if location not in seen_locations:
                findings.append(self._finding(file_path, unsafe_usage.start_point.row + 1))
                seen_locations.add(location)

        return findings

    def _parse(self, source: bytes) -> tree_sitter.Tree:
        language = tree_sitter.Language(tree_sitter_php.language_php())
        parser = tree_sitter.Parser(language)
        return parser.parse(source)

    def _finding(self, file_path: str, line: int) -> Finding:
        return self.create_finding(
            title="Cache value is used without fallback",
            file=file_path,
            line_start=line,
            context=f"{file_path}:{line}",
            description="This Cache::get result can be null and is used without a detected fallback or guard.",
            why_it_matters=(
                "Cache misses, evictions, and cold starts are normal production events. Code that assumes a warm cache "
                "can crash or skip critical fallback behavior."
            ),
            suggested_fix=self.fix_suggestion,
            confidence=0.88,
            tags=["laravel", "cache", "fallback", "distributed-systems"],
            evidence_signals=["cache_get=true", "default_missing=true", "fallback_guard=false"],
        )

    def _find_nodes(self, node: tree_sitter.Node, types: set[str]) -> Iterable[tree_sitter.Node]:
        if node.type in types:
            yield node
        for child in node.children:
            yield from self._find_nodes(child, types)

    def _text(self, node: tree_sitter.Node, source: bytes) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")

    def _method_name(self, node: tree_sitter.Node, source: bytes) -> str:
        for child in reversed(node.children):
            if child.type == "name":
                return self._text(child, source)
        return ""

    def _is_cache_get_without_default(self, node: tree_sitter.Node, source: bytes) -> bool:
        if self._method_name(node, source).lower() != "get":
            return False
        if len(node.children) < 4 or self._text(node.children[0], source) != "Cache":
            return False
        arguments = next((child for child in node.children if child.type == "arguments"), None)
        return arguments is not None and len([child for child in arguments.children if child.type == "argument"]) < 2

    def _has_null_coalescing_ancestor(self, node: tree_sitter.Node, source: bytes) -> bool:
        current = node.parent
        while current is not None:
            if current.type == "binary_expression" and "??" in self._text(current, source):
                return True
            if current.type in {"expression_statement", "assignment_expression", "return_statement", "argument"}:
                return False
            current = current.parent
        return False

    def _enclosing_assignment(self, node: tree_sitter.Node) -> tree_sitter.Node | None:
        current = node.parent
        while current is not None:
            if current.type == "assignment_expression":
                return current
            if current.type in {"expression_statement", "return_statement", "argument", "method_declaration"}:
                return None
            current = current.parent
        return None

    def _enclosing_node(self, node: tree_sitter.Node, node_type: str) -> tree_sitter.Node | None:
        current = node.parent
        while current is not None:
            if current.type == node_type:
                return current
            current = current.parent
        return None

    def _assignment_variable(self, assignment: tree_sitter.Node, source: bytes) -> str | None:
        if not assignment.children:
            return None
        left = assignment.children[0]
        if left.type != "variable_name":
            return None
        return self._text(left, source)

    def _has_cache_guard(
        self,
        variable: str,
        assignment: tree_sitter.Node,
        scope: tree_sitter.Node,
        source: bytes,
    ) -> bool:
        for node in self._find_nodes(scope, {"binary_expression", "if_statement", "function_call_expression"}):
            if node.start_byte <= assignment.end_byte:
                continue
            text = self._text(node, source)
            if variable not in text:
                continue
            if node.type == "binary_expression" and ("??" in text or "null" in text.lower()):
                return True
            if node.type == "if_statement":
                condition = node.children[1] if len(node.children) > 1 else node
                condition_text = self._text(condition, source).lower()
                if "null" in condition_text or "isset" in condition_text or "empty" in condition_text:
                    return True
            if node.type == "function_call_expression" and self._method_name(node, source).lower() in {"isset", "empty"}:
                return True
        return False

    def _first_unsafe_usage(
        self,
        variable: str,
        assignment: tree_sitter.Node,
        scope: tree_sitter.Node,
        source: bytes,
    ) -> tree_sitter.Node | None:
        candidates: list[tree_sitter.Node] = []
        for node in self._find_nodes(scope, {"member_call_expression", "subscript_expression"}):
            if node.start_byte <= assignment.end_byte:
                continue
            if self._is_var_receiver(node, variable, source):
                candidates.append(node)
        return min(candidates, key=lambda item: item.start_byte) if candidates else None

    def _direct_unsafe_usage(self, call: tree_sitter.Node) -> tree_sitter.Node | None:
        current = call.parent
        while current is not None:
            if current.type in {"member_call_expression", "subscript_expression"}:
                return current
            if current.type in {"expression_statement", "return_statement", "argument", "method_declaration"}:
                return None
            current = current.parent
        return None

    def _is_var_receiver(self, node: tree_sitter.Node, variable: str, source: bytes) -> bool:
        if not node.children:
            return False
        receiver = node.children[0]
        return receiver.type == "variable_name" and self._text(receiver, source) == variable
