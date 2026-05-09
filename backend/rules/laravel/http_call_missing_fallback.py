"""HTTP call missing fallback rule."""

from __future__ import annotations

from typing import Iterable

import tree_sitter
import tree_sitter_php

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class HttpCallMissingFallbackRule(Rule):
    id = "http-call-missing-fallback"
    name = "HTTP Call Missing Fallback"
    description = "Detects Laravel HTTP client calls that are not wrapped or checked before use"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    type = "ast"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = (
        "Wrap outbound Http calls in try/catch or assign the response and check ok(), successful(), failed(), "
        "status(), null coalescing, or an explicit branch before depending on the remote service."
    )
    examples = {
        "bad": "Http::post($url, $payload);",
        "good": "$response = Http::timeout(5)->post($url, $payload); if ($response->successful()) { ... }",
    }
    priority = 1
    group = "Architecture Integrity"
    applies_to = ["controller", "service", "job"]
    references = ["Laravel HTTP Client", "AWS Builders Library - timeouts, retries, and backoff"]
    related_rules = ["missing-circuit-breaker", "job-http-call-missing-timeout"]
    false_positive_notes = "May be a false positive when fallback behavior is handled in a wrapper not visible to this rule."
    detection_type = "ast"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "http-fallback"}

    _HTTP_METHODS = {"get", "post", "put", "patch", "delete", "send"}
    _RESPONSE_GUARDS = {"ok", "successful", "failed", "status"}

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

        for call in self._find_nodes(root, {"scoped_call_expression", "member_call_expression"}):
            if not self._is_target_http_call(call, source):
                continue
            if self._is_inside_type(call, "try_statement"):
                continue

            assignment = self._enclosing_assignment(call)
            if assignment is None:
                location = (call.start_point.row, call.start_point.column)
                if location not in seen_locations:
                    findings.append(self._finding(file_path, call.start_point.row + 1))
                    seen_locations.add(location)
                continue

            variable = self._assignment_variable(assignment, source)
            method = self._enclosing_node(call, "method_declaration")
            scope = method or root
            if variable and self._has_response_guard(variable, assignment, scope, source):
                continue

            location = (call.start_point.row, call.start_point.column)
            if location not in seen_locations:
                findings.append(self._finding(file_path, call.start_point.row + 1))
                seen_locations.add(location)

        return findings

    def _parse(self, source: bytes) -> tree_sitter.Tree:
        parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_php.language_php()))
        return parser.parse(source)

    def _finding(self, file_path: str, line: int) -> Finding:
        return self.create_finding(
            title="HTTP call lacks fallback or response guard",
            file=file_path,
            line_start=line,
            context=f"{file_path}:{line}",
            description="This outbound Laravel HTTP call is not wrapped in try/catch and its response is not guarded.",
            why_it_matters=(
                "Remote services fail, time out, and return partial errors. Unguarded calls can cascade provider "
                "outages into request failures or lost background work."
            ),
            suggested_fix=self.fix_suggestion,
            confidence=0.88,
            tags=["laravel", "http", "fallback", "distributed-systems"],
            evidence_signals=["http_call=true", "try_catch=false", "response_guard=false"],
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
                return self._text(child, source).lower()
        return ""

    def _is_target_http_call(self, node: tree_sitter.Node, source: bytes) -> bool:
        method_name = self._method_name(node, source)
        if method_name not in self._HTTP_METHODS:
            return False
        text = self._text(node, source)
        if "Http::fake" in text:
            return False
        return self._chain_contains_http_root(node, source)

    def _chain_contains_http_root(self, node: tree_sitter.Node, source: bytes) -> bool:
        if node.type == "scoped_call_expression":
            return len(node.children) >= 3 and self._text(node.children[0], source) == "Http"
        for child in node.children:
            if child.type in {"scoped_call_expression", "member_call_expression"} and self._chain_contains_http_root(
                child, source
            ):
                return True
        return False

    def _is_inside_type(self, node: tree_sitter.Node, node_type: str) -> bool:
        current = node.parent
        while current is not None:
            if current.type == node_type:
                return True
            current = current.parent
        return False

    def _enclosing_node(self, node: tree_sitter.Node, node_type: str) -> tree_sitter.Node | None:
        current = node.parent
        while current is not None:
            if current.type == node_type:
                return current
            current = current.parent
        return None

    def _enclosing_assignment(self, node: tree_sitter.Node) -> tree_sitter.Node | None:
        current = node.parent
        while current is not None:
            if current.type == "assignment_expression":
                return current
            if current.type in {"expression_statement", "return_statement", "if_statement", "method_declaration"}:
                return None
            current = current.parent
        return None

    def _assignment_variable(self, assignment: tree_sitter.Node, source: bytes) -> str | None:
        if not assignment.children:
            return None
        left = assignment.children[0]
        if left.type != "variable_name":
            return None
        return self._text(left, source)

    def _has_response_guard(
        self,
        variable: str,
        assignment: tree_sitter.Node,
        scope: tree_sitter.Node,
        source: bytes,
    ) -> bool:
        for node in self._find_nodes(scope, {"member_call_expression", "if_statement", "binary_expression"}):
            if node.start_byte <= assignment.end_byte:
                continue
            text = self._text(node, source)
            if variable not in text:
                continue
            if node.type == "member_call_expression":
                receiver = node.children[0] if node.children else None
                if receiver is not None and self._text(receiver, source) == variable:
                    if self._method_name(node, source) in self._RESPONSE_GUARDS:
                        return True
            elif node.type == "if_statement":
                condition = node.children[1] if len(node.children) > 1 else node
                if variable in self._text(condition, source):
                    return True
            elif node.type == "binary_expression" and "??" in text:
                return True
        return False
