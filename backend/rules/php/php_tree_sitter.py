"""
Shared Tree-sitter PHP utilities for Laravel/PHP rules.
"""
from __future__ import annotations

import re

try:
    import tree_sitter_php as tsphp
    from tree_sitter import Language, Parser

    TREE_SITTER_READY = True
except Exception:
    Language = None
    Parser = None
    TREE_SITTER_READY = False


class PhpTreeSitterHelper:
    def __init__(self) -> None:
        self._parser: Parser | None = None
        if TREE_SITTER_READY:
            try:
                self._parser = Parser(Language(tsphp.language_php()))
            except Exception:
                self._parser = None

    def is_ready(self) -> bool:
        return self._parser is not None

    def parse_tree(self, content: str):
        if not self._parser:
            return None
        try:
            return self._parser.parse((content or "").encode("utf-8"))
        except Exception:
            return None

    def walk(self, node):
        yield node
        for child in getattr(node, "children", []) or []:
            yield from self.walk(child)

    def find_function_calls(self, root, function_names: set[str], content_bytes: bytes) -> list[dict]:
        """Find all calls to the given bare function names (e.g. unserialize, json_encode).

        Returns list of dicts with keys: name, line, source.
        """
        results: list[dict] = []
        for node in self.walk(root):
            if node.type != "function_call_expression":
                continue
            name_node = node.child_by_field_name("function")
            if not name_node:
                continue
            name = content_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
            if name in function_names:
                line = (node.start_point.row if hasattr(node, "start_point") else 0) + 1
                source = content_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                results.append({"name": name, "line": line, "source": source, "start_byte": node.start_byte, "end_byte": node.end_byte})
        return results

    def find_method_calls(self, root, methods: set[str], content_bytes: bytes) -> list[dict]:
        """Find calls matching method patterns like $var->method(), Class::method().

        methods is a set of call patterns to match against (e.g. "mail::send", "->send").
        For scoped calls (Class::method), matches the full "scope::name".
        For member calls ($obj->method), matches "->method" as a suffix of the call name.
        Patterns are matched case-insensitively.
        """
        def _match_name(node) -> str | None:
            if node.type == "scoped_call_expression":
                scope = node.child_by_field_name("scope")
                name = node.child_by_field_name("name")
                if scope and name:
                    s = content_bytes[scope.start_byte:scope.end_byte].decode("utf-8", errors="replace")
                    n = content_bytes[name.start_byte:name.end_byte].decode("utf-8", errors="replace")
                    return f"{s}::{n}"
            if node.type == "member_call_expression":
                prop = node.child_by_field_name("name") or node.child_by_field_name("property")
                if prop:
                    n = content_bytes[prop.start_byte:prop.end_byte].decode("utf-8", errors="replace")
                    return f"->{n}"
            if node.type == "function_call_expression":
                fn = node.child_by_field_name("function")
                if fn:
                    return content_bytes[fn.start_byte:fn.end_byte].decode("utf-8", errors="replace")
            return None

        results: list[dict] = []
        for node in self.walk(root):
            if node.type not in ("function_call_expression", "scoped_call_expression", "member_call_expression"):
                continue
            name = _match_name(node)
            if not name:
                continue
            low_name = name.lower()
            for method in methods:
                low_method = method.lower()
                if low_method == low_name or low_name.endswith(low_method):
                    source = content_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                    line = (node.start_point.row if hasattr(node, "start_point") else 0) + 1
                    results.append({"name": method, "line": line, "source": source, "start_byte": node.start_byte, "end_byte": node.end_byte})
                    break
        return results

    def has_declare_strict_types(self, root, content_bytes: bytes) -> bool:
        """Check if the file has declare(strict_types=1) at the top level.

        Checks both AST node types (declare_directive, declare_statement)
        and falls back to regex for robustness across grammar versions.
        """
        content = content_bytes.decode("utf-8", errors="replace")
        # First pass: walk AST for known node type patterns
        for node in self.walk(root):
            # Some grammar versions: expression_statement > declare_directive
            if node.type == "expression_statement":
                child = node.child(0)
                if child and child.type == "declare_directive":
                    text = content_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                    if "strict_types" in text and "=1" in text:
                        return True
            # Other grammar versions: declare_statement directly
            if node.type == "declare_statement":
                text = content_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                if "strict_types" in text and "=1" in text:
                    return True
            # grammar variant: expression_statement > declare_statement
            if node.type == "expression_statement":
                child = node.child(0)
                if child and child.type == "declare_statement":
                    text = content_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                    if "strict_types" in text and "=1" in text:
                        return True
        # Fallback: regex for Tree-sitter grammar versions that don't parse declare
        if re.search(r"declare\s*\(\s*strict_types\s*=\s*1\s*\)", content):
            return True
        return False

    def get_call_arguments(self, call_node, content_bytes: bytes) -> str:
        """Extract the arguments portion of a call expression (without parens).

        Works for function_call_expression, scoped_call_expression, member_call_expression.
        """
        if not call_node:
            return ""
        for child in getattr(call_node, "children", []) or []:
            if child.type == "arguments":
                inner = content_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                inner = inner.strip()
                if inner.startswith("(") and inner.endswith(")"):
                    inner = inner[1:-1].strip()
                return inner
        return ""

    def find_all_calls(self, root, patterns: set[str], content_bytes: bytes) -> list[dict]:
        """Find all calls (function + method) matching any of the given patterns.

        Patterns are matched case-insensitively as substrings in the call source.
        Returns list of dicts with keys: name, line, source, arguments.
        """
        results: list[dict] = []
        for node in self.walk(root):
            if node.type not in ("function_call_expression", "scoped_call_expression", "member_call_expression"):
                continue
            source = content_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            lowered = source.lower()
            for pattern in patterns:
                if pattern.lower() in lowered:
                    line = (node.start_point.row if hasattr(node, "start_point") else 0) + 1
                    args = self.get_call_arguments(node, content_bytes)
                    results.append({"name": pattern, "line": line, "source": source, "arguments": args, "start_byte": node.start_byte, "end_byte": node.end_byte})
                    break
        return results
