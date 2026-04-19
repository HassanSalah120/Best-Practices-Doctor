"""
React Side Effects In Render Rule

Detects side-effectful operations executed directly in component render flow.
"""

from __future__ import annotations

from typing import Iterable

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

try:
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts
    from tree_sitter import Language, Parser

    _TREE_SITTER_READY = True
except Exception:
    Language = None
    Parser = None
    _TREE_SITTER_READY = False


class ReactSideEffectsInRenderRule(Rule):
    id = "react-side-effects-in-render"
    name = "Side Effects During Render"
    description = "Detects side-effect calls executed directly during React render"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.DEFECT
    type = "ast"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _FUNCTION_NODE_TYPES = {"function_declaration", "function_expression", "arrow_function", "method_definition"}

    _SIDE_EFFECT_CALLEES = {
        "fetch",
        "router.visit",
        "router.reload",
        "router.get",
        "router.post",
        "router.put",
        "router.patch",
        "router.delete",
        "Inertia.visit",
        "Inertia.reload",
        "Inertia.get",
        "Inertia.post",
        "Inertia.put",
        "Inertia.patch",
        "Inertia.delete",
        "window.location.assign",
        "window.location.replace",
        "location.assign",
        "location.replace",
        "localStorage.setItem",
        "localStorage.removeItem",
        "sessionStorage.setItem",
        "sessionStorage.removeItem",
        "navigator.sendBeacon",
    }

    _AXIOS_METHODS = {"get", "post", "put", "patch", "delete", "request"}
    _SIDE_EFFECT_CTORS = {"WebSocket", "EventSource", "BroadcastChannel", "Worker"}

    def __init__(self, config):
        super().__init__(config)
        self._parsers: dict[str, Parser] = {}
        if _TREE_SITTER_READY:
            try:
                self._parsers["javascript"] = Parser(Language(tsjs.language()))
                self._parsers["typescript"] = Parser(Language(tsts.language_typescript()))
                self._parsers["tsx"] = Parser(Language(tsts.language_tsx()))
            except Exception:
                self._parsers = {}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        text = content or ""
        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if not any(token in text for token in ("fetch(", "router.", "Inertia.", "axios.", "WebSocket", "localStorage", "location.")):
            return []

        tree = self._parse_tree(file_path, text)
        if not tree or not getattr(tree, "root_node", None):
            return []

        content_bytes = text.encode("utf-8")
        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for node in self._walk(tree.root_node):
            callee_name = ""
            pattern_name = ""
            if node.type == "call_expression":
                function_node = node.child_by_field_name("function")
                callee_name = self._callee_name(function_node, content_bytes)
                pattern_name = self._side_effect_pattern_for_call(callee_name)
            elif node.type == "new_expression":
                ctor = self._callee_name(node.child_by_field_name("constructor"), content_bytes)
                if ctor in self._SIDE_EFFECT_CTORS:
                    callee_name = f"new {ctor}"
                    pattern_name = f"new-{ctor}"
            if not pattern_name:
                continue

            component_fn, nested_fn = self._enclosing_component_function(node, content_bytes)
            if component_fn is None or nested_fn:
                continue

            line_number = node.start_point.row + 1
            if line_number in seen_lines:
                continue
            seen_lines.add(line_number)

            findings.append(
                self.create_finding(
                    title="Side-effectful operation appears in render flow",
                    context=f"{callee_name}@{line_number}",
                    file=file_path,
                    line_start=line_number,
                    description=(
                        f"Detected `{callee_name}` directly in component render flow."
                    ),
                    why_it_matters=(
                        "Side effects in render can trigger repeated network calls, unstable behavior, and difficult-to-debug rerender loops."
                    ),
                    suggested_fix=(
                        "Move this operation to an explicit lifecycle/event boundary (event handler, approved mount wrapper, "
                        "or data-fetching abstraction) rather than executing during render."
                    ),
                    confidence=0.91,
                    tags=["react", "render", "side-effects", "correctness"],
                    evidence_signals=[
                        f"callee={callee_name}",
                        f"pattern={pattern_name}",
                        "parser=tree-sitter",
                        "nested_function=0",
                    ],
                    metadata={
                        "decision_profile": {
                            "callee": callee_name,
                            "pattern": pattern_name,
                            "nested_function": False,
                        }
                    },
                )
            )
            if len(findings) >= max_findings_per_file:
                break

        return findings

    def _parse_tree(self, file_path: str, content: str):
        parser = self._parsers.get(self._language_for(file_path))
        if not parser:
            return None
        try:
            return parser.parse((content or "").encode("utf-8"))
        except Exception:
            return None

    def _language_for(self, file_path: str) -> str:
        low = str(file_path or "").lower()
        if low.endswith(".tsx"):
            return "tsx"
        if low.endswith(".ts"):
            return "typescript"
        return "javascript"

    def _walk(self, node) -> Iterable:
        yield node
        for child in getattr(node, "children", []) or []:
            yield from self._walk(child)

    def _node_text(self, node, content_bytes: bytes) -> str:
        if not node:
            return ""
        return content_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _callee_name(self, node, content_bytes: bytes) -> str:
        if not node:
            return ""
        if node.type == "identifier":
            return self._node_text(node, content_bytes)
        if node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            left = self._callee_name(obj, content_bytes)
            right = self._node_text(prop, content_bytes)
            return f"{left}.{right}".strip(".")
        return self._node_text(node, content_bytes)

    def _side_effect_pattern_for_call(self, callee_name: str) -> str:
        callee = str(callee_name or "").strip()
        if not callee:
            return ""
        if callee in self._SIDE_EFFECT_CALLEES:
            return callee
        if callee.startswith("axios."):
            method = callee.split(".", 1)[1]
            if method in self._AXIOS_METHODS:
                return f"axios:{method}"
        return ""

    def _enclosing_component_function(self, node, content_bytes: bytes):
        current = getattr(node, "parent", None)
        nested_function_count = 0
        while current is not None:
            if current.type in self._FUNCTION_NODE_TYPES:
                if self._is_component_like_function(current, content_bytes):
                    return current, nested_function_count > 0
                nested_function_count += 1
            current = getattr(current, "parent", None)
        return None, False

    def _is_component_like_function(self, fn_node, content_bytes: bytes) -> bool:
        name = self._function_name(fn_node, content_bytes)
        if name.startswith("use"):
            return False
        if name and name[0].isupper():
            return True
        body = fn_node.child_by_field_name("body")
        body_text = self._node_text(body, content_bytes)
        return "return <" in body_text or ("return (" in body_text and "<" in body_text)

    def _function_name(self, fn_node, content_bytes: bytes) -> str:
        if not fn_node:
            return ""
        if fn_node.type == "function_declaration":
            return self._node_text(fn_node.child_by_field_name("name"), content_bytes)
        if fn_node.type in {"function_expression", "arrow_function"}:
            parent = getattr(fn_node, "parent", None)
            if parent and parent.type == "variable_declarator":
                return self._node_text(parent.child_by_field_name("name"), content_bytes)
            if parent and parent.type == "assignment_expression":
                return self._node_text(parent.child_by_field_name("left"), content_bytes)
        if fn_node.type == "method_definition":
            return self._node_text(fn_node.child_by_field_name("name"), content_bytes)
        return ""
