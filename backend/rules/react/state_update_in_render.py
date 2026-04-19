"""
State Update In Render Rule

Flags direct setState-like calls executed in render flow.
"""

from __future__ import annotations

from typing import Iterable

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
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


class StateUpdateInRenderRule(Rule):
    id = "state-update-in-render"
    name = "State Update During Render"
    description = "Detects direct setState-like calls in React render flow"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.DEFECT
    type = "ast"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _EFFECT_CONTAINER_CALLEES = {
        "useEffect",
        "useLayoutEffect",
        "useMemo",
        "useCallback",
        "useMountEffect",
    }
    _FUNCTION_NODE_TYPES = {"function_declaration", "function_expression", "arrow_function", "method_definition"}

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
        normalized_path = (file_path or "").lower().replace("\\", "/")
        if any(marker in normalized_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if "set" not in (content or ""):
            return []

        tree = self._parse_tree(file_path, content)
        if not tree or not getattr(tree, "root_node", None):
            return []

        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        content_bytes = (content or "").encode("utf-8")
        findings: list[Finding] = []

        for node in self._walk(tree.root_node):
            if len(findings) >= max_findings_per_file:
                break
            if node.type != "call_expression":
                continue

            function_node = node.child_by_field_name("function")
            callee_name = self._callee_name(function_node, content_bytes)
            if not self._looks_like_state_setter(callee_name):
                continue
            if self._inside_effect_like_context(node, content_bytes):
                continue

            component_fn, has_nested_function = self._enclosing_component_function(node, content_bytes)
            if component_fn is None:
                continue
            if has_nested_function:
                continue

            line_number = node.start_point.row + 1
            findings.append(
                self.create_finding(
                    title="State update appears in render flow",
                    context=f"{callee_name}() @ line {line_number}",
                    file=file_path,
                    line_start=line_number,
                    description=(
                        f"Detected direct `{callee_name}(...)` during component render. "
                        "State updates should run in event handlers, effects, or transitions, not directly while rendering."
                    ),
                    why_it_matters=(
                        "State updates during render can cause render loops and unstable UI behavior. "
                        "They also make control flow harder to reason about."
                    ),
                    suggested_fix=(
                        "Move this state update to the event that triggers it (click/submit/etc.), "
                        "or to a properly scoped effect when synchronizing with an external system."
                    ),
                    confidence=0.93,
                    tags=["react", "state", "render", "correctness"],
                    evidence_signals=[
                        f"callee={callee_name}",
                        "parser=tree-sitter",
                        "component_context=1",
                        "nested_function=0",
                    ],
                    metadata={
                        "decision_profile": {
                            "callee": callee_name,
                            "component_function": self._function_name(component_fn, content_bytes),
                            "nested_function": False,
                        }
                    },
                )
            )

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
            if obj and prop:
                return f"{self._node_text(obj, content_bytes)}.{self._node_text(prop, content_bytes)}"
        return self._node_text(node, content_bytes)

    def _looks_like_state_setter(self, callee_name: str) -> bool:
        name = str(callee_name or "").strip()
        if "." in name:
            return False
        return name.startswith("set") and len(name) > 3 and name[3:4].isupper()

    def _inside_effect_like_context(self, node, content_bytes: bytes) -> bool:
        current = getattr(node, "parent", None)
        while current is not None:
            if current.type == "call_expression":
                fn = current.child_by_field_name("function")
                callee = self._callee_name(fn, content_bytes)
                if callee in self._EFFECT_CONTAINER_CALLEES:
                    return True
            current = getattr(current, "parent", None)
        return False

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
