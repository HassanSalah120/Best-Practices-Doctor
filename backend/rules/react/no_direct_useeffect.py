"""
No Direct useEffect Rule

Strict-policy React rule that bans calling useEffect directly in components/modules.
Uses Tree-sitter for call detection so wrapper allowances and namespaced calls are
resolved from real JS/TS structure rather than text heuristics.
"""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class _EffectCall:
    start: int
    line: int
    callee: str
    callback_text: str
    dep_arg_text: str


class NoDirectUseEffectRule(Rule):
    id = "no-direct-useeffect"
    name = "Direct useEffect Is Disallowed"
    description = "Flags direct useEffect usage in strict React policy projects"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]
    applicable_project_types = []

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
        if "useEffect" not in (content or ""):
            return []

        low_path = str(file_path or "").lower().replace("\\", "/")
        if any(token in low_path for token in (".test.", ".spec.", "__tests__", ".stories.")):
            return []

        tree = self._parse_tree(file_path, content)
        if not tree or not getattr(tree, "root_node", None):
            return []

        content_bytes = content.encode("utf-8")
        allowed_wrappers = self.get_threshold("allowed_wrapper_names", ["useMountEffect"])
        allowed_names = [str(name or "").strip() for name in allowed_wrappers if str(name or "").strip()]
        suppress_external_sync = bool(self.get_threshold("suppress_external_sync", False))
        allow_mount_only_without_wrapper = bool(self.get_threshold("allow_mount_only_without_wrapper", False))
        wrapper_ranges = self._find_wrapper_ranges(tree.root_node, content_bytes, allowed_names)

        findings: list[Finding] = []
        for call in self._find_effect_calls(tree.root_node, content_bytes):
            is_allowed_wrapper = self._is_inside_allowed_wrapper(call.start, wrapper_ranges)
            if is_allowed_wrapper and call.dep_arg_text == "[]":
                continue

            suggestion, reason = self._suggest_replacement(call.callback_text, call.dep_arg_text)
            if reason == "external-sync" and suppress_external_sync:
                continue
            if reason == "mount-only-sync" and allow_mount_only_without_wrapper:
                continue
            findings.append(
                self.create_finding(
                    title="Direct useEffect call is banned by strict React policy",
                    context=f"{call.callee}@{call.line}",
                    file=file_path,
                    line_start=call.line,
                    description=(
                        f"Detected direct `{call.callee}(...)` usage. In strict mode, side effects should not be orchestrated "
                        "through ad-hoc dependency arrays inside components."
                    ),
                    why_it_matters=(
                        "Direct useEffect tends to hide control flow, create race conditions, and introduce dependency-array bugs. "
                        "Strict mode prefers derived state, event handlers, query libraries, or an explicit mount-only wrapper."
                    ),
                    suggested_fix=suggestion,
                    tags=["react", "useeffect", "strict-policy", "effects"],
                    confidence=0.96,
                    evidence_signals=[
                        "policy=no-direct-useeffect",
                        "parser=tree-sitter",
                        f"callee={call.callee}",
                        f"wrapper_allowed={int(is_allowed_wrapper)}",
                        f"reason={reason}",
                    ],
                    metadata={
                        "decision_profile": {
                            "frontend_policy": "no-direct-useeffect",
                            "decision": "emit",
                            "decision_summary": f"emit because direct {call.callee} is disallowed in strict mode",
                            "allowed_wrapper_names": allowed_names,
                            "suppress_external_sync": suppress_external_sync,
                            "allow_mount_only_without_wrapper": allow_mount_only_without_wrapper,
                            "replacement_reason": reason,
                            "parser": "tree-sitter",
                        }
                    },
                )
            )

        return findings

    def _find_wrapper_ranges(
        self,
        root_node,
        content_bytes: bytes,
        allowed_names: list[str],
    ) -> list[tuple[int, int]]:
        allowed = {name for name in allowed_names if name}
        if not allowed:
            return []

        ranges: list[tuple[int, int]] = []
        for node in self._walk(root_node):
            if node.type == "function_declaration":
                name = self._node_text(node.child_by_field_name("name"), content_bytes)
                if name not in allowed:
                    continue
                body = node.child_by_field_name("body")
                if body:
                    ranges.append((body.start_byte, body.end_byte))
                    continue
                ranges.append((node.start_byte, node.end_byte))
            elif node.type == "variable_declarator":
                name = self._node_text(node.child_by_field_name("name"), content_bytes)
                if name not in allowed:
                    continue
                value = node.child_by_field_name("value")
                if not value or value.type not in {"arrow_function", "function_expression"}:
                    continue
                body = value.child_by_field_name("body")
                if body:
                    ranges.append((body.start_byte, body.end_byte))
                    continue
                ranges.append((value.start_byte, value.end_byte))
        return ranges

    def _find_effect_calls(self, root_node, content_bytes: bytes) -> list[_EffectCall]:
        out: list[_EffectCall] = []
        for node in self._walk(root_node):
            if node.type != "call_expression":
                continue
            function_node = node.child_by_field_name("function")
            callee = self._callee_name(function_node, content_bytes)
            if callee not in {"useEffect", "React.useEffect"}:
                continue

            args_node = node.child_by_field_name("arguments")
            if not args_node:
                continue
            args = list(args_node.named_children)
            callback_text = self._node_text(args[0], content_bytes) if args else ""
            dep_arg_text = self._node_text(args[1], content_bytes).strip() if len(args) >= 2 else ""
            out.append(
                _EffectCall(
                    start=node.start_byte,
                    line=node.start_point.row + 1,
                    callee=callee,
                    callback_text=callback_text,
                    dep_arg_text=dep_arg_text,
                )
            )
        return out

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

    def _is_inside_allowed_wrapper(self, offset: int, ranges: list[tuple[int, int]]) -> bool:
        return any(start <= offset <= end for start, end in ranges)

    def _suggest_replacement(self, callback_text: str, dep_arg: str) -> tuple[str, str]:
        body = str(callback_text or "")
        low = body.lower()
        if any(
            token in low
            for token in (
                "new websocket",
                "addeventlistener(",
                "removeeventlistener(",
                "setinterval(",
                "clearinterval(",
                "settimeout(",
                "cleartimeout(",
                "subscribe(",
                "unsubscribe(",
                "onmessage",
                "onopen",
                "onclose",
            )
        ):
            return (
                "This looks like external-system synchronization. Move it behind the approved lifecycle boundary, "
                "for example `useMountEffect(...)` or a dedicated subscription hook, instead of calling `useEffect` directly.",
                "external-sync",
            )
        if any(token in low for token in ("fetch(", "axios.", "client.get(", "client.post(", "queryclient")):
            return (
                "Move data loading to a query/data-fetching abstraction instead of `useEffect`, "
                "for example `useQuery(...)` or your existing data layer. Let the library handle caching, "
                "cancellation, and stale state.",
                "fetch-in-effect",
            )
        if "set" in body and any(ch.isupper() for ch in body):
            import re

            if re.search(r"\bset[A-Z][A-Za-z0-9_]*\s*\(", body):
                return (
                    "If this state is derived from props/state, compute it during render instead of syncing it in an effect. "
                    "If it represents an action, run that work in the event handler that caused it.",
                    "derived-or-relay-state",
                )
        if dep_arg == "[]":
            return (
                "Replace the direct effect with `useMountEffect(...)` if this is truly a mount/unmount external sync. "
                "Otherwise move the work to a more explicit boundary such as conditional mounting or an event handler.",
                "mount-only-sync",
            )
        return (
            "Replace this direct `useEffect` with one of the preferred patterns: derive values during render, "
            "perform actions in event handlers, use a query library for data fetching, or use `useMountEffect(...)` "
            "for the rare mount-only external synchronization case.",
            "general-effect-ban",
        )

    def _walk(self, node) -> Iterable:
        yield node
        for child in getattr(node, "children", []) or []:
            yield from self._walk(child)

    def _node_text(self, node, content_bytes: bytes) -> str:
        if not node:
            return ""
        return content_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _parse_tree(self, file_path: str, content: str):
        language = self._language_for(file_path)
        parser = self._parsers.get(language)
        if not parser:
            return None
        try:
            return parser.parse(content.encode("utf-8"))
        except Exception:
            return None

    def _language_for(self, file_path: str) -> str:
        low = str(file_path or "").lower()
        if low.endswith(".tsx"):
            return "tsx"
        if low.endswith(".jsx"):
            return "javascript"
        if low.endswith(".ts"):
            return "typescript"
        return "javascript"
