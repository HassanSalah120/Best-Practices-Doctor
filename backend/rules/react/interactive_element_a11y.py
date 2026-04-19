"""
React Interactive Element A11y Rule (AST-first).

Detects non-semantic clickable elements that are missing keyboard operability
contracts (role, keyboard handlers, tabIndex).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule
from rules.react.jsx_tree_sitter import JsxTreeSitterHelper


class InteractiveElementA11yRule(Rule):
    id = "interactive-element-a11y"
    name = "Interactive Element Accessibility"
    description = "Detects non-semantic clickable elements missing role/keyboard contracts"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "ast"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _NON_SEMANTIC_TAGS = {"div", "span", "li", "p", "section", "article"}
    _ALLOWLIST_PATH_MARKERS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/demo/",
        "/demos/",
        "/fixtures/",
        "/generated/",
        "/dist/",
        "/build/",
    )

    def __init__(self, config):
        super().__init__(config)
        self._jsx = JsxTreeSitterHelper()

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
        if self._is_allowlisted_path(file_path):
            return []
        if not self._jsx.is_ready():
            return []
        if "onClick" not in (content or ""):
            return []

        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []

        findings: list[Finding] = []
        content_bytes = (content or "").encode("utf-8")
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 4)))

        for node in self._jsx.iter_jsx_elements(tree.root_node):
            if len(findings) >= max_findings:
                break

            opening = self._jsx.get_opening_node(node)
            tag = self._jsx.get_tag_name(opening, content_bytes).strip()
            if not tag or tag.lower() not in self._NON_SEMANTIC_TAGS:
                continue

            attrs = self._jsx.get_attributes(opening, content_bytes)
            attrs_by_name = {a.name: a for a in attrs}
            if "onClick" not in attrs_by_name:
                continue
            if self._has_true_attr(attrs_by_name, "aria-hidden") or self._has_attr(attrs_by_name, "disabled"):
                continue

            has_role = self._has_attr(attrs_by_name, "role")
            has_tabindex = self._has_attr(attrs_by_name, "tabIndex")
            has_keyboard = any(k in attrs_by_name for k in ("onKeyDown", "onKeyUp", "onKeyPress"))
            has_accessible_name = (
                self._has_attr(attrs_by_name, "aria-label")
                or self._has_attr(attrs_by_name, "aria-labelledby")
                or self._has_visible_text_label(node, content_bytes)
            )

            # Keep this rule focused on keyboard operability; name-only issues are handled by a dedicated rule.
            missing_keyboard_contract = []
            if not has_role:
                missing_keyboard_contract.append("role")
            if not has_keyboard:
                missing_keyboard_contract.append("keyboard handler")
            if not has_tabindex:
                missing_keyboard_contract.append("tabIndex")

            if not missing_keyboard_contract:
                continue
            if len(missing_keyboard_contract) == 1 and has_accessible_name:
                continue

            line = node.start_point.row + 1
            pointer_only = not has_keyboard
            confidence = 0.9 if len(missing_keyboard_contract) >= 2 else 0.82

            evidence = [
                f"tag={tag.lower()}",
                "onclick_present=true",
                f"keyboard_contract_missing={','.join(missing_keyboard_contract)}",
                f"accessible_name_source={'present' if has_accessible_name else 'missing'}",
                f"interaction_mode={'pointer_only' if pointer_only else 'keyboard_supported'}",
            ]

            findings.append(
                self.create_finding(
                    title="Clickable non-semantic element lacks keyboard accessibility contract",
                    context=f"{file_path}:{line}:clickable-non-semantic",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Detected non-semantic clickable element missing required keyboard operability "
                        f"signals: {', '.join(missing_keyboard_contract)}."
                    ),
                    why_it_matters=(
                        "WCAG/APG requires keyboard users to operate interactive controls, and pointer-only "
                        "interaction patterns block assistive technology users."
                    ),
                    suggested_fix=(
                        "Prefer semantic controls (`<button>` or `<a>`). If a non-semantic element is necessary, "
                        "add role, keyboard handlers, and tabIndex consistently."
                    ),
                    tags=["react", "a11y", "keyboard", "wcag", "apg"],
                    confidence=confidence,
                    evidence_signals=evidence,
                    metadata={
                        "decision_profile": {
                            "widget_type": "non_semantic_clickable",
                            "keyboard_contract_missing": ",".join(missing_keyboard_contract),
                            "accessible_name_source": "present" if has_accessible_name else "missing",
                            "interaction_mode": "pointer_only" if pointer_only else "keyboard_supported",
                        }
                    },
                )
            )

        return findings

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        # Backward-compatible alias for older tests/callers that still invoke analyze_regex directly.
        return self.analyze_ast(file_path, content, facts, metrics)

    def _has_attr(self, attrs_by_name: dict[str, object], key: str) -> bool:
        return key in attrs_by_name

    def _has_true_attr(self, attrs_by_name: dict[str, object], key: str) -> bool:
        attr = attrs_by_name.get(key)
        if attr is None:
            return False
        raw = str(getattr(attr, "raw_value", "") or "").strip().lower()
        static = getattr(attr, "static_value", None)
        if raw in {'"true"', "'true'", "{true}"}:
            return True
        if isinstance(static, str) and static.lower() == "true":
            return True
        return False

    def _has_visible_text_label(self, jsx_node, content_bytes: bytes) -> bool:
        if jsx_node.type != "jsx_element":
            return False
        for child in getattr(jsx_node, "children", []) or []:
            if child.type == "jsx_text":
                txt = content_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="replace")
                if re.search(r"[A-Za-z0-9]", txt or ""):
                    return True
        return False

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATH_MARKERS)
