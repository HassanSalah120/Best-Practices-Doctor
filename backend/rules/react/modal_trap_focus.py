"""
Modal Trap Focus Rule (hardened contract checks).
"""

from __future__ import annotations

from rules.base import Rule
from rules.react.dialog_usage_helpers import tags_are_shared_dialog_consumers
from rules.react.jsx_tree_sitter import JsxTreeSitterHelper
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class ModalTrapFocusRule(Rule):
    id = "modal-trap-focus"
    name = "Modal Focus Trap Missing"
    description = "Detects dialog/modal widgets missing keyboard focus management contracts"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "ast"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
    )

    _DIALOG_TAG_HINTS = ("Dialog", "Modal", "AlertDialog")
    _TRAP_SIGNALS = (
        "FocusTrap",
        "FocusScope",
        "createFocusTrap",
        "useFocusTrap",
        "@headlessui/react",
        "@radix-ui/react-dialog",
        "@radix-ui/react-alert-dialog",
        "DialogContent",
        "AlertDialogContent",
        "onKeyDown",
        # Custom focus trap implementations
        "getFocusableElements",
        "focusableElements",
        "FOCUSABLE_SELECTOR",
        "querySelectorAll",
        "tabIndex",
    )
    _FOCUS_ENTRY_SIGNALS = (
        "autoFocus",
        "initialFocus",
        "initialFocusRef",
        "onOpenAutoFocus",
        ".focus(",
        "first.focus",
        "last.focus",
        "focusable[0]",
    )
    _CLOSE_SIGNALS = (
        "onClose",
        "onOpenChange",
        "onDismiss",
        "Escape",
        "Esc",
        "setOpen(false)",
        'e.key === "Escape"',
        "key === 'Escape'",
    )
    _FOCUS_RESTORE_SIGNALS = (
        "onCloseAutoFocus",
        "returnFocus",
        "restoreFocus",
        "previousActiveElement",
        "triggerRef.current.focus",
        "focusTrigger",
        "previousActiveElement.current",
        "?.focus()",
        ".current?.focus",
    )
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Update the component markup and interaction contract so the modal focus trap missing is accessible by keyboard and assistive technology. Verify the expected ARIA/semantic state in a component test when practical.'
    examples = {}
    priority = 3
    group = 'React Accessibility'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'accessibility', 'concern': 'modal-trap-focus'}

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

        tree = self._jsx.parse_tree(file_path, content or "")
        if not tree or not getattr(tree, "root_node", None):
            return []

        dialog_nodes = self._find_dialog_nodes(tree.root_node, (content or "").encode("utf-8"))
        if not dialog_nodes:
            return []

        text = content or ""
        dialog_tags = self._dialog_tags(dialog_nodes, text.encode("utf-8"))
        if tags_are_shared_dialog_consumers(
            dialog_tags,
            text,
            file_path=file_path,
            project_path=getattr(facts, "project_path", None),
        ):
            return []

        has_trap_signal = any(s in text for s in self._TRAP_SIGNALS)
        has_focus_entry_signal = any(s in text for s in self._FOCUS_ENTRY_SIGNALS)
        has_close_signal = any(s in text for s in self._CLOSE_SIGNALS)
        has_focus_restore_signal = any(s in text for s in self._FOCUS_RESTORE_SIGNALS)

        missing: list[str] = []
        if not has_focus_entry_signal:
            missing.append("focus entry")
        if not has_trap_signal:
            missing.append("focus trap")
        if not has_close_signal:
            missing.append("keyboard close")
        if not has_focus_restore_signal:
            missing.append("focus restore")

        # High-precision: only emit when at least trap or close is missing.
        if has_trap_signal and has_close_signal:
            return []
        if len(missing) < 2:
            return []

        line = min(node.start_point.row + 1 for node in dialog_nodes)
        return [
            self.create_finding(
                title="Dialog widget may miss APG focus management contract",
                context=f"{file_path}:{line}:dialog-contract",
                file=file_path,
                line_start=line,
                description=(
                    "Dialog/modal widget detected with missing focus management signals: "
                    f"{', '.join(missing)}."
                ),
                why_it_matters=(
                    "APG dialog pattern expects focus entry, focus containment, keyboard close, and focus restoration "
                    "to keep keyboard and assistive technology navigation reliable."
                ),
                suggested_fix=(
                    "Use a proven dialog primitive with built-in focus trap/restore, or implement full APG dialog "
                    "keyboard and focus lifecycle contract explicitly."
                ),
                tags=["a11y", "wcag", "apg", "dialog", "keyboard", "focus"],
                confidence=0.86,
                evidence_signals=[
                    "widget_type=dialog",
                    f"missing_apg_signals={','.join(missing)}",
                    f"focus_entry_signal={int(has_focus_entry_signal)}",
                    f"focus_restore_signal={int(has_focus_restore_signal)}",
                    f"keyboard_contract_missing={int(not has_close_signal)}",
                ],
                metadata={
                    "decision_profile": {
                        "widget_type": "dialog",
                        "missing_apg_signals": ",".join(missing),
                        "focus_entry_signal": bool(has_focus_entry_signal),
                        "focus_restore_signal": bool(has_focus_restore_signal),
                        "keyboard_contract_missing": bool(not has_close_signal),
                    },
                },
            ),
        ]

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        # Backward-compatible alias for older tests/callers that still invoke analyze_regex directly.
        return self.analyze_ast(file_path, content, facts, metrics)

    def _find_dialog_nodes(self, root, content_bytes: bytes) -> list:
        nodes = []
        for node in self._jsx.iter_jsx_elements(root):
            opening = self._jsx.get_opening_node(node)
            tag = self._jsx.get_tag_name(opening, content_bytes)
            attrs = self._jsx.get_attributes(opening, content_bytes)
            attr_map = {a.name: a for a in attrs}

            if any(tag.endswith(hint) for hint in self._DIALOG_TAG_HINTS):
                nodes.append(node)
                continue
            role_attr = attr_map.get("role")
            if role_attr and (role_attr.static_value or "").lower() in {"dialog", "alertdialog"}:
                nodes.append(node)
                continue
            aria_modal = attr_map.get("aria-modal")
            if aria_modal and (aria_modal.static_value or "").lower() == "true":
                nodes.append(node)
                continue
        return nodes

    def _dialog_tags(self, dialog_nodes: list, content_bytes: bytes) -> list[str]:
        tags: list[str] = []
        for node in dialog_nodes:
            opening = self._jsx.get_opening_node(node)
            tag = self._jsx.get_tag_name(opening, content_bytes).strip()
            if tag:
                tags.append(tag)
        return tags

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
