"""
Modal Trap Focus Rule

Detects modal dialogs that may not trap focus properly.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ModalTrapFocusRule(Rule):
    id = "modal-trap-focus"
    name = "Modal Focus Trap Missing"
    description = "Detects modal dialogs that may not trap keyboard focus"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Modal patterns
    _MODAL_PATTERNS = [
        re.compile(r"<(?:Dialog|Modal|Popup|Overlay)\b", re.IGNORECASE),
        re.compile(r'role=["\']dialog["\']', re.IGNORECASE),
        re.compile(r'role=["\']alertdialog["\']', re.IGNORECASE),
        re.compile(r'aria-modal=["\']true["\']', re.IGNORECASE),
        re.compile(r"data-state=[\"']open[\"']", re.IGNORECASE),
        re.compile(r"className=[\"'][^\"']*modal[^\"']*[\"']", re.IGNORECASE),
        re.compile(r"className=[\"'][^\"']*dialog[^\"']*[\"']", re.IGNORECASE),
    ]
    
    # Focus trap patterns (good)
    _FOCUS_TRAP_PATTERNS = [
        re.compile(r"FocusTrap", re.IGNORECASE),
        re.compile(r"focus-trap", re.IGNORECASE),
        re.compile(r"focusTrap", re.IGNORECASE),
        re.compile(r"createFocusTrap", re.IGNORECASE),
        re.compile(r"useFocusTrap", re.IGNORECASE),
        re.compile(r"@react-aria/focus", re.IGNORECASE),
        re.compile(r"FocusScope", re.IGNORECASE),
        re.compile(r"aria-modal", re.IGNORECASE),  # Implies focus management
        re.compile(r"@headlessui/react", re.IGNORECASE),  # Headless UI has built-in focus trap
        re.compile(r"Dialog\s*=\s*require\(['\"]@headlessui", re.IGNORECASE),
        re.compile(r"from\s+['\"]@headlessui/react['\"]", re.IGNORECASE),
        re.compile(r"radix-ui.*dialog", re.IGNORECASE),  # Radix UI has focus trap
        re.compile(r"@radix-ui/react-dialog", re.IGNORECASE),
        re.compile(r"@radix-ui/react-alert-dialog", re.IGNORECASE),
        re.compile(r"DialogContent", re.IGNORECASE),  # shadcn/ui Dialog
        re.compile(r"AlertDialogContent", re.IGNORECASE),  # shadcn/ui AlertDialog
        # Manual focus trap implementation patterns
        re.compile(r"FOCUSABLE_SELECTOR", re.IGNORECASE),  # Focusable element selector constant
        re.compile(r"getFocusableElements", re.IGNORECASE),  # Function to get focusable elements
        re.compile(r"handleKeyDown.*Tab", re.IGNORECASE),  # Tab key handler for focus wrap
        re.compile(r"e\.key.*Tab.*focusable", re.IGNORECASE),  # Tab trap logic
        re.compile(r"previousActiveElement", re.IGNORECASE),  # Focus restoration pattern
    ]

    # Patterns indicating file uses a Modal component (inherits focus trap)
    _MODAL_USAGE_PATTERNS = [
        re.compile(r"from\s+['\"].*/components/UI/Modal['\"]", re.IGNORECASE),
        re.compile(r"from\s+['\"].*/Modal['\"]", re.IGNORECASE),
        re.compile(r"import.*Modal.*from", re.IGNORECASE),
        re.compile(r"<Modal\b", re.IGNORECASE),  # Using Modal component
    ]
    
    # Close button patterns
    _CLOSE_PATTERNS = [
        re.compile(r"onClose", re.IGNORECASE),
        re.compile(r"close", re.IGNORECASE),
        re.compile(r"dismiss", re.IGNORECASE),
        re.compile(r"onDismiss", re.IGNORECASE),
    ]
    
    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._is_allowlisted_path(file_path):
            return []

        findings: list[Finding] = []
        
        # Check if file has modal patterns
        has_modal = any(p.search(content) for p in self._MODAL_PATTERNS)
        if not has_modal:
            return findings
        
        # Check if focus trap is implemented
        has_focus_trap = any(p.search(content) for p in self._FOCUS_TRAP_PATTERNS)
        if has_focus_trap:
            return findings

        # Check if file uses a Modal component that has built-in focus trap
        uses_modal_component = any(p.search(content) for p in self._MODAL_USAGE_PATTERNS)
        if uses_modal_component:
            return findings
        
        # Find modal location for line number
        line = 1
        for p in self._MODAL_PATTERNS:
            m = p.search(content)
            if m:
                line = content.count("\n", 0, m.start()) + 1
                break
        
        findings.append(
            self.create_finding(
                title="Modal may lack focus trap",
                context=f"{file_path}:{line}:modal-focus",
                file=file_path,
                line_start=line,
                description=(
                    "Modal dialog detected but no focus trap implementation found. "
                    "Keyboard focus can escape the modal, making navigation confusing."
                ),
                why_it_matters=(
                    "WCAG 2.4.3 requires focus to be contained within dialogs.\n"
                    "- Keyboard users may tab to background content behind the modal\n"
                    "- Screen reader users may navigate away from the dialog\n"
                    "- Creates confusing experience for assistive technology users"
                ),
                suggested_fix=(
                    "1. Use a focus trap library: focus-trap-react, @react-aria/focus\n"
                    "2. Or implement manual focus trap:\n"
                    "   - Track first/last focusable elements\n"
                    "   - Wrap focus from last to first on Tab\n"
                    "   - Wrap focus from first to last on Shift+Tab\n"
                    "3. Ensure Escape key closes the modal"
                ),
                tags=["ux", "a11y", "modal", "focus", "keyboard", "accessibility"],
                confidence=0.70,
                evidence_signals=[
                    "modal_detected=true",
                    "focus_trap_missing=true",
                ],
            )
        )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
