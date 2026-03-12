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
