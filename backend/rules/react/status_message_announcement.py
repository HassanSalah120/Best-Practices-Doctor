"""
Status Message Announcement Rule

Detects status messages that may not be announced to screen readers (WCAG 4.1.3).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class StatusMessageAnnouncementRule(Rule):
    id = "status-message-announcement"
    name = "Status Message Announcement"
    description = "Detects status messages that may not be announced to screen readers"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Status message patterns (actual status DISPLAY patterns, not useState setters)
    # Note: toast() is excluded here - checked separately after sonner detection
    # These patterns look for FUNCTION CALLS or COMPONENT USAGE, not just the word "error"
    _STATUS_PATTERNS = [
        # Function calls that display status
        re.compile(r"notify\s*\([^)]*\)", re.IGNORECASE),  # notify() function call
        re.compile(r"showToast\s*\([^)]*\)", re.IGNORECASE),  # showToast() call
        re.compile(r"showNotification\s*\([^)]*\)", re.IGNORECASE),  # showNotification() call
        re.compile(r"showMessage\s*\([^)]*\)", re.IGNORECASE),  # showMessage() call
        re.compile(r"displayError\s*\(", re.IGNORECASE),  # displayError() call
        re.compile(r"displaySuccess\s*\(", re.IGNORECASE),  # displaySuccess() call
        # Status message variables being rendered
        re.compile(r"\{[^}]*(success|error|warning|info)Message[^}]*\}", re.IGNORECASE),  # {errorMessage} in JSX
        re.compile(r"<StatusMessage", re.IGNORECASE),  # <StatusMessage> component
        re.compile(r"<Alert[^>]*(success|error|warning|info)", re.IGNORECASE),  # <Alert type="error">
    ]
    
    # Toast patterns - checked separately after sonner detection
    _TOAST_PATTERNS = [
        re.compile(r"toast\s*\(", re.IGNORECASE),
        re.compile(r"toast\.(success|error|warning|info|loading|promise)\s*\(", re.IGNORECASE),
        re.compile(r"toast\.custom\s*\(", re.IGNORECASE),
    ]
    
    # ARIA live region patterns (good)
    _LIVE_REGION_PATTERNS = [
        re.compile(r'role=["\'](?:alert|status|log|marquee|timer)["\']', re.IGNORECASE),
        re.compile(r'aria-live=["\'](?:polite|assertive|off)["\']', re.IGNORECASE),
        re.compile(r'aria-atomic=["\'](?:true|false)["\']', re.IGNORECASE),
        re.compile(r'<Alert\b', re.IGNORECASE),
        re.compile(r'<Toast\b', re.IGNORECASE),
        re.compile(r'<Notification\b', re.IGNORECASE),
        re.compile(r'<Snackbar\b', re.IGNORECASE),
        re.compile(r'<StatusMessage\b', re.IGNORECASE),
        # aria-invalid and aria-errormessage for form validation errors
        re.compile(r'aria-invalid=["\']true["\']', re.IGNORECASE),
        re.compile(r'aria-errormessage', re.IGNORECASE),
    ]
    
    # Common toast/notification libraries (usually have a11y built-in)
    _A11Y_LIBRARIES = [
        re.compile(r"react-hot-toast", re.IGNORECASE),
        re.compile(r"react-toastify", re.IGNORECASE),
        re.compile(r"@radix-ui/react-toast", re.IGNORECASE),
        re.compile(r"chakra-ui.*toast", re.IGNORECASE),
    ]
    
    # Sonner-specific patterns (sonner has built-in accessibility)
    _SONNER_PATTERNS = [
        re.compile(r"from\s+['\"]sonner['\"]", re.IGNORECASE),  # Direct sonner import
        re.compile(r"import\s+\{[^}]*toast[^}]*\}\s+from\s+['\"]sonner['\"]", re.IGNORECASE),
        re.compile(r"import\s+\*\s+as\s+\w+\s+from\s+['\"]sonner['\"]", re.IGNORECASE),
        re.compile(r"<Toaster\b", re.IGNORECASE),  # Toaster component from sonner
        re.compile(r"toast\.(success|error|warning|info|loading|promise|custom)\s*\(", re.IGNORECASE),  # sonner API
        re.compile(r"useFlashToast", re.IGNORECASE),  # Custom hook wrapping sonner
    ]
    
    # Inertia/Laravel flash message patterns (handled by layout with toast)
    _INERTIA_FLASH_PATTERNS = [
        re.compile(r"page\.props\.flash", re.IGNORECASE),  # Inertia flash messages
        re.compile(r"props\.flash", re.IGNORECASE),  # Flash from props
        re.compile(r"flash\.(success|error|warning|info)", re.IGNORECASE),  # Flash types
        re.compile(r"usePage\s*\(\s*\)\.props\.flash", re.IGNORECASE),  # usePage hook
    ]
    
    # Files that should be excluded (don't render status messages)
    _NON_RENDERING_FILES = [
        re.compile(r"/hooks/", re.IGNORECASE),  # Hooks don't render
        re.compile(r"/use[A-Z]", re.IGNORECASE),  # useXxx files
        re.compile(r"\.types\.tsx?$", re.IGNORECASE),  # Type definitions
        re.compile(r"/types/", re.IGNORECASE),  # Types directory
        re.compile(r"\.utils?\.tsx?$", re.IGNORECASE),  # Utility files
        re.compile(r"/utils?/", re.IGNORECASE),
        re.compile(r"/i18n/", re.IGNORECASE),  # i18n config
        re.compile(r"/constants?/", re.IGNORECASE),
        re.compile(r"/config/", re.IGNORECASE),
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

        # Skip non-rendering files (hooks, types, utils - they don't render status messages)
        norm_path = (file_path or "").replace("\\", "/").lower()
        if any(p.search(norm_path) for p in self._NON_RENDERING_FILES):
            return []

        findings: list[Finding] = []
        
        # Check if file uses sonner (has built-in accessibility)
        uses_sonner = any(p.search(content) for p in self._SONNER_PATTERNS)
        if uses_sonner:
            return findings
        
        
        # Check if file has status message patterns
        has_status = any(p.search(content) for p in self._STATUS_PATTERNS)
        
        # Also check for generic toast() calls (but only if not using sonner)
        has_toast = any(p.search(content) for p in self._TOAST_PATTERNS)
        
        if not has_status and not has_toast:
            return findings
        
        # Check if file uses Inertia flash messages (handled by layout with toast)
        uses_inertia_flash = any(p.search(content) for p in self._INERTIA_FLASH_PATTERNS)
        if uses_inertia_flash:
            return findings
        
        # Check if file uses accessible notification library
        uses_a11y_lib = any(p.search(content) for p in self._A11Y_LIBRARIES)
        if uses_a11y_lib:
            return findings
        
        # Check if file has live region patterns
        has_live_region = any(p.search(content) for p in self._LIVE_REGION_PATTERNS)
        if has_live_region:
            return findings
        
        # Find status message usage for line number
        line = 1
        for p in self._STATUS_PATTERNS:
            m = p.search(content)
            if m:
                line = content.count("\n", 0, m.start()) + 1
                break
        
        findings.append(
            self.create_finding(
                title="Status messages may not be announced to screen readers",
                context=f"{file_path}:{line}:status-message",
                file=file_path,
                line_start=line,
                description=(
                    "This file shows status messages (success/error/loading) but does not appear to use "
                    "ARIA live regions or accessible notification components. Screen reader users may not "
                    "be notified of important status changes."
                ),
                why_it_matters=(
                    "WCAG 4.1.3 requires status messages to be announced to screen readers.\n"
                    "- Users need to know when actions succeed or fail\n"
                    "- Form validation errors must be announced\n"
                    "- Loading states should be communicated\n"
                    "- Without live regions, screen reader users miss critical feedback"
                ),
                suggested_fix=(
                    "1. Use ARIA live regions:\n"
                    '   <div role="status" aria-live="polite">{message}</div>\n'
                    "2. Or use accessible toast library:\n"
                    "   - react-hot-toast\n"
                    "   - react-toastify\n"
                    "   - sonner\n"
                    "3. For errors, use role=\"alert\" or aria-live=\"assertive\""
                ),
                tags=["ux", "a11y", "notifications", "live-region", "accessibility", "wcag"],
                confidence=0.65,
                evidence_signals=[
                    "status_patterns_detected=true",
                    "live_region_missing=true",
                ],
            )
        )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
