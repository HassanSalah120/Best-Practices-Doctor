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

    # Status message patterns (common patterns that show status)
    _STATUS_PATTERNS = [
        re.compile(r"(success|error|warning|info|loading|saving|deleting|updating)\s*(message|text|toast|alert|notification)", re.IGNORECASE),
        re.compile(r"toast\s*\(", re.IGNORECASE),
        re.compile(r"notify\s*\(", re.IGNORECASE),
        re.compile(r"showToast", re.IGNORECASE),
        re.compile(r"showNotification", re.IGNORECASE),
        re.compile(r"showMessage", re.IGNORECASE),
        re.compile(r"setMessage", re.IGNORECASE),
        re.compile(r"setStatus", re.IGNORECASE),
        re.compile(r"setError", re.IGNORECASE),
        re.compile(r"setSuccess", re.IGNORECASE),
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
    ]
    
    # Common toast/notification libraries (usually have a11y built-in)
    _A11Y_LIBRARIES = [
        re.compile(r"react-hot-toast", re.IGNORECASE),
        re.compile(r"react-toastify", re.IGNORECASE),
        re.compile(r"sonner", re.IGNORECASE),
        re.compile(r"@radix-ui/react-toast", re.IGNORECASE),
        re.compile(r"chakra-ui.*toast", re.IGNORECASE),
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
        
        # Check if file has status message patterns
        has_status = any(p.search(content) for p in self._STATUS_PATTERNS)
        if not has_status:
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
