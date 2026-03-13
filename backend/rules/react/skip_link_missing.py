"""
Skip Link Missing Rule

Detects pages that lack skip-to-content links for keyboard users.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class SkipLinkMissingRule(Rule):
    id = "skip-link-missing"
    name = "Skip Link Missing"
    description = "Detects pages without skip-to-content link for keyboard navigation"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Skip link patterns
    _SKIP_LINK_PATTERNS = [
        re.compile(r"<a[^>]*href=[\"']#main[\"']", re.IGNORECASE),
        re.compile(r"<a[^>]*href=[\"']#content[\"']", re.IGNORECASE),
        re.compile(r"<a[^>]*href=[\"']#skip[\"']", re.IGNORECASE),
        re.compile(r"<a[^>]*href=[\"']#main-content[\"']", re.IGNORECASE),
        re.compile(r"skip\s*(?:to\s*)?(?:main|content)", re.IGNORECASE),
        re.compile(r"skip-link", re.IGNORECASE),
        re.compile(r"skipLink", re.IGNORECASE),
    ]
    
    # Main content landmarks
    _MAIN_CONTENT_PATTERNS = [
        re.compile(r"<main\b", re.IGNORECASE),
        re.compile(r'role=["\']main["\']', re.IGNORECASE),
        re.compile(r'id=["\']main["\']', re.IGNORECASE),
        re.compile(r'id=["\']content["\']', re.IGNORECASE),
        re.compile(r'id=["\']main-content["\']', re.IGNORECASE),
    ]
    
    # Page-like files (layouts, pages) - only layouts need skip links
    _LAYOUT_PATTERNS = [
        re.compile(r"/layouts?/", re.IGNORECASE),
        re.compile(r"Layout\.tsx?$", re.IGNORECASE),
        re.compile(r"[A-Z][a-zA-Z]*Layout\.tsx?$"),  # XxLayout.tsx
        re.compile(r"/App\.tsx?$", re.IGNORECASE),  # Main App component
        re.compile(r"/_app\.tsx?$", re.IGNORECASE),  # Next.js _app
        re.compile(r"/_document\.tsx?$", re.IGNORECASE),  # Next.js _document
    ]
    
    # Files that should be excluded
    _NON_LAYOUT_FILES = [
        re.compile(r"/pages/", re.IGNORECASE),  # Individual pages don't need skip links
        re.compile(r"/components/", re.IGNORECASE),
        re.compile(r"/hooks/", re.IGNORECASE),
        re.compile(r"/types/", re.IGNORECASE),
        re.compile(r"/utils?/", re.IGNORECASE),
        re.compile(r"/i18n/", re.IGNORECASE),
    ]
    
    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/components/ui/",  # Reusable UI components don't need skip links
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
        norm_path = (file_path or "").replace("\\", "/").lower()

        # Skip non-layout files
        if any(p.search(norm_path) for p in self._NON_LAYOUT_FILES):
            return findings

        # Check if this is a layout file
        is_layout = any(p.search(norm_path) for p in self._LAYOUT_PATTERNS)
        if not is_layout:
            return findings
        
        # Check if file has main content landmark
        has_main_content = any(p.search(content) for p in self._MAIN_CONTENT_PATTERNS)
        if not has_main_content:
            return findings  # No main content to skip to
        
        # Check if skip link exists
        has_skip_link = any(p.search(content) for p in self._SKIP_LINK_PATTERNS)
        if has_skip_link:
            return findings  # Skip link present
        
        findings.append(
            self.create_finding(
                title="Page missing skip-to-content link",
                context=f"file:{file_path}",
                file=file_path,
                line_start=1,
                description=(
                    "This page has main content but no skip link. "
                    "Keyboard users must tab through all navigation to reach content."
                ),
                why_it_matters=(
                    "Skip links allow keyboard users to bypass repetitive navigation blocks.\n"
                    "- Required by WCAG 2.4.1 (Bypass Blocks)\n"
                    "- Essential for users who navigate by keyboard\n"
                    "- Screen reader users can jump to main content, but sighted keyboard users cannot"
                ),
                suggested_fix=(
                    "Add a skip link at the start of the page:\n"
                    "<a href=\"#main\" className=\"sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4\">\n"
                    "  Skip to main content\n"
                    "</a>\n"
                    "<main id=\"main\">...</main>"
                ),
                tags=["ux", "a11y", "skip-link", "keyboard", "accessibility"],
                confidence=0.75,
                evidence_signals=[
                    "skip_link_missing=true",
                    "main_content_present=true",
                ],
            )
        )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
