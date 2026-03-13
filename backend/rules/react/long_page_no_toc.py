"""
Long Page No TOC Rule

Detects long pages without table of contents or landmark navigation.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class LongPageNoTocRule(Rule):
    id = "long-page-no-toc"
    name = "Long Page Without TOC"
    description = "Detects long pages without table of contents or navigation landmarks"
    category = Category.ACCESSIBILITY
    default_severity = Severity.LOW
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Heading pattern to count sections
    _HEADING_PATTERN = re.compile(
        r"<h[1-6]\b[^>]*>",
        re.IGNORECASE,
    )
    
    # TOC patterns (good)
    _TOC_PATTERNS = [
        re.compile(r"<nav\b[^>]*aria-label=[\"'][^\"']*contents[\"']", re.IGNORECASE),
        re.compile(r"<nav\b[^>]*aria-label=[\"'][^\"']*toc[\"']", re.IGNORECASE),
        re.compile(r"table\s*of\s*contents", re.IGNORECASE),
        re.compile(r"toc", re.IGNORECASE),
        re.compile(r"contents-list", re.IGNORECASE),
        re.compile(r"on-this-page", re.IGNORECASE),
        re.compile(r"in-this-article", re.IGNORECASE),
        re.compile(r"jump-to", re.IGNORECASE),
    ]
    
    # Landmark patterns (good)
    _LANDMARK_PATTERNS = [
        re.compile(r"<nav\b", re.IGNORECASE),
        re.compile(r'role=["\']navigation["\']', re.IGNORECASE),
        re.compile(r"<aside\b", re.IGNORECASE),
        re.compile(r'role=["\']complementary["\']', re.IGNORECASE),
    ]
    
    # Page patterns
    _PAGE_PATTERNS = [
        re.compile(r"Page", re.IGNORECASE),
        re.compile(r"Screen", re.IGNORECASE),
        re.compile(r"Article", re.IGNORECASE),
        re.compile(r"Documentation", re.IGNORECASE),
        re.compile(r"Guide", re.IGNORECASE),
    ]

    # Dashboard/SPA patterns that DON'T need TOC (application interfaces, not articles)
    _DASHBOARD_PATTERNS = [
        re.compile(r"Dashboard", re.IGNORECASE),  # Dashboard pages
        re.compile(r"Admin", re.IGNORECASE),  # Admin interfaces
        re.compile(r"Settings", re.IGNORECASE),  # Settings pages
        re.compile(r"ShowView", re.IGNORECASE),  # Detail view sub-components
        re.compile(r"Content", re.IGNORECASE),  # Content sub-components
        re.compile(r"Tabs", re.IGNORECASE),  # Tabbed interfaces
        re.compile(r"Tab", re.IGNORECASE),  # Tab components
        re.compile(r"Panel", re.IGNORECASE),  # Panel-based layouts
        re.compile(r"Widget", re.IGNORECASE),  # Widget dashboards
        re.compile(r"Card", re.IGNORECASE),  # Card-based UIs
        re.compile(r"/Portal/", re.IGNORECASE),  # Portal sections
        re.compile(r"/portal/", re.IGNORECASE),  # Portal sections
        re.compile(r"GlobalSettings", re.IGNORECASE),  # Global settings
        re.compile(r"System", re.IGNORECASE),  # System pages
    ]

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/components/ui/",
    )

    # Minimum headings to consider page "long"
    MIN_HEADINGS = 6

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

        # Skip dashboard/SPA pages that don't need TOC
        is_dashboard_page = any(p.search(file_path) for p in self._DASHBOARD_PATTERNS)
        if is_dashboard_page:
            return findings

        # Skip pages that use tabs (they have built-in section navigation)
        has_tabs = re.search(r'<Tab[^s]|Tabs|tablist|role=["\']tablist["\']', content, re.IGNORECASE)
        if has_tabs:
            return findings

        # Count headings
        headings = self._HEADING_PATTERN.findall(content)
        heading_count = len(headings)
        
        if heading_count < self.MIN_HEADINGS:
            return findings
        
        # Check for TOC
        has_toc = any(p.search(content) for p in self._TOC_PATTERNS)
        if has_toc:
            return findings
        
        # Check for navigation landmarks
        has_landmark = any(p.search(content) for p in self._LANDMARK_PATTERNS)
        
        # If there's a nav but not specifically a TOC, note it
        if has_landmark:
            return findings  # Has some navigation
        
        findings.append(
            self.create_finding(
                title="Long page without table of contents",
                context=f"file:{file_path}",
                file=file_path,
                line_start=1,
                description=(
                    f"This page has {heading_count} headings but no table of contents or "
                    "in-page navigation. Users must scroll to find content."
                ),
                why_it_matters=(
                    "Long pages without TOC:\n"
                    "- Require users to scroll to find relevant sections\n"
                    "- Screen reader users cannot jump to specific sections easily\n"
                    "- Cognitive load increases for all users\n"
                    "- WCAG 2.4.1 suggests bypass mechanisms for repeated blocks"
                ),
                suggested_fix=(
                    "1. Add a table of contents at the top:\n"
                    "   <nav aria-label='Table of contents'>\n"
                    "     <ul>\n"
                    "       <li><a href='#section1'>Section 1</a></li>\n"
                    "       ...\n"
                    "     </ul>\n"
                    "   </nav>\n"
                    "2. Or add 'On this page' navigation in sidebar"
                ),
                tags=["ux", "a11y", "navigation", "toc", "accessibility"],
                confidence=0.60,
                evidence_signals=[
                    f"heading_count={heading_count}",
                    "toc_missing=true",
                ],
            )
        )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
