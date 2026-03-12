"""
Page Title Missing Rule

Detects pages without proper title element (WCAG 2.4.2).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class PageTitleMissingRule(Rule):
    id = "page-title-missing"
    name = "Page Title Missing"
    description = "Detects pages without descriptive title element"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Title patterns
    _TITLE_PATTERN = re.compile(
        r"<title[^>]*>(?P<text>[^<]+)</title>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Document.title or useTitle hook
    _USE_TITLE_PATTERN = re.compile(
        r"useTitle\s*\(|document\.title\s*=",
        re.IGNORECASE,
    )
    
    # Head component with title (Next.js, etc.)
    _HEAD_TITLE_PATTERN = re.compile(
        r"<Head[^>]*>.*?<title[^>]*>.*?</title>.*?</Head>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Page patterns
    _PAGE_PATTERNS = [
        re.compile(r"Page", re.IGNORECASE),
        re.compile(r"Screen", re.IGNORECASE),
        re.compile(r"View", re.IGNORECASE),
    ]
    
    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/components/ui/",
        "/components/common/",
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
        
        # Check if this is a page-like file
        is_page_like = any(p.search(file_path) for p in self._PAGE_PATTERNS)
        if not is_page_like:
            return findings
        
        # Check for title element
        has_title = bool(self._TITLE_PATTERN.search(content))
        has_use_title = bool(self._USE_TITLE_PATTERN.search(content))
        has_head_title = bool(self._HEAD_TITLE_PATTERN.search(content))
        
        if has_title or has_use_title or has_head_title:
            return findings
        
        # Check if title is too short or generic
        title_match = self._TITLE_PATTERN.search(content)
        if title_match:
            title_text = title_match.group("text").strip()
            if len(title_text) < 3 or title_text.lower() in ("untitled", "page", "new page"):
                findings.append(
                    self.create_finding(
                        title="Page title is too short or generic",
                        context=f"file:{file_path}",
                        file=file_path,
                        line_start=1,
                        description=(
                            f"Page title \"{title_text}\" is too short or generic. "
                            "Titles should describe the page content."
                        ),
                        why_it_matters=(
                            "WCAG 2.4.2 requires descriptive page titles.\n"
                            "- Screen reader users rely on titles to understand page context\n"
                            "- Browser tabs show titles for navigation\n"
                            "- Search engines use titles for indexing"
                        ),
                        suggested_fix=(
                            "Provide a descriptive title:\n"
                            "<title>User Profile - MyApp</title>\n"
                            "Or use useTitle hook: useTitle('Settings - MyApp')"
                        ),
                        tags=["ux", "a11y", "title", "accessibility", "wcag"],
                        confidence=0.85,
                        evidence_signals=[f"title_text={title_text}"],
                    )
                )
            return findings
        
        findings.append(
            self.create_finding(
                title="Page missing title element",
                context=f"file:{file_path}",
                file=file_path,
                line_start=1,
                description=(
                    "This page does not have a <title> element. "
                    "All pages must have a descriptive title."
                ),
                why_it_matters=(
                    "WCAG 2.4.2 requires descriptive page titles.\n"
                    "- Screen reader users rely on titles to understand page context\n"
                    "- Browser tabs show titles for navigation\n"
                    "- Search engines use titles for indexing\n"
                    "- Users with multiple tabs need titles to identify pages"
                ),
                suggested_fix=(
                    "Add a descriptive title:\n"
                    "<title>Dashboard - MyApp</title>\n"
                    "Or for SPAs, use useTitle hook:\n"
                    "useTitle('Settings - MyApp')"
                ),
                tags=["ux", "a11y", "title", "accessibility", "wcag"],
                confidence=0.90,
                evidence_signals=["title_missing=true"],
            )
        )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
