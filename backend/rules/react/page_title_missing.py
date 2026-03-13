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

    _TITLE_PATTERN = re.compile(
        r"<title[^>]*>(?P<text>[^<]+)</title>",
        re.IGNORECASE | re.DOTALL,
    )

    _TITLE_LITERAL_PATTERNS = [
        _TITLE_PATTERN,
        re.compile(r"<Head[^>]*\btitle\s*=\s*['\"](?P<text>[^'\"]+)['\"]", re.IGNORECASE),
        re.compile(
            r"<[A-Z][a-zA-Z0-9]*(?:Layout|Shell|Page|Wrapper)\b[^>]*\btitle\s*=\s*['\"](?P<text>[^'\"]+)['\"]",
            re.IGNORECASE,
        ),
        re.compile(r"useTitle\s*\(\s*['\"](?P<text>[^'\"]+)['\"]", re.IGNORECASE),
        re.compile(r"document\.title\s*=\s*['\"](?P<text>[^'\"]+)['\"]", re.IGNORECASE),
        re.compile(r"usePageTitle\s*\(\s*['\"](?P<text>[^'\"]+)['\"]", re.IGNORECASE),
        re.compile(r"setPageTitle\s*\(\s*['\"](?P<text>[^'\"]+)['\"]", re.IGNORECASE),
    ]

    _TITLE_SIGNAL_PATTERNS = [
        _TITLE_PATTERN,
        re.compile(r"useTitle\s*\(", re.IGNORECASE),
        re.compile(r"document\.title\s*=", re.IGNORECASE),
        re.compile(r"usePageTitle\s*\(", re.IGNORECASE),
        re.compile(r"setPageTitle\s*\(", re.IGNORECASE),
        re.compile(r"useDocumentTitle\s*\(", re.IGNORECASE),
        re.compile(r"setDocumentTitle\s*\(", re.IGNORECASE),
        re.compile(r"<Head[^>]*title\s*=", re.IGNORECASE),
        re.compile(r"<Head[^>]*>.*?<title[^>]*>.*?</title>.*?</Head>", re.IGNORECASE | re.DOTALL),
        re.compile(
            r"<[A-Z][a-zA-Z0-9]*(?:Layout|Shell|Page|Wrapper)\b[^>]*\b(title|pageTitle|metaTitle|seoTitle)\s*=",
            re.IGNORECASE,
        ),
        re.compile(
            r"\.\s*layout\s*=\s*(?:.|\n){0,240}?\b(title|pageTitle|metaTitle|seoTitle)\s*=",
            re.MULTILINE,
        ),
    ]
    _PAGE_EXPORT_PATTERN = re.compile(
        r"\bexport\s+default\b|\bexport\s+function\s+[A-Z]\w*\b|\bexport\s+const\s+[A-Z]\w*\b|return\s*\(",
        re.MULTILINE,
    )
    _GENERIC_TITLES = {"untitled", "page", "new page", "home"}

    # Legacy compatibility patterns
    _USE_TITLE_PATTERN = re.compile(
        r"useTitle\s*\(|document\.title\s*=",
        re.IGNORECASE,
    )
    
    # Page patterns - these indicate a page component
    _PAGE_PATTERNS = [
        re.compile(r"/Pages/", re.IGNORECASE),
        re.compile(r"/pages/", re.IGNORECASE),
        re.compile(r"/screens/", re.IGNORECASE),
        re.compile(r"/Screens/", re.IGNORECASE),
        re.compile(r"/views/", re.IGNORECASE),
        re.compile(r"/Views/", re.IGNORECASE),
    ]

    # Patterns that indicate a page file name (not types, hooks, utils)
    _PAGE_FILE_PATTERNS = [
        re.compile(r"/Index\.tsx?$", re.IGNORECASE),
        re.compile(r"/Show\.tsx?$", re.IGNORECASE),
        re.compile(r"/Edit\.tsx?$", re.IGNORECASE),
        re.compile(r"/Create\.tsx?$", re.IGNORECASE),
        re.compile(r"/[A-Z][a-zA-Z]*Page\.tsx?$"),  # XxPage.tsx
        re.compile(r"/[A-Z][a-zA-Z]*Screen\.tsx?$"),  # XxScreen.tsx
        re.compile(r"/[A-Z][a-zA-Z]*View\.tsx?$"),  # XxView.tsx
    ]

    # Patterns that should NEVER be flagged (non-page files)
    _NON_PAGE_PATTERNS = [
        re.compile(r"\.components\.tsx?$", re.IGNORECASE),  # Component modules (*.components.tsx)
        re.compile(r"\.types\.tsx?$", re.IGNORECASE),  # Type definition files
        re.compile(r"\.type\.tsx?$", re.IGNORECASE),
        re.compile(r"/types/", re.IGNORECASE),  # Types directory
        re.compile(r"/i18n/", re.IGNORECASE),  # i18n configuration files
        re.compile(r"/hooks/", re.IGNORECASE),  # Hook files
        re.compile(r"/use[A-Z]", re.IGNORECASE),  # useXxx files
        re.compile(r"\.utils?\.tsx?$", re.IGNORECASE),  # Utility files (e.g., Show.utils.ts)
        re.compile(r"/utils?\.tsx?$", re.IGNORECASE),  # Standalone utils.ts files
        re.compile(r"/utils?/", re.IGNORECASE),  # Utils directory
        re.compile(r"/utilities?/", re.IGNORECASE),  # Utilities directory
        re.compile(r"[A-Z][a-zA-Z]*Utils\.ts$", re.IGNORECASE),  # XxUtils.ts (e.g., invoiceUtils.ts)
        re.compile(r"\.helpers?\.tsx?$", re.IGNORECASE),  # Helper files (e.g., branding.helpers.ts)
        re.compile(r"/helpers?\.tsx?$", re.IGNORECASE),  # Standalone helpers.ts files
        re.compile(r"/helpers?/", re.IGNORECASE),
        re.compile(r"/types\.tsx?$", re.IGNORECASE),  # Standalone types.ts files
        re.compile(r"/config\.tsx?$", re.IGNORECASE),
        re.compile(r"/api\.tsx?$", re.IGNORECASE),
        re.compile(r"/service[s]?\.tsx?$", re.IGNORECASE),
        re.compile(r"/context\.tsx?$", re.IGNORECASE),
        re.compile(r"/[A-Z][a-zA-Z]*Context\.tsx?$"),  # XxContext.tsx
        re.compile(r"/[A-Z][a-zA-Z]*Provider\.tsx?$"),  # XxProvider.tsx
        re.compile(r"/_", re.IGNORECASE),  # Partial files starting with _
        re.compile(r"/components/", re.IGNORECASE),  # Component files (not pages)
        re.compile(r"/layouts?/", re.IGNORECASE),  # Layout files
        re.compile(r"/modals?/", re.IGNORECASE),  # Modal files
        re.compile(r"/dialogs?/", re.IGNORECASE),  # Dialog files
        # Stats/Summary components (not standalone pages)
        re.compile(r"Stats\.tsx?$", re.IGNORECASE),  # *Stats.tsx (e.g., ScheduleStats.tsx)
        re.compile(r"Summary\.tsx?$", re.IGNORECASE),  # *Summary.tsx
        # Content/Section/Card components (not standalone pages)
        re.compile(r"Content\.tsx?$", re.IGNORECASE),  # *Content.tsx (e.g., InvoiceIndexContent.tsx)
        re.compile(r"Section\.tsx?$", re.IGNORECASE),  # *Section.tsx (e.g., HeroSection.tsx)
        re.compile(r"Card\.tsx?$", re.IGNORECASE),  # *Card.tsx
        re.compile(r"Form\.tsx?$", re.IGNORECASE),  # *Form.tsx (e.g., EmailBookingForm.tsx)
        re.compile(r"Row\.tsx?$", re.IGNORECASE),  # *Row.tsx (table rows, list items)
        re.compile(r"Item\.tsx?$", re.IGNORECASE),  # *Item.tsx (list items)
        re.compile(r"Cell\.tsx?$", re.IGNORECASE),  # *Cell.tsx (table cells)
        re.compile(r"Bar\.tsx?$", re.IGNORECASE),  # *Bar.tsx (navigation bars, toolbars)
        re.compile(r"Panel\.tsx?$", re.IGNORECASE),  # *Panel.tsx
        re.compile(r"Modal\.tsx?$", re.IGNORECASE),  # *Modal.tsx
        re.compile(r"Dialog\.tsx?$", re.IGNORECASE),  # *Dialog.tsx
        re.compile(r"Dropdown\.tsx?$", re.IGNORECASE),  # *Dropdown.tsx
        re.compile(r"Menu\.tsx?$", re.IGNORECASE),  # *Menu.tsx
        re.compile(r"Tab[s]?\.tsx?$", re.IGNORECASE),  # *Tab.tsx, *Tabs.tsx
        re.compile(r"Button\.tsx?$", re.IGNORECASE),  # *Button.tsx
        re.compile(r"Input\.tsx?$", re.IGNORECASE),  # *Input.tsx
        re.compile(r"Field\.tsx?$", re.IGNORECASE),  # *Field.tsx
        re.compile(r"Filter\.tsx?$", re.IGNORECASE),  # *Filter.tsx
        re.compile(r"Wizard\.tsx?$", re.IGNORECASE),  # *Wizard.tsx (multi-step components)
        # View sub-components (ShowView.tsx is a component used by Show.tsx, not a page)
        re.compile(r"View\.tsx?$", re.IGNORECASE),  # *View.tsx sub-components
        re.compile(r"List\.tsx?$", re.IGNORECASE),  # *List.tsx sub-components
        re.compile(r"Grid\.tsx?$", re.IGNORECASE),  # *Grid.tsx sub-components
        re.compile(r"Chart\.tsx?$", re.IGNORECASE),  # *Chart.tsx sub-components
        # Landing page sections (not standalone pages)
        re.compile(r"/Welcome/[^/]+\.tsx?$", re.IGNORECASE),  # Welcome/*.tsx except Index
        re.compile(r"/ContactSales/[^/]+\.tsx?$", re.IGNORECASE),  # ContactSales/*.tsx
        # Scripts
        re.compile(r"/scripts?/", re.IGNORECASE),  # Node.js scripts
        re.compile(r"\.config\.js$", re.IGNORECASE),  # Config files
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

        # First, exclude non-page files (types, hooks, utils, components, etc.)
        if any(p.search(file_path) for p in self._NON_PAGE_PATTERNS):
            return []

        # Check if this is a page-like file (in pages/screens/views folder OR has page file name)
        is_in_page_folder = any(p.search(file_path) for p in self._PAGE_PATTERNS)
        is_page_file_name = any(p.search(file_path) for p in self._PAGE_FILE_PATTERNS)

        if not (is_in_page_folder or is_page_file_name):
            return []
        if not self._looks_like_page_component(content):
            return []

        title_text = self._extract_explicit_title(content)
        if title_text is not None:
            if self._is_generic_title(title_text):
                return [
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
                        evidence_signals=[f"title_text={title_text.strip()}"],
                    )
                ]
            return []

        if any(pattern.search(content) for pattern in self._TITLE_SIGNAL_PATTERNS):
            return []

        return [
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
        ]

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)

    def _looks_like_page_component(self, content: str) -> bool:
        return bool(self._PAGE_EXPORT_PATTERN.search(content or ""))

    def _extract_explicit_title(self, content: str) -> str | None:
        text = content or ""
        for pattern in self._TITLE_LITERAL_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            title_text = (match.groupdict().get("text") or "").strip()
            if title_text:
                return title_text
        return None

    def _is_generic_title(self, title_text: str) -> bool:
        normalized = (title_text or "").strip().lower()
        return len(normalized) < 3 or normalized in self._GENERIC_TITLES
