"""
Inertia Page Missing Head Rule

Detects Inertia React page components that do not render a `Head` element.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


PAGE_EXPORT_RE = re.compile(
    r"\bexport\s+default\b|\bexport\s+function\s+[A-Z]\w*\b|\bexport\s+const\s+[A-Z]\w*\b",
    re.MULTILINE,
)
COMPONENT_SIGNAL_RE = re.compile(
    r"\bfunction\s+[A-Z]\w*\s*\(|\bconst\s+[A-Z]\w*\s*=\s*(?:memo\s*\()?(?:function\b|\([^)]*\)\s*=>)|return\s*<|return\s*\(",
    re.MULTILINE,
)
HEAD_IMPORT_RE = re.compile(
    r"(from\s+[\"']@inertiajs/react[\"'][^\n]*\bHead\b)|(\bHead\b[^\n]*from\s+[\"']@inertiajs/react[\"'])",
    re.MULTILINE,
)
ALT_HEAD_COMPONENT_RE = re.compile(
    r"<(?:PageHead|SeoHead|SeoMeta|PageMeta|MetaTags)\b[^>]*\b(title|pageTitle|metaTitle|seoTitle)\s*=",
    re.MULTILINE,
)
HELMET_TITLE_RE = re.compile(
    r"<Helmet[^>]*>.*?<title[^>]*>.*?</title>.*?</Helmet>",
    re.IGNORECASE | re.DOTALL,
)
HEAD_LIB_IMPORT_RE = re.compile(
    r"from\s+[\"']react-helmet(?:-async)?[\"']",
    re.MULTILINE,
)
LAYOUT_TITLE_PROP_RE = re.compile(
    r"<[A-Z][A-Za-z0-9]*(?:Layout|Shell|Page)\b[^>]*\b(title|pageTitle|metaTitle|seoTitle)\s*=",
    re.MULTILINE,
)
LAYOUT_ASSIGNMENT_TITLE_RE = re.compile(
    r"\.\s*layout\s*=\s*(?:.|\n){0,240}?\b(title|pageTitle|metaTitle|seoTitle)\s*=",
    re.MULTILINE,
)
TITLE_MANAGEMENT_RE = re.compile(
    r"\b(document\.title|useDocumentTitle|setDocumentTitle|usePageTitle|setPageTitle)\b",
    re.MULTILINE,
)
PARTIAL_NAME_MARKERS = (
    ".components",
    ".component",
    ".helpers",
    ".helper",
    ".utils",
    ".util",
)
PARTIAL_DIR_MARKERS = (
    "/components/",
    "/component/",
    "/partials/",
    "/partial/",
    "/utils/",
    "/helpers/",
    "/hooks/",
)
PARTIAL_EXACT_NAMES = {
    "utils",
    "util",
    "helpers",
    "helper",
    "types",
    "constants",
    "schema",
    "schemas",
}
PARTIAL_SUFFIXES = (
    "Card",
    "List",
    "Grid",
    "Stats",
    "Section",
    "Modal",
    "Dialog",
    "Panel",
    "Preview",
    "Footer",
    "Header",
    "Navbar",
    "Sidebar",
    "Item",
    "Row",
    "Table",
    "Tabs",
    "Tab",
    "Form",
    "Fields",
    "Field",
    "SaveBar",
    "Actions",
    "View",
)
ROUTE_ENTRY_BASENAMES = {"index", "show", "edit", "create", "new"}


class InertiaPageMissingHeadRule(Rule):
    id = "inertia-page-missing-head"
    name = "Inertia Page Missing Head"
    description = "Detects Inertia page components that do not render a Head element"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = ["laravel_inertia_react"]
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

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
        norm = (file_path or "").replace("\\", "/")
        if "/resources/js/pages/" not in f"/{norm.lower()}":
            return []
        if self._is_likely_page_partial(file_path, facts):
            return []

        text = content or ""
        if not PAGE_EXPORT_RE.search(text):
            return []
        if not COMPONENT_SIGNAL_RE.search(text):
            return []

        if "<Head" in text or HEAD_IMPORT_RE.search(text):
            return []
        if ALT_HEAD_COMPONENT_RE.search(text):
            return []
        if HEAD_LIB_IMPORT_RE.search(text) and HELMET_TITLE_RE.search(text):
            return []
        if self._uses_project_head_wrapper(text, facts):
            return []

        if LAYOUT_TITLE_PROP_RE.search(text):
            return []

        if LAYOUT_ASSIGNMENT_TITLE_RE.search(text):
            return []

        if TITLE_MANAGEMENT_RE.search(text):
            return []

        return [
            self.create_finding(
                title="Inertia page does not render a Head element",
                context=f"file:{file_path}",
                file=file_path,
                line_start=1,
                description=(
                    "Detected an Inertia page component under `resources/js/Pages` that does not render"
                    " `Head` from `@inertiajs/react`."
                ),
                why_it_matters=(
                    "Page-level titles and metadata are usually managed through Inertia's `Head` component."
                    " Omitting it makes page UX and SEO metadata inconsistent."
                ),
                suggested_fix=(
                    "Import `Head` from `@inertiajs/react` and render a page title, for example"
                    " `<Head title=\"Dashboard\" />`."
                ),
                tags=["react", "inertia", "head", "seo"],
                confidence=0.84,
                evidence_signals=[f"file={file_path}", "head_component_missing=true"],
            )
        ]

    def _is_likely_page_partial(self, file_path: str, facts: Facts) -> bool:
        norm = (file_path or "").replace("\\", "/")
        low = norm.lower()
        if any(marker in low for marker in PARTIAL_DIR_MARKERS):
            return True

        stem = Path(norm).stem
        stem_low = stem.lower()
        if stem_low in ROUTE_ENTRY_BASENAMES:
            return False
        if stem_low in PARTIAL_EXACT_NAMES:
            return True
        if any(marker in stem_low for marker in PARTIAL_NAME_MARKERS):
            return True
        if any(stem.endswith(suffix) for suffix in PARTIAL_SUFFIXES):
            return True

        return self._has_sibling_index_page(file_path, facts)

    def _has_sibling_index_page(self, file_path: str, facts: Facts) -> bool:
        project_root = str(getattr(facts, "project_path", "") or "").strip()
        if not project_root:
            return False

        parent = Path(file_path).parent
        stem = Path(file_path).stem.lower()
        if stem in ROUTE_ENTRY_BASENAMES:
            return False

        for candidate in ("Index.tsx", "Index.jsx", "Index.ts", "Index.js"):
            sibling = Path(project_root) / parent / candidate
            if sibling.exists():
                return True
        return False

    def _uses_project_head_wrapper(self, content: str, facts: Facts) -> bool:
        wrappers = [
            str(name or "").strip()
            for name in (getattr(getattr(facts, "project_context", None), "custom_head_wrappers", []) or [])
            if str(name or "").strip() and str(name or "").strip() != "Head"
        ]
        if not wrappers:
            return False
        wrapper_re = re.compile(
            rf"<(?:{'|'.join(re.escape(name) for name in wrappers)})\b[^>]*\b(title|pageTitle|metaTitle|seoTitle)\s*=",
            re.MULTILINE,
        )
        return bool(wrapper_re.search(content or ""))
