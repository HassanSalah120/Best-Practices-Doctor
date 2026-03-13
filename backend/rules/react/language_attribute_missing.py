"""
Language Attribute Missing Rule

Detects HTML documents without lang attribute (WCAG 3.1.1).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class LanguageAttributeMissingRule(Rule):
    id = "language-attribute-missing"
    name = "Language Attribute Missing"
    description = "Detects HTML documents without lang attribute"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx", ".html"]

    # HTML lang attribute
    _HTML_LANG_PATTERN = re.compile(
        r"<html[^>]*\blang=[\"'](?P<lang>[^\"']+)[\"'][^>]*>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # HTML without lang
    _HTML_NO_LANG_PATTERN = re.compile(
        r"<html(?![^>]*\blang=)[^>]*>",
        re.IGNORECASE,
    )
    
    # Document.documentElement.lang or setAttribute('lang')
    _JS_LANG_PATTERN = re.compile(
        r"document\.documentElement\.lang\s*=|"
        r"setAttribute\s*\(\s*[\"']lang[\"']",
        re.IGNORECASE,
    )
    
    # Next.js _document or layout with lang
    _NEXT_LANG_PATTERN = re.compile(
        r"<html[^>]*lang=\{[^}]+\}",
        re.IGNORECASE,
    )
    
    # Patterns that should NEVER be flagged (non-page/non-layout files)
    _NON_HTML_FILES = [
        re.compile(r"\.types\.tsx?$", re.IGNORECASE),  # Type definition files
        re.compile(r"\.type\.tsx?$", re.IGNORECASE),
        re.compile(r"/types/", re.IGNORECASE),  # Types directory
        re.compile(r"/i18n/", re.IGNORECASE),  # i18n configuration files
        re.compile(r"/hooks/", re.IGNORECASE),  # Hook files
        re.compile(r"/use[A-Z]", re.IGNORECASE),  # useXxx files
        re.compile(r"/utils?\.tsx?$", re.IGNORECASE),  # Standalone utils.ts files
        re.compile(r"\.utils?\.tsx?$", re.IGNORECASE),  # Utility files (e.g., Show.utils.ts)
        re.compile(r"/helpers?\.tsx?$", re.IGNORECASE),
        re.compile(r"/constants?\.tsx?$", re.IGNORECASE),
        re.compile(r"/config\.tsx?$", re.IGNORECASE),
        re.compile(r"/api\.tsx?$", re.IGNORECASE),
        re.compile(r"/service[s]?\.tsx?$", re.IGNORECASE),
        re.compile(r"/context\.tsx?$", re.IGNORECASE),
        re.compile(r"/[A-Z][a-zA-Z]*Context\.tsx?$"),  # XxContext.tsx
        re.compile(r"/[A-Z][a-zA-Z]*Provider\.tsx?$"),  # XxProvider.tsx
        re.compile(r"/components/", re.IGNORECASE),  # Reusable components (not pages)
        re.compile(r"/modals?/", re.IGNORECASE),  # Modal files
        re.compile(r"/dialogs?/", re.IGNORECASE),  # Dialog files
        # React/Inertia page components - they inherit lang from layout
        re.compile(r"/pages/", re.IGNORECASE),  # Individual pages use layouts
        re.compile(r"/screens/", re.IGNORECASE),  # Screen components use layouts
        re.compile(r"/views/", re.IGNORECASE),  # View components use layouts
    ]
    
    # Only these files should be checked for lang attribute
    _HTML_ROOT_FILES = [
        re.compile(r"/layouts?/", re.IGNORECASE),  # Layout files define <html>
        re.compile(r"/_document\.tsx?$", re.IGNORECASE),  # Next.js _document
        re.compile(r"/_app\.tsx?$", re.IGNORECASE),  # Next.js _app
        re.compile(r"/app/layout\.tsx?$", re.IGNORECASE),  # Next.js app router layout
        re.compile(r"/index\.html$", re.IGNORECASE),  # Static HTML files
        re.compile(r"\.html$", re.IGNORECASE),  # Any HTML file
    ]

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/node_modules/",
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

        norm_path = (file_path or "").replace("\\", "/").lower()

        # Skip non-HTML files (types, hooks, utils, components, etc.)
        if any(p.search(norm_path) for p in self._NON_HTML_FILES):
            return []

        findings: list[Finding] = []

        # Only check files that are HTML root files (layouts, _document, .html files)
        # Individual page components inherit lang from their layout
        is_html_root = any(p.search(norm_path) for p in self._HTML_ROOT_FILES)
        if not is_html_root:
            return findings

        # Only check files that have <html> element
        has_html = "<html" in content.lower()
        if not has_html:
            return findings
        
        # Check for lang attribute
        has_lang = bool(self._HTML_LANG_PATTERN.search(content))
        has_js_lang = bool(self._JS_LANG_PATTERN.search(content))
        has_next_lang = bool(self._NEXT_LANG_PATTERN.search(content))
        
        if has_lang or has_js_lang or has_next_lang:
            # Check if lang value is valid (not empty)
            lang_match = self._HTML_LANG_PATTERN.search(content)
            if lang_match:
                lang = lang_match.group("lang")
                if lang and len(lang) >= 2:
                    return findings
                # Empty or invalid lang
                findings.append(
                    self.create_finding(
                        title="HTML lang attribute is empty or invalid",
                        context=f"file:{file_path}",
                        file=file_path,
                        line_start=1,
                        description=(
                            "The html element has a lang attribute but it's empty or invalid. "
                            "Language code must be a valid BCP 47 language tag (e.g., 'en', 'es', 'fr')."
                        ),
                        why_it_matters=(
                            "WCAG 3.1.1 requires the default human language of the page to be identified.\n"
                            "- Screen readers need correct language to pronounce content properly\n"
                            "- Incorrect language causes mispronunciation\n"
                            "- Browser translation features rely on language attribute"
                        ),
                        suggested_fix=(
                            "Set a valid language code:\n"
                            '<html lang="en">  <!-- English -->\n'
                            '<html lang="es">  <!-- Spanish -->\n'
                            '<html lang="fr">  <!-- French -->'
                        ),
                        tags=["ux", "a11y", "language", "accessibility", "wcag"],
                        confidence=0.90,
                        evidence_signals=[f"lang_value={lang}"],
                    )
                )
            return findings
        
        # No lang attribute found
        html_match = self._HTML_NO_LANG_PATTERN.search(content)
        if html_match:
            findings.append(
                self.create_finding(
                    title="HTML element missing lang attribute",
                    context=f"file:{file_path}",
                    file=file_path,
                    line_start=1,
                    description=(
                        "The <html> element does not have a lang attribute. "
                        "This is required for screen readers to pronounce content correctly."
                    ),
                    why_it_matters=(
                        "WCAG 3.1.1 requires the default human language of the page to be identified.\n"
                        "- Screen readers need correct language to pronounce content properly\n"
                        "- Without lang, screen readers may use wrong pronunciation\n"
                        "- Browser translation features rely on language attribute\n"
                        "- This is a Level A requirement (mandatory)"
                    ),
                    suggested_fix=(
                        "Add lang attribute to html element:\n"
                        '<html lang="en">\n'
                        "For Next.js in app/layout.tsx:\n"
                        '<html lang="en" className={...}>'
                    ),
                    tags=["ux", "a11y", "language", "accessibility", "wcag"],
                    confidence=0.95,
                    evidence_signals=["lang_missing=true"],
                )
            )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
