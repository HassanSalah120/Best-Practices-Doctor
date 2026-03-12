"""
Link Text Vague Rule

Detects links with vague text like "click here", "read more", "learn more" without context.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class LinkTextVagueRule(Rule):
    id = "link-text-vague"
    name = "Link Text Vague"
    description = "Detects links with vague text that lacks context"
    category = Category.ACCESSIBILITY
    default_severity = Severity.LOW
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Vague link text patterns
    _VAGUE_PATTERNS = [
        re.compile(r"click\s*here", re.IGNORECASE),
        re.compile(r"read\s*more", re.IGNORECASE),
        re.compile(r"learn\s*more", re.IGNORECASE),
        re.compile(r"more\s*info", re.IGNORECASE),
        re.compile(r"find\s*out\s*more", re.IGNORECASE),
        re.compile(r"see\s*more", re.IGNORECASE),
        re.compile(r"continue\s*reading", re.IGNORECASE),
        re.compile(r"go\s*here", re.IGNORECASE),
        re.compile(r"this\s*(?:page|link|article|post)", re.IGNORECASE),
        re.compile(r"^(?:here|more|link)$", re.IGNORECASE),
    ]
    
    # Link patterns
    _LINK_PATTERN = re.compile(
        r"<a\b(?P<attrs>[^>]*)>(?P<text>[^<]*)</a>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Check for aria-label that provides context
    _ARIA_LABEL = re.compile(r"aria-label=[\"'](?P<label>[^\"']+)[\"']", re.IGNORECASE)
    
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

        for m in self._LINK_PATTERN.finditer(content):
            attrs = m.group("attrs") or ""
            text = m.group("text") or ""
            
            # Strip JSX expressions and get plain text
            plain_text = re.sub(r"\{[^}]*\}", "", text).strip()
            
            if not plain_text:
                # Link might have icon or nested elements - check aria-label
                aria_match = self._ARIA_LABEL.search(attrs)
                if aria_match:
                    plain_text = aria_match.group("label")
                else:
                    continue  # Icon link without aria-label - different issue
            
            # Check if text matches vague patterns
            is_vague = False
            matched_pattern = None
            for pattern in self._VAGUE_PATTERNS:
                if pattern.search(plain_text):
                    is_vague = True
                    matched_pattern = pattern.pattern
                    break
            
            if not is_vague:
                continue
            
            # Check for aria-label that provides better context
            aria_match = self._ARIA_LABEL.search(attrs)
            if aria_match:
                aria_text = aria_match.group("label")
                # If aria-label is more descriptive, skip
                if len(aria_text) > len(plain_text) + 10:
                    continue

            line = content.count("\n", 0, m.start()) + 1
            
            findings.append(
                self.create_finding(
                    title="Link text is vague or lacks context",
                    context=f"{file_path}:{line}:link-text",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Link text \"{plain_text}\" is vague. Screen reader users hear links out of context, "
                        "so \"click here\" doesn't tell them where the link goes."
                    ),
                    why_it_matters=(
                        "Vague link text:\n"
                        "- Forces screen reader users to guess the destination\n"
                        "- Appears in link lists without surrounding context\n"
                        "- Hurts SEO (search engines use link text to understand destinations)\n"
                        "- Violates WCAG 2.4.4 (Link Purpose)"
                    ),
                    suggested_fix=(
                        "1. Make link text describe the destination: \"Read our pricing guide\"\n"
                        "2. Or add aria-label: <a href=\"...\" aria-label=\"Read more about pricing\">Read more</a>\n"
                        "3. Or use visually-hidden text: Read more <span class=\"sr-only\">about pricing</span>"
                    ),
                    tags=["ux", "a11y", "links", "accessibility", "seo"],
                    confidence=0.80,
                    evidence_signals=[
                        f"link_text={plain_text}",
                        f"matched_pattern={matched_pattern}",
                    ],
                )
            )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
