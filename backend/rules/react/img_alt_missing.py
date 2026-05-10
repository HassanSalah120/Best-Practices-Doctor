"""
Image Alt Missing Rule

Detects <img> tags without alt attribute or with empty alt attribute.
"""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class ImageAltMissingRule(Rule):
    id = "img-alt-missing"
    name = "Image Alt Text Missing"
    description = "Detects <img> tags missing descriptive alt text"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _IMG_START = re.compile(r"<img\b", re.IGNORECASE)
    _ALT_ATTR = re.compile(r"\balt\s*=", re.IGNORECASE)
    _EMPTY_ALT = re.compile(r"\balt\s*=\s*(?:\"\"|''|\{\s*\"\"\s*\}|\{\s*''\s*\})", re.IGNORECASE)
    _DECORATIVE = re.compile(
        r"\brole\s*=\s*(?:\"presentation\"|'presentation'|\{\s*['\"]presentation['\"]\s*\})"
        r"|\baria-hidden\s*=\s*(?:\"true\"|'true'|\{\s*true\s*\})",
        re.IGNORECASE,
    )
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Update the component markup and interaction contract so the image alt text missing is accessible by keyboard and assistive technology. Verify the expected ARIA/semantic state in a component test when practical.'
    examples = {}
    priority = 3
    group = 'React Accessibility'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'accessibility', 'concern': 'img-alt'}

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
        findings = []

        for start, _end, attrs in self._iter_img_tags(content):

            # Check for alt attribute
            # We want to catch:
            # 1. Missing alt
            # 2. empty alt="" (unless role="presentation" or aria-hidden="true" is present)

            has_alt = bool(self._ALT_ATTR.search(attrs))
            is_decorative = bool(self._DECORATIVE.search(attrs))
            has_empty_alt = bool(self._EMPTY_ALT.search(attrs))

            if (not has_alt or has_empty_alt) and not is_decorative:
                line = content.count("\n", 0, start) + 1
                missing_text = "without an `alt` attribute" if not has_alt else "with an empty `alt` attribute"
                findings.append(
                    self.create_finding(
                        title="Image missing alt attribute",
                        context=f"{file_path}:{line}:img-alt",
                        file=file_path,
                        line_start=line,
                        description=f"<img> tag detected {missing_text}.",
                        why_it_matters=(
                            "Alternative text is essential for screen reader users to understand the content of images. "
                            "It also helps with SEO and when images fail to load."
                        ),
                        suggested_fix='Add `alt="Description of image"` or `alt=""` with `role="presentation"` if decorative.',
                        tags=["react", "a11y", "accessibility", "images"],
                        confidence=0.9,
                    ),
                )

        return findings

    def _iter_img_tags(self, content: str) -> list[tuple[int, int, str]]:
        tags: list[tuple[int, int, str]] = []
        for match in self._IMG_START.finditer(content):
            end = self._find_tag_end(content, match.end())
            if end == -1:
                continue
            attrs = content[match.end():end]
            tags.append((match.start(), end, attrs))
        return tags

    def _find_tag_end(self, content: str, start: int) -> int:
        brace_depth = 0
        in_single = False
        in_double = False
        in_backtick = False
        escaped = False

        for i in range(start, len(content)):
            ch = content[i]

            if escaped:
                escaped = False
                continue

            if ch == "\\" and (in_single or in_double or in_backtick):
                escaped = True
                continue

            if in_single:
                if ch == "'":
                    in_single = False
                continue

            if in_double:
                if ch == '"':
                    in_double = False
                continue

            if in_backtick:
                if ch == "`":
                    in_backtick = False
                continue

            if ch == "'":
                in_single = True
                continue
            if ch == '"':
                in_double = True
                continue
            if ch == "`":
                in_backtick = True
                continue

            if ch == "{":
                brace_depth += 1
                continue
            if ch == "}":
                brace_depth = max(0, brace_depth - 1)
                continue
            if ch == ">" and brace_depth == 0:
                return i

        return -1
