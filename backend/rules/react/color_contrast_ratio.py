"""
Color Contrast Ratio Rule

Detects potential color contrast issues in inline styles and Tailwind classes.
Note: This is a heuristic check - actual contrast requires computed styles.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ColorContrastRatioRule(Rule):
    id = "color-contrast-ratio"
    name = "Color Contrast Ratio"
    description = "Detects potential color contrast issues in text elements"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Text elements
    _TEXT_PATTERN = re.compile(
        r"<(?P<tag>p|h[1-6]|span|div|li|td|th|label|a|button|small|strong|em)\b(?P<attrs>[^>]*)>",
        re.IGNORECASE,
    )
    
    # Low contrast color patterns (gray-400, gray-300, etc. on white)
    _LOW_CONTRAST_TAILWIND = [
        re.compile(r'text-gray-[3-5]00\b', re.IGNORECASE),
        re.compile(r'text-slate-[3-5]00\b', re.IGNORECASE),
        re.compile(r'text-zinc-[3-5]00\b', re.IGNORECASE),
        re.compile(r'text-neutral-[3-5]00\b', re.IGNORECASE),
        re.compile(r'text-stone-[3-5]00\b', re.IGNORECASE),
        re.compile(r'text-muted', re.IGNORECASE),
        re.compile(r'text-muted-foreground', re.IGNORECASE),
    ]
    
    # Inline style color patterns
    _STYLE_COLOR = re.compile(
        r'style=["\'][^"\']*color\s*:\s*(?P<color>[^;"\']+)[^"\']*["\']',
        re.IGNORECASE,
    )
    
    # Light hex colors (heuristic - light grays, pastels)
    _LIGHT_COLOR_PATTERN = re.compile(
        r'#[d-e][0-9a-f]{5}|#[c-f][c-f][c-f][c-f][c-f][c-f]|rgba?\([^)]*,\s*0\.[4-9]\)',
        re.IGNORECASE,
    )
    
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
        seen_lines: set[int] = set()

        for m in self._TEXT_PATTERN.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            if line in seen_lines:
                continue
            
            tag = m.group("tag").lower()
            attrs = m.group("attrs") or ""
            
            # Check for low contrast Tailwind classes
            low_contrast_class = None
            for pattern in self._LOW_CONTRAST_TAILWIND:
                match = pattern.search(attrs)
                if match:
                    low_contrast_class = match.group(0)
                    break
            
            if low_contrast_class:
                seen_lines.add(line)
                findings.append(
                    self.create_finding(
                        title="Potential low contrast text color",
                        context=f"{file_path}:{line}:{tag}",
                        file=file_path,
                        line_start=line,
                        description=(
                            f"`<{tag}>` uses `{low_contrast_class}` which may have insufficient contrast. "
                            "WCAG AA requires 4.5:1 contrast ratio for normal text."
                        ),
                        why_it_matters=(
                            "Low contrast text:\n"
                            "- Is difficult to read for users with low vision\n"
                            "- Fails WCAG 2.1 Success Criterion 1.4.3\n"
                            "- Affects users in bright environments\n"
                            "- May be invisible for colorblind users"
                        ),
                        suggested_fix=(
                            "1. Use darker color: text-gray-700 or text-gray-800\n"
                            "2. Check contrast with a tool: webaim.org/resources/contrastchecker\n"
                            "3. Ensure 4.5:1 ratio for normal text, 3:1 for large text"
                        ),
                        tags=["ux", "a11y", "contrast", "accessibility", "wcag"],
                        confidence=0.70,
                        evidence_signals=[
                            f"tag={tag}",
                            f"low_contrast_class={low_contrast_class}",
                        ],
                    )
                )
                continue
            
            # Check for inline style colors
            style_match = self._STYLE_COLOR.search(attrs)
            if style_match:
                color = style_match.group("color")
                if self._LIGHT_COLOR_PATTERN.search(color):
                    seen_lines.add(line)
                    findings.append(
                        self.create_finding(
                            title="Potential low contrast inline color",
                            context=f"{file_path}:{line}:{tag}",
                            file=file_path,
                            line_start=line,
                            description=(
                                f"`<{tag}>` uses inline color `{color}` which may have insufficient contrast."
                            ),
                            why_it_matters="Low contrast text is difficult to read and fails WCAG guidelines.",
                            suggested_fix="Verify contrast ratio meets WCAG AA (4.5:1 for normal text).",
                            tags=["ux", "a11y", "contrast", "accessibility"],
                            confidence=0.55,
                            evidence_signals=[f"color={color}"],
                        )
                    )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
