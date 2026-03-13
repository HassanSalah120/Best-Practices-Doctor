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
    
    # Low contrast color patterns (gray-300, gray-400 are definitely too light)
    # gray-500 on white is 4.6:1 which PASSES AA - so we don't flag it
    # gray-600/slate-600 on white is 6.6:1 which PASSES AA - don't flag
    # gray-700/slate-700 on white is 9.5:1 which PASSES AA - don't flag
    _LOW_CONTRAST_TAILWIND = [
        re.compile(r'text-gray-[23]00\b', re.IGNORECASE),  # gray-200 (1.9:1), gray-300 (2.9:1)
        re.compile(r'text-slate-[23]00\b', re.IGNORECASE),  # slate-200 (2.0:1), slate-300 (3.0:1)
        re.compile(r'text-zinc-[23]00\b', re.IGNORECASE),
        re.compile(r'text-neutral-[23]00\b', re.IGNORECASE),
        re.compile(r'text-stone-[23]00\b', re.IGNORECASE),
        # gray-400, slate-400 etc are borderline (3.0-3.1:1) - flag with lower confidence
        re.compile(r'text-gray-400\b', re.IGNORECASE),  # 3.1:1
        re.compile(r'text-slate-400\b', re.IGNORECASE),  # 3.0:1
        re.compile(r'text-zinc-400\b', re.IGNORECASE),
        re.compile(r'text-neutral-400\b', re.IGNORECASE),
        re.compile(r'text-stone-400\b', re.IGNORECASE),
        # Semantic muted colors (depends on theme, but often too light)
        re.compile(r'text-muted\b', re.IGNORECASE),
        re.compile(r'text-muted-foreground\b', re.IGNORECASE),
        # NOTE: text-app-* are semantic theme colors that adapt to light/dark mode
        # They should NOT be flagged as they're designed for their context
        # NOTE: gray-500/600/700, slate-500/600/700 all PASS WCAG AA (4.5:1+)
    ]

    # Borderline colors that might be okay depending on background
    _BORDERLINE_CONTRAST = [
        re.compile(r'text-gray-400\b', re.IGNORECASE),  # 3.1:1 - borderline
        re.compile(r'text-slate-400\b', re.IGNORECASE),  # 3.0:1 - borderline
        re.compile(r'text-zinc-400\b', re.IGNORECASE),
        re.compile(r'text-neutral-400\b', re.IGNORECASE),
        re.compile(r'text-stone-400\b', re.IGNORECASE),
        # NOTE: gray-500 (4.6:1), slate-500 (4.9:1) PASS AA
        # NOTE: gray-600 (6.6:1), slate-600 (7.1:1) PASS AA
        # NOTE: gray-700 (9.5:1), slate-700 (9.5:1) PASS AA
        # NOTE: text-app-* removed - semantic theme colors
    ]

    # Pattern to detect colored backgrounds (bg-X-100, bg-X-50) - text might be okay on these
    _COLORED_BG_PATTERN = re.compile(r'bg-[a-z]+-[15]0\b', re.IGNORECASE)
    
    # Dark mode pattern - colors with dark: prefix are for dark backgrounds
    _DARK_MODE_PATTERN = re.compile(r'dark:', re.IGNORECASE)
    
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
            is_borderline = False
            for pattern in self._LOW_CONTRAST_TAILWIND:
                match = pattern.search(attrs)
                if match:
                    # Check if this match is part of a dark: variant
                    # dark:text-slate-200 is for dark mode and should not be flagged
                    pos = match.start()
                    if pos >= 5 and attrs[pos-5:pos] == 'dark:':
                        continue  # Skip dark mode variant
                    if pos >= 6 and attrs[pos-6:pos] == 'dark:':
                        continue  # Skip dark mode variant (with space)
                    
                    low_contrast_class = match.group(0)
                    # Check if this is a borderline color
                    is_borderline = any(p.search(attrs) for p in self._BORDERLINE_CONTRAST)
                    break

            if low_contrast_class:
                # Skip if element has a colored background (contrast might be fine)
                has_colored_bg = bool(self._COLORED_BG_PATTERN.search(attrs))

                # Adjust confidence based on context
                if has_colored_bg and is_borderline:
                    # Likely okay - colored background with borderline text
                    continue
                elif has_colored_bg:
                    # Colored background - lower confidence
                    confidence = 0.50
                elif is_borderline:
                    # Borderline on white/light bg - medium confidence
                    confidence = 0.60
                else:
                    # Definitely too light (gray-200, gray-300)
                    confidence = 0.80

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
                        confidence=confidence,
                        evidence_signals=[
                            f"tag={tag}",
                            f"low_contrast_class={low_contrast_class}",
                            f"has_colored_bg={has_colored_bg}",
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
