"""
Focus Indicator Missing Rule

Detects focusable elements that may lack visible focus indicators.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class FocusIndicatorMissingRule(Rule):
    id = "focus-indicator-missing"
    name = "Focus Indicator Missing"
    description = "Detects focusable elements that may lack visible focus styling"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Focusable elements
    _FOCUSABLE_PATTERN = re.compile(
        r"<(?P<tag>button|a|input|select|textarea|summary)\b(?P<attrs>[^>]*)>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Elements with tabIndex
    _TABINDEX_PATTERN = re.compile(
        r"<(?P<tag>[a-zA-Z][a-zA-Z0-9]*)\b(?P<attrs>[^>]*)tabIndex[^>]*>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Patterns that indicate focus styling exists
    _FOCUS_STYLE_PATTERNS = [
        re.compile(r"focus:", re.IGNORECASE),  # Tailwind focus: variant
        re.compile(r":focus", re.IGNORECASE),  # CSS pseudo-class
        re.compile(r"focus-visible:", re.IGNORECASE),  # Tailwind focus-visible
        re.compile(r":focus-visible", re.IGNORECASE),  # CSS pseudo-class
        re.compile(r"\.focus", re.IGNORECASE),  # Focus class
        re.compile(r"ring-", re.IGNORECASE),  # Tailwind ring utilities
        re.compile(r"outline-", re.IGNORECASE),  # Outline utilities
    ]
    
    # Patterns that remove focus indicator
    _NO_FOCUS_PATTERNS = [
        re.compile(r"outline-none", re.IGNORECASE),
        re.compile(r"outline-0", re.IGNORECASE),
        re.compile(r"outline:\s*none", re.IGNORECASE),
        re.compile(r"ring-0(?!\d)", re.IGNORECASE),  # ring-0 but not ring-0px
    ]
    
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
        
        # Check if file has any focus styles
        file_has_focus_styles = any(p.search(content) for p in self._FOCUS_STYLE_PATTERNS)

        # Check focusable elements
        for pattern in [self._FOCUSABLE_PATTERN, self._TABINDEX_PATTERN]:
            for m in pattern.finditer(content):
                line = content.count("\n", 0, m.start()) + 1
                if line in seen_lines:
                    continue
                
                tag = m.group("tag").lower()
                attrs = m.group("attrs") or ""
                
                # Skip hidden/disabled elements
                if self._is_hidden_or_disabled(attrs):
                    continue
                
                # Check if element has focus styling
                has_focus_style = any(p.search(attrs) for p in self._FOCUS_STYLE_PATTERNS)
                removes_focus = any(p.search(attrs) for p in self._NO_FOCUS_PATTERNS)
                
                # If removes focus without adding alternative, flag it
                if removes_focus and not has_focus_style:
                    seen_lines.add(line)
                    findings.append(
                        self.create_finding(
                            title="Focus indicator removed without replacement",
                            context=f"{file_path}:{line}:{tag}",
                            file=file_path,
                            line_start=line,
                            description=(
                                f"`<{tag}>` has `outline-none` or similar but no visible focus replacement. "
                                "Keyboard users won't see where focus is."
                            ),
                            why_it_matters=(
                                "WCAG 2.4.7 requires visible focus indicator.\n"
                                "- Keyboard users need to know which element has focus\n"
                                "- Removing outline without replacement violates accessibility guidelines\n"
                                "- Focus indicator helps all users track their position"
                            ),
                            suggested_fix=(
                                "1. Add Tailwind focus styles: `focus:ring-2 focus:ring-blue-500`\n"
                                "2. Or use focus-visible: `focus-visible:ring-2`\n"
                                "3. Never use outline-none without providing alternative focus style"
                            ),
                            tags=["ux", "a11y", "focus", "keyboard", "accessibility"],
                            confidence=0.90,
                            evidence_signals=[
                                f"tag={tag}",
                                "outline_removed=true",
                                "focus_style_missing=true",
                            ],
                        )
                    )
                
                # If file has no focus styles at all, note it (lower confidence)
                elif not file_has_focus_styles and not has_focus_style:
                    # Only flag once per file
                    if not findings:
                        findings.append(
                            self.create_finding(
                                title="File may lack focus indicator styles",
                                context=f"file:{file_path}",
                                file=file_path,
                                line_start=line,
                                description=(
                                    "No focus styles detected in this file. "
                                    "Focusable elements should have visible focus indicators."
                                ),
                                why_it_matters=(
                                    "WCAG 2.4.7 requires visible focus indicator for keyboard navigation."
                                ),
                                suggested_fix=(
                                    "Add focus styles to interactive elements:\n"
                                    "- Tailwind: `focus:ring-2 focus:ring-blue-500 focus:outline-none`\n"
                                    "- CSS: `:focus { outline: 2px solid blue; }`"
                                ),
                                tags=["ux", "a11y", "focus", "keyboard", "accessibility"],
                                confidence=0.60,  # Lower - might be in global CSS
                                evidence_signals=["no_focus_styles_in_file=true"],
                            )
                        )

        return findings

    def _is_hidden_or_disabled(self, attrs: str) -> bool:
        attrs_lower = attrs.lower()
        return (
            "hidden" in attrs_lower
            or "disabled" in attrs_lower
            or 'aria-hidden="true"' in attrs_lower
            or 'type="hidden"' in attrs_lower
            or 'tabindex="-1"' in attrs_lower
        )

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
