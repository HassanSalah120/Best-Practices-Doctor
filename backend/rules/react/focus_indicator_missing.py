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
    
    # Global CSS classes that typically have focus styles defined elsewhere
    _GLOBAL_CSS_CLASSES = [
        re.compile(r'\binput\b', re.IGNORECASE),  # Generic input class
        re.compile(r'\binput-base\b', re.IGNORECASE),  # Base input styling
        re.compile(r'\bbtn\b', re.IGNORECASE),  # Button class
        re.compile(r'\bbutton\b', re.IGNORECASE),  # Button class
        re.compile(r'\blink\b', re.IGNORECASE),  # Link class
        re.compile(r'\bform-input\b', re.IGNORECASE),  # Form input class
        re.compile(r'\bform-select\b', re.IGNORECASE),  # Form select class
        re.compile(r'\bform-textarea\b', re.IGNORECASE),  # Form textarea class
    ]

    # Custom component patterns that have built-in focus styles (e.g., <Button>, <Link>)
    # These components typically include focus-visible:ring or similar internally
    _CUSTOM_FOCUSABLE_COMPONENTS = [
        re.compile(r'<Button\b', re.IGNORECASE),  # Custom Button component
        re.compile(r'<Link\b', re.IGNORECASE),  # Custom Link component (not <a>)
        re.compile(r'<IconButton\b', re.IGNORECASE),  # Icon button component
        re.compile(r'<ActionButton\b', re.IGNORECASE),  # Action button component
        re.compile(r'<SubmitButton\b', re.IGNORECASE),  # Submit button component
        re.compile(r'<NavLink\b', re.IGNORECASE),  # Navigation link component
        re.compile(r'<Tab\b', re.IGNORECASE),  # Tab component
        re.compile(r'<Chip\b', re.IGNORECASE),  # Chip/Tag component
        re.compile(r'<Badge\b', re.IGNORECASE),  # Badge component with click
        re.compile(r'<MenuItem\b', re.IGNORECASE),  # Menu item component
        re.compile(r'<ListItem\b', re.IGNORECASE),  # List item with click
        re.compile(r'<DropdownItem\b', re.IGNORECASE),  # Dropdown item
        re.compile(r'<Toggle\b', re.IGNORECASE),  # Toggle component
        re.compile(r'<Switch\b', re.IGNORECASE),  # Switch component
        re.compile(r'<Checkbox\b', re.IGNORECASE),  # Custom checkbox
        re.compile(r'<Radio\b', re.IGNORECASE),  # Custom radio
        re.compile(r'<PaginationItem\b', re.IGNORECASE),  # Pagination item
    ]
    
    # Patterns that remove focus indicator
    _NO_FOCUS_PATTERNS = [
        re.compile(r"outline-none", re.IGNORECASE),
        re.compile(r"outline-0", re.IGNORECASE),
        re.compile(r"outline:\s*none", re.IGNORECASE),
        re.compile(r"ring-0(?!\d)", re.IGNORECASE),  # ring-0 but not ring-0px
    ]

    # Pattern for hover styles without corresponding focus styles
    _HOVER_NO_FOCUS_PATTERN = re.compile(
        r"hover:[a-zA-Z-]+(?!\s+focus:)",  # hover: class not followed by focus:
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

        # Check if file uses custom components with built-in focus styles
        # If the file uses these components heavily, reduce confidence
        has_custom_components = any(p.search(content) for p in self._CUSTOM_FOCUSABLE_COMPONENTS)

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
                
                # Check if element uses global CSS classes with focus styles
                uses_global_css = any(p.search(attrs) for p in self._GLOBAL_CSS_CLASSES)
                if uses_global_css and not any(p.search(attrs) for p in self._NO_FOCUS_PATTERNS):
                    # Element uses a global class that likely has focus styles in CSS
                    continue
                
                # Check if element has focus styling
                has_focus_style = any(p.search(attrs) for p in self._FOCUS_STYLE_PATTERNS)
                removes_focus = any(p.search(attrs) for p in self._NO_FOCUS_PATTERNS)
                has_hover = "hover:" in attrs

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
                # If custom components are used, confidence is even lower as they have built-in styles
                elif not file_has_focus_styles and not has_focus_style:
                    # Only flag once per file
                    if not findings:
                        # Reduce confidence if file uses custom components with built-in focus styles
                        confidence = 0.40 if has_custom_components else 0.60
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
                                confidence=confidence,
                                evidence_signals=["no_focus_styles_in_file=true", f"uses_custom_components={has_custom_components}"],
                            )
                        )

                # If element has hover but no focus styles - common accessibility issue
                # BUT skip if using custom components like <Button> that have built-in focus styles
                elif has_hover and not has_focus_style:
                    # Check if this line uses a custom component with built-in focus styles
                    line_content = content.split("\n")[line - 1] if line > 0 else ""
                    uses_custom_component = any(p.search(line_content) for p in self._CUSTOM_FOCUSABLE_COMPONENTS)
                    if uses_custom_component:
                        continue  # Skip - custom components have built-in focus styles

                    seen_lines.add(line)
                    findings.append(
                        self.create_finding(
                            title="Interactive element has hover but no focus styles",
                            context=f"{file_path}:{line}:{tag}",
                            file=file_path,
                            line_start=line,
                            description=(
                                f"`<{tag}>` has `hover:` styles but no `focus:` styles. "
                                "Keyboard users won't see visual feedback when tabbing to this element."
                            ),
                            why_it_matters=(
                                "WCAG 2.4.7 requires visible focus indicator.\n"
                                "- Mouse users get hover feedback, keyboard users deserve equivalent feedback\n"
                                "- Interactive elements should be accessible to all input methods\n"
                                "- Focus styles help keyboard users navigate efficiently"
                            ),
                            suggested_fix=(
                                "Add focus styles matching your hover styles:\n"
                                "Before: className=\"... hover:bg-amber-200\"\n"
                                "After:  className=\"... hover:bg-amber-200 focus:ring-2 focus:ring-amber-500 focus:outline-none\""
                            ),
                            tags=["ux", "a11y", "focus", "keyboard", "accessibility"],
                            confidence=0.85,
                            evidence_signals=[
                                f"tag={tag}",
                                "has_hover=true",
                                "has_focus=false",
                            ],
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
