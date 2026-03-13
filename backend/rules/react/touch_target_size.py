"""
Touch Target Size Rule

Detects interactive elements that are too small for touch targets (WCAG 2.1: 44x44px minimum).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class TouchTargetSizeRule(Rule):
    id = "touch-target-size"
    name = "Touch Target Size"
    description = "Detects interactive elements smaller than 44x44px minimum touch target"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Interactive elements
    _INTERACTIVE_PATTERN = re.compile(
        r"<(?P<tag>button|a|input|select|textarea|summary)\b(?P<attrs>[^>]*)>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Elements with onClick that should also be checked
    _ONCLICK_PATTERN = re.compile(
        r"<(?P<tag>[a-zA-Z][a-zA-Z0-9]*)\b(?P<attrs>[^>]*)onClick[^>]*>",
        re.IGNORECASE | re.DOTALL,
    )

    # Custom UI components that typically have built-in proper touch targets
    _CUSTOM_BUTTON_COMPONENTS = [
        re.compile(r"<Button\b", re.IGNORECASE),
        re.compile(r"<IconButton\b", re.IGNORECASE),
        re.compile(r"<Link\b", re.IGNORECASE),
        re.compile(r"<NavLink\b", re.IGNORECASE),
        re.compile(r"<ActionButton\b", re.IGNORECASE),
        re.compile(r"<MenuButton\b", re.IGNORECASE),
        re.compile(r"<DropdownButton\b", re.IGNORECASE),
    ]

    # Size patterns in className or style
    _SIZE_CLASS_PATTERN = re.compile(
        r"(?:w|h|width|height|size)-(?P<value>\d+)",
        re.IGNORECASE,
    )
    _STYLE_SIZE_PATTERN = re.compile(
        r"(?:width|height)\s*:\s*(?P<value>\d+)(?:px)?",
        re.IGNORECASE,
    )
    _TAILWIND_SIZE_MAP = {
        "0": 0, "1": 4, "2": 8, "3": 12, "4": 16, "5": 20, "6": 24,
        "7": 28, "8": 32, "9": 36, "10": 40, "11": 44, "12": 48,
        "14": 56, "16": 64, "20": 80, "24": 96, "28": 112, "32": 128,
    }

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

        # Check all interactive elements
        for pattern in [self._INTERACTIVE_PATTERN, self._ONCLICK_PATTERN]:
            for m in pattern.finditer(content):
                line = content.count("\n", 0, m.start()) + 1
                if line in seen_lines:
                    continue
                
                tag = m.group("tag").lower()
                attrs = m.group("attrs") or ""
                
                # Skip hidden/disabled elements
                if self._is_hidden_or_disabled(attrs):
                    continue
                
                # Skip inputs that are hidden/checkbox/radio (usually styled differently)
                if tag == "input" and re.search(r'type=["\'](?:hidden|checkbox|radio)["\']', attrs, re.IGNORECASE):
                    continue
                
                # Skip form inputs with h-10 (40px) - standard size with padding that meets 44px
                # Date inputs, selects, and text inputs with h-10 have padding that expands touch target
                if tag in ("input", "select") and re.search(r'\bh-10\b', attrs, re.IGNORECASE):
                    continue
                
                # Skip custom UI components that typically have proper touch targets
                line_content = content.split("\n")[line - 1] if line > 0 else ""
                if any(p.search(line_content) for p in self._CUSTOM_BUTTON_COMPONENTS):
                    continue
                
                # Try to detect size
                size_info = self._detect_size(attrs)
                
                if size_info and (size_info["width"] < 44 or size_info["height"] < 44):
                    seen_lines.add(line)
                    findings.append(
                        self.create_finding(
                            title="Touch target size too small",
                            context=f"{file_path}:{line}:{tag}",
                            file=file_path,
                            line_start=line,
                            description=(
                                f"Interactive element `<{tag}>` appears to be smaller than 44x44px "
                                f"(detected: {size_info['width']}x{size_info['height']}px). "
                                "WCAG 2.1 requires minimum 44x44px touch targets."
                            ),
                            why_it_matters=(
                                "Small touch targets are difficult to activate on touch devices, "
                                "especially for users with motor impairments. This affects mobile users "
                                "and anyone using a touchscreen."
                            ),
                            suggested_fix=(
                                "1. Increase element size to at least 44x44px\n"
                                "2. Use padding to expand the clickable area\n"
                                "3. For icons, wrap in a larger touch target\n"
                                "4. Use Tailwind: `p-2` or `min-w-[44px] min-h-[44px]`"
                            ),
                            tags=["ux", "a11y", "touch", "mobile", "wcag"],
                            confidence=size_info["confidence"],
                            evidence_signals=[
                                f"tag={tag}",
                                f"width={size_info['width']}",
                                f"height={size_info['height']}",
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
        )

    def _detect_size(self, attrs: str) -> dict | None:
        """Try to detect element size from className or style attributes."""
        width = None
        height = None
        confidence = 0.0

        # Check for Tailwind size classes
        w_match = re.search(r"\bw-(?P<val>\d+|full|screen)\b", attrs)
        h_match = re.search(r"\bh-(?P<val>\d+|full|screen)\b", attrs)
        
        if w_match:
            val = w_match.group("val")
            if val in self._TAILWIND_SIZE_MAP:
                width = self._TAILWIND_SIZE_MAP[val]
                confidence = 0.85
            elif val in ("full", "screen"):
                width = 999  # Large enough
                confidence = 0.90
        
        if h_match:
            val = h_match.group("val")
            if val in self._TAILWIND_SIZE_MAP:
                height = self._TAILWIND_SIZE_MAP[val]
                confidence = max(confidence, 0.85)
            elif val in ("full", "screen"):
                height = 999
                confidence = max(confidence, 0.90)

        # Check for size attribute (icons)
        size_match = re.search(r'\bsize=["\'](?P<val>\d+)["\']', attrs)
        if size_match:
            val = int(size_match.group("val"))
            width = height = val
            confidence = 0.90

        # Check for style attribute
        style_match = re.search(r'style=["\'](?P<style>[^"\']+)["\']', attrs)
        if style_match:
            style = style_match.group("style")
            w_style = re.search(r"width\s*:\s*(\d+)", style, re.IGNORECASE)
            h_style = re.search(r"height\s*:\s*(\d+)", style, re.IGNORECASE)
            if w_style:
                width = int(w_style.group(1))
                confidence = max(confidence, 0.95)
            if h_style:
                height = int(h_style.group(1))
                confidence = max(confidence, 0.95)

        # Check for min-width/min-height
        min_w = re.search(r"min-w-\[(\d+)px\]", attrs)
        min_h = re.search(r"min-h-\[(\d+)px\]", attrs)
        if min_w:
            width = int(min_w.group(1))
            confidence = max(confidence, 0.90)
        if min_h:
            height = int(min_h.group(1))
            confidence = max(confidence, 0.90)

        # If no size detected, check for padding (which increases touch target)
        if width is None and height is None:
            p_match = re.search(r"\bp-(?P<val>\d+)\b", attrs)
            if p_match:
                val = p_match.group("val")
                if val in self._TAILWIND_SIZE_MAP:
                    padding = self._TAILWIND_SIZE_MAP[val]
                    # Assume content + padding >= 44
                    if padding >= 11:  # p-3 or more gives decent touch target
                        return None  # Likely OK
            return None  # Can't determine size

        # If size is detected but below 44px, check if padding expands it enough
        if width is not None and height is not None and (width < 44 or height < 44):
            # Check for padding that would expand the touch target
            px_match = re.search(r"\bpx-(?P<val>\d+)\b", attrs)
            py_match = re.search(r"\bpy-(?P<val>\d+)\b", attrs)
            p_match = re.search(r"\bp-(?P<val>\d+)\b", attrs)

            extra_width = 0
            extra_height = 0

            if p_match:
                val = p_match.group("val")
                if val in self._TAILWIND_SIZE_MAP:
                    padding = self._TAILWIND_SIZE_MAP[val]
                    extra_width = padding * 2
                    extra_height = padding * 2
            else:
                if px_match:
                    val = px_match.group("val")
                    if val in self._TAILWIND_SIZE_MAP:
                        extra_width = self._TAILWIND_SIZE_MAP[val] * 2
                if py_match:
                    val = py_match.group("val")
                    if val in self._TAILWIND_SIZE_MAP:
                        extra_height = self._TAILWIND_SIZE_MAP[val] * 2

            # If padding expands touch target to >= 44px, it's OK
            if (width + extra_width >= 44) and (height + extra_height >= 44):
                return None  # Padding makes it large enough

        # Default unknown dimension to detected one (square assumption)
        if width is None:
            width = height or 0
        if height is None:
            height = width or 0

        return {"width": width, "height": height, "confidence": confidence}

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
