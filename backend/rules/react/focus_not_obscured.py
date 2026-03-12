"""
Focus Not Obscured Rule

Detects fixed/sticky overlays that may obscure focused elements (WCAG 2.4.11).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class FocusNotObscuredRule(Rule):
    id = "focus-not-obscured"
    name = "Focus Not Obscured"
    description = "Detects fixed/sticky elements that may obscure focused content"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx", ".css"]

    # Fixed/sticky positioning patterns
    _FIXED_STICKY_PATTERNS = [
        re.compile(r'position\s*:\s*(?:fixed|sticky)', re.IGNORECASE),
        re.compile(r'fixed\s*:', re.IGNORECASE),  # Tailwind
        re.compile(r'sticky\s*:', re.IGNORECASE),  # Tailwind
        re.compile(r'position-fixed', re.IGNORECASE),  # Bootstrap
        re.compile(r'position-sticky', re.IGNORECASE),  # Bootstrap
    ]
    
    # Common overlay patterns
    _OVERLAY_PATTERNS = [
        re.compile(r"(?:header|footer|nav|sidebar|modal|overlay|banner|cookie|notification)", re.IGNORECASE),
    ]
    
    # Z-index patterns that suggest layering
    _ZINDEX_PATTERN = re.compile(r'z-index\s*:\s*(\d+)', re.IGNORECASE)
    _ZINDEX_CLASS = re.compile(r'z-\d+', re.IGNORECASE)  # Tailwind
    
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

        # Check for fixed/sticky positioning
        for pattern in self._FIXED_STICKY_PATTERNS:
            for m in pattern.finditer(content):
                line = content.count("\n", 0, m.start()) + 1
                if line in seen_lines:
                    continue
                
                seen_lines.add(line)
                
                # Check context for z-index (suggests it's a layer on top)
                context_start = max(0, m.start() - 100)
                context_end = min(len(content), m.end() + 100)
                context = content[context_start:context_end]
                
                has_high_zindex = False
                z_match = self._ZINDEX_PATTERN.search(context)
                if z_match:
                    z_value = int(z_match.group(1))
                    has_high_zindex = z_value >= 10
                
                z_class_match = self._ZINDEX_CLASS.search(context)
                if z_class_match:
                    has_high_zindex = True
                
                # Check if this is likely an overlay element
                is_overlay = any(p.search(context) for p in self._OVERLAY_PATTERNS)
                
                if has_high_zindex or is_overlay:
                    findings.append(
                        self.create_finding(
                            title="Fixed/sticky element may obscure focused content",
                            context=f"{file_path}:{line}:focus-obscured",
                            file=file_path,
                            line_start=line,
                            description=(
                                "Fixed or sticky positioned element detected. When users navigate with keyboard, "
                                "focused elements may be hidden behind this overlay, violating WCAG 2.4.11."
                            ),
                            why_it_matters=(
                                "WCAG 2.4.11 (Level AA 2.2) requires focused elements to be visible.\n"
                                "- Keyboard users need to see which element has focus\n"
                                "- Fixed headers/banners can cover focused content\n"
                                "- Users may lose track of their position\n"
                                "- This is especially problematic with sticky headers"
                            ),
                            suggested_fix=(
                                "1. Add scroll-padding-top to account for fixed header:\n"
                                "   html { scroll-padding-top: 80px; }\n"
                                "2. Ensure focused elements scroll into view:\n"
                                "   element.scrollIntoView({ block: 'nearest' })\n"
                                "3. Consider hiding fixed elements when not needed\n"
                                "4. Use CSS: :focus { scroll-margin-top: 80px; }"
                            ),
                            tags=["ux", "a11y", "focus", "keyboard", "accessibility", "wcag"],
                            confidence=0.55,
                            evidence_signals=[
                                "fixed_position=true",
                                f"high_zindex={has_high_zindex}",
                                f"is_overlay={is_overlay}",
                            ],
                        )
                    )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
