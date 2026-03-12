"""
Heading Order Rule

Detects skipped heading levels (e.g., h1 -> h3 without h2).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class HeadingOrderRule(Rule):
    id = "heading-order"
    name = "Heading Order"
    description = "Detects skipped heading levels that break document outline"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Heading patterns
    _HEADING_PATTERN = re.compile(
        r"<h(?P<level>[1-6])\b[^>]*>(?P<text>.*?)</h[1-6]>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Also catch headings with JSX content
    _HEADING_JSX_PATTERN = re.compile(
        r"<h(?P<level>[1-6])\b[^>]*>",
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
        
        # Collect all headings with their levels and positions
        headings: list[tuple[int, int, str]] = []  # (level, line, text)
        
        for m in self._HEADING_PATTERN.finditer(content):
            level = int(m.group("level"))
            line = content.count("\n", 0, m.start()) + 1
            text = re.sub(r"<[^>]+>|\{[^}]*\}", "", m.group("text")).strip()[:30]
            headings.append((level, line, text))
        
        if len(headings) < 2:
            return findings
        
        # Check for skipped levels
        prev_level = 0
        for level, line, text in headings:
            # First heading should be h1 (but we don't enforce this strictly)
            if prev_level == 0:
                prev_level = level
                continue
            
            # Check if level is skipped (e.g., h1 -> h3)
            if level > prev_level + 1:
                skipped = list(range(prev_level + 1, level))
                skipped_str = ", ".join(f"h{s}" for s in skipped)
                
                findings.append(
                    self.create_finding(
                        title="Heading level skipped",
                        context=f"{file_path}:{line}:heading-skip",
                        file=file_path,
                        line_start=line,
                        description=(
                            f"Heading level skipped from h{prev_level} to h{level}. "
                            f"Missing heading level(s): {skipped_str}."
                        ),
                        why_it_matters=(
                            "Screen reader users navigate by heading levels. "
                            "Skipped levels break the document outline and make navigation confusing. "
                            "WCAG 1.3.1 requires proper heading hierarchy."
                        ),
                        suggested_fix=(
                            f"1. Use h{prev_level + 1} instead of h{level} if appropriate\n"
                            f"2. Or add missing h{prev_level + 1} section before this heading\n"
                            "3. Ensure headings reflect actual document structure"
                        ),
                        tags=["ux", "a11y", "headings", "accessibility", "structure"],
                        confidence=0.85,
                        evidence_signals=[
                            f"from_level={prev_level}",
                            f"to_level={level}",
                            f"skipped={skipped_str}",
                        ],
                    )
                )
            
            # Allow going back up (h3 -> h2 is fine)
            prev_level = level

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
