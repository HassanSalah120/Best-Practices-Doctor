"""
No Dangerously Set Inner HTML Rule

Detects usage of dangerouslySetInnerHTML, which exposes the application to XSS attacks.
"""
from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class NoDangerouslySetInnerHtmlRule(Rule):
    id = "no-dangerously-set-inner-html"
    name = "No Dangerously Set Inner HTML"
    description = "Detects usage of dangerouslySetInnerHTML"
    category = Category.SECURITY
    default_severity = Severity.CRITICAL
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Pattern to match JSX prop usage (supports single-line and multi-line formatting)
    _DANGEROUS_PROP_PATTERN = re.compile(
        r"dangerouslySetInnerHTML\s*=\s*\{",
        re.IGNORECASE | re.DOTALL,
    )

    # Patterns for comments to skip
    _COMMENT_PATTERNS = [
        re.compile(r"^\s*//"),           # Single-line comment
        re.compile(r"^\s*\*"),           # Multi-line comment continuation
        re.compile(r"^\s*/\*"),          # Multi-line comment start
        re.compile(r".*\*/\s*$"),        # Multi-line comment end
    ]

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
        findings: list[Finding] = []

        # Quick check - if no dangerouslySetInnerHTML in file, skip
        if "dangerouslySetInnerHTML" not in content:
            return findings

        lines = content.splitlines()
        comment_mask = self._build_comment_mask(lines)

        seen_lines: set[int] = set()
        for match in self._DANGEROUS_PROP_PATTERN.finditer(content):
            line_no = content.count("\n", 0, match.start()) + 1
            if line_no in seen_lines:
                continue
            seen_lines.add(line_no)

            # Skip comment-only hits.
            if 0 < line_no <= len(comment_mask) and comment_mask[line_no - 1]:
                continue

            # Also check surrounding lines for DOMPurify usage
            window_start = max(0, line_no - 4)
            window_end = min(len(lines), line_no + 2)
            context_window = "\n".join(lines[window_start:window_end])
            lowered_window = context_window.lower()
            if "dompurify" in lowered_window or "sanitize(" in lowered_window:
                continue

            findings.append(
                self.create_finding(
                    title="Usage of dangerouslySetInnerHTML detected",
                    context=f"{file_path}:{line_no}:dangerouslySetInnerHTML",
                    file=file_path,
                    line_start=line_no,
                    description=(
                        "Detected usage of `dangerouslySetInnerHTML`. "
                        "This prop bypasses React's XSS protection and allows arbitrary HTML execution."
                    ),
                    why_it_matters=(
                        "If the HTML content comes from an untrusted source (e.g. user input), "
                        "it can lead to Cross-Site Scripting (XSS) attacks."
                    ),
                    suggested_fix=(
                        "Avoid using this prop. If you must render HTML, use a sanitization library "
                        "like `dompurify` before passing it to `dangerouslySetInnerHTML`."
                    ),
                    tags=["react", "security", "xss"],
                    confidence=0.9,
                )
            )

        return findings

    def _build_comment_mask(self, lines: list[str]) -> list[bool]:
        """Return a boolean mask marking lines that are comments."""
        mask: list[bool] = []
        in_multiline_comment = False

        for line in lines:
            stripped = line.strip()
            is_comment = False

            if in_multiline_comment:
                is_comment = True

            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                is_comment = True

            mask.append(is_comment)

            if "/*" in line and "*/" not in line:
                in_multiline_comment = True
            if "*/" in line:
                in_multiline_comment = False

        return mask
