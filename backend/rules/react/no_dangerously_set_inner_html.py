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

    # Pattern to match actual JSX prop usage (not comments or strings)
    _DANGEROUS_PROP_PATTERN = re.compile(
        r"dangerouslySetInnerHTML\s*=\s*\{",
        re.IGNORECASE
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

        # Track if we're inside a multi-line comment
        in_multiline_comment = False

        for i, line in enumerate(lines):
            # Track multi-line comment state
            if "/*" in line and "*/" not in line:
                in_multiline_comment = True
            if "*/" in line:
                in_multiline_comment = False
                continue

            # Skip if inside multi-line comment
            if in_multiline_comment:
                continue

            # Skip single-line comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                continue

            # Check for actual JSX prop usage pattern
            if not self._DANGEROUS_PROP_PATTERN.search(line):
                continue

            # Check if this line uses DOMPurify.sanitize() - already safe
            if "dompurify" in line.lower() or "sanitize" in line.lower():
                continue

            # Also check surrounding lines for DOMPurify usage
            window_start = max(0, i - 3)
            window_end = min(len(lines), i + 2)
            context_window = "\n".join(lines[window_start:window_end])
            if "dompurify" in context_window.lower() or "sanitize(" in context_window.lower():
                continue

            findings.append(
                self.create_finding(
                    title="Usage of dangerouslySetInnerHTML detected",
                    context=f"{file_path}:{i+1}:dangerouslySetInnerHTML",
                    file=file_path,
                    line_start=i + 1,
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
