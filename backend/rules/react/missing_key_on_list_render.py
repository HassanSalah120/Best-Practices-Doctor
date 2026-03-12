"""
React Missing Key On List Render Rule

Detects `.map(...)` list renders whose returned JSX root element has no `key` prop.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingKeyOnListRenderRule(Rule):
    id = "missing-key-on-list-render"
    name = "Missing Key On List Render"
    description = "Detects list renders that return JSX without a key prop"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _MAP_CALL = re.compile(r"\.map\s*\(")
    _JSX_TAG = re.compile(r"<(?P<tag>[A-Za-z][\w.]*)\b(?P<attrs>[^>]*)>", re.DOTALL)

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
        seen_lines: set[int] = set()

        for m in self._MAP_CALL.finditer(content):
            idx = m.start()
            # Look for common JSX return patterns in a small window after .map(
            window = content[idx : idx + 150]
            
            # Pattern: => <Tag or return <Tag
            # This is more precise than just looking for "<" anywhere.
            jsx_return_pattern = re.search(r"(=>\s*<|return\s+<)", window)
            if not jsx_return_pattern:
                continue

            # Now look for the tag in a larger window to extract attributes
            full_window = content[idx : idx + 800]
            tag_match = self._JSX_TAG.search(full_window)
            if not tag_match:
                continue

            attrs = (tag_match.group("attrs") or "").lower()
            if "key=" in attrs:
                continue

            tag = (tag_match.group("tag") or "").strip()
            if not tag:
                continue

            line = content.count("\n", 0, idx) + 1
            
            findings.append(
                self.create_finding(
                    title="List render root element is missing `key` prop",
                    context=f"map:{tag}", # Stable context - one per tag type in file
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Detected `.map(...)` returning `<{tag}>` without a `key` prop."
                    ),
                    why_it_matters=(
                        "Missing keys break React list reconciliation and can lead to unstable UI state, "
                        "wrong item reuse, and rendering bugs."
                    ),
                    suggested_fix=(
                        "Add a stable key from your data model (e.g. `key={item.id}`).\n"
                        "Avoid generating random keys during render."
                    ),
                    tags=["react", "lists", "reconciliation", "performance"],
                    confidence=0.9,
                    evidence_signals=[
                        f"file={file_path}",
                        f"line={line}",
                        f"jsx_tag={tag}",
                    ]
                )
            )

        # Deduplicate: Only one "missing key" finding per unique Tag type per file.
        unique_findings: dict[str, Finding] = {}
        for f in findings:
            fp = f.fingerprint or f.compute_fingerprint()
            if fp not in unique_findings:
                unique_findings[fp] = f
            else:
                unique_findings[fp].evidence_signals.append(f"additional_line={f.line_start}")

        return list(unique_findings.values())
