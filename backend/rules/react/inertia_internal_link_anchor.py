"""
Inertia Internal Link Anchor Rule

Detects raw internal anchor tags in Inertia React pages that should prefer `Link`.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class InertiaInternalLinkAnchorRule(Rule):
    id = "inertia-internal-link-anchor"
    name = "Inertia Internal Link Anchor"
    description = "Detects internal anchors that should use Inertia Link"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = ["laravel_inertia_react"]
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ANCHOR = re.compile(
        r"<a\b(?=[^>]*\bhref\s*=\s*['\"]/(?!(?:/|#))[^'\"]+['\"])(?P<attrs>[^>]*)>",
        re.IGNORECASE | re.DOTALL,
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
        norm = (file_path or "").replace("\\", "/").lower()
        if "/resources/js/" not in f"/{norm}":
            return []

        text = content or ""
        m = self._ANCHOR.search(text)
        if not m:
            return []

        attrs = (m.group("attrs") or "").lower()
        if "target=" in attrs or "download" in attrs:
            return []

        line = text.count("\n", 0, m.start()) + 1
        return [
            self.create_finding(
                title="Internal anchor should likely use Inertia Link",
                context=f"{file_path}:{line}:anchor",
                file=file_path,
                line_start=line,
                description=(
                    "Detected a raw internal `<a href=\"/...\">` link in an Inertia React file."
                ),
                why_it_matters=(
                    "Using Inertia's `Link` preserves SPA navigation, history, and partial reload behavior."
                ),
                suggested_fix=(
                    "Replace raw internal anchors with `Link` from `@inertiajs/react`, unless a full page"
                    " reload is explicitly intended."
                ),
                tags=["react", "inertia", "navigation", "link"],
                confidence=0.8,
                evidence_signals=[f"file={file_path}", f"line={line}", "raw_internal_anchor=true"],
            )
        ]
