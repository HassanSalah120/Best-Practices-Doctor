"""
Route Shell Missing Error Boundary Rule

Detects data-heavy route/page shells that do not provide an error boundary.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule


class RouteShellMissingErrorBoundaryRule(Rule):
    id = "route-shell-missing-error-boundary"
    name = "Route Shell Missing Error Boundary"
    description = "Detects route/page shells with async data flow but no error boundary"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx", ".js", ".ts"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _ROUTE_SHELL_MARKER = re.compile(r"/(pages|routes|screens|views)/", re.IGNORECASE)
    _JSX_RETURN = re.compile(r"return\s*\(\s*<|return\s*<", re.IGNORECASE)
    _DATA_SIGNAL_PATTERNS = [
        re.compile(r"\buseQuery\s*\(", re.IGNORECASE),
        re.compile(r"\buseInfiniteQuery\s*\(", re.IGNORECASE),
        re.compile(r"\buseSWR(?:Infinite)?\s*\(", re.IGNORECASE),
        re.compile(r"\buseLoaderData\s*\(", re.IGNORECASE),
        re.compile(r"\bfetch\s*\(", re.IGNORECASE),
        re.compile(r"\baxios\.", re.IGNORECASE),
    ]
    _ERROR_BOUNDARY_PATTERNS = [
        re.compile(r"<\s*ErrorBoundary\b", re.IGNORECASE),
        re.compile(r"\bwithErrorBoundary\s*\(", re.IGNORECASE),
        re.compile(r"\berrorElement\s*:", re.IGNORECASE),
        re.compile(r"\bcreateBrowserRouter\s*\(", re.IGNORECASE),
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
        text = content or ""
        normalized_path = (file_path or "").replace("\\", "/").lower()
        if any(marker in normalized_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if not self._ROUTE_SHELL_MARKER.search(normalized_path):
            return []
        if not self._JSX_RETURN.search(text):
            return []

        min_data_signals = max(1, int(self.get_threshold("min_data_signals", 2)))
        if any(pattern.search(text) for pattern in self._ERROR_BOUNDARY_PATTERNS):
            return []

        data_signal_hits: list[tuple[str, int]] = []
        for pattern in self._DATA_SIGNAL_PATTERNS:
            for match in pattern.finditer(text):
                line_number = text.count("\n", 0, match.start()) + 1
                data_signal_hits.append((pattern.pattern, line_number))
                if len(data_signal_hits) >= min_data_signals:
                    break
            if len(data_signal_hits) >= min_data_signals:
                break

        if len(data_signal_hits) < min_data_signals:
            return []

        first_line = data_signal_hits[0][1]
        finding = self.create_finding(
            title="Data-heavy route shell has no error boundary",
            context=file_path,
            file=file_path,
            line_start=first_line,
            description=(
                "This route/page shell appears to perform async data orchestration but no error boundary was detected."
            ),
            why_it_matters=(
                "Without an error boundary, async/render failures can cascade to full-route crashes "
                "and degrade user recovery experience."
            ),
            suggested_fix=(
                "Wrap the route shell (or critical panels) with an `ErrorBoundary`, "
                "or use framework-specific route error boundaries."
            ),
            confidence=0.8,
            tags=["react", "routing", "error-boundary", "resilience"],
            evidence_signals=[
                f"data_signals={len(data_signal_hits)}",
                "error_boundary=0",
            ],
            metadata={"decision_profile": {"data_signal_count": len(data_signal_hits)}},
        )
        return [finding]
