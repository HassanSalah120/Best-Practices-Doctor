"""
Context Provider Inline Value Rule

Detects inline object, array, or function values passed directly to Context providers.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ContextProviderInlineValueRule(Rule):
    id = "context-provider-inline-value"
    name = "Context Provider Inline Value"
    description = "Detects inline provider values that trigger unnecessary rerenders"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _INLINE_VALUE = re.compile(
        r"<[A-Za-z0-9_.]+\.Provider\b[^>]*\bvalue=\{\s*(\{|\[|(?:async\s*)?\([^)]*\)\s*=>|function\b)",
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
        text = content or ""
        match = self._INLINE_VALUE.search(text)
        if not match:
            return []

        line = text.count("\n", 0, match.start()) + 1
        return [
            self.create_finding(
                title="Context provider uses an inline value object",
                context=f"{file_path}:{line}:provider-value",
                file=file_path,
                line_start=line,
                description=(
                    "Detected a React context provider receiving an inline object, array, or function as its "
                    "`value` prop."
                ),
                why_it_matters=(
                    "Inline provider values create a new reference on every render and can force all consuming "
                    "components to rerender unnecessarily."
                ),
                suggested_fix=(
                    "Move the provider value into `useMemo` or a stable variable, for example "
                    "`const value = useMemo(() => ({ state, setState }), [state]);`."
                ),
                tags=["react", "context", "performance", "rerenders"],
                confidence=0.9,
                evidence_signals=["inline_provider_value=true", f"line={line}"],
            )
        ]
