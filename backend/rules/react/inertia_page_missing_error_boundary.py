from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class InertiaPageMissingErrorBoundaryRule(Rule):
    id = "inertia-page-missing-error-boundary"
    name = "Inertia Page Missing Error Boundary"
    description = "Detects Inertia page components that use page data without an ErrorBoundary wrapper"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".tsx", ".ts", ".jsx", ".js"]
    severity_weight = 5
    confidence = "medium"
    fix_suggestion = "Wrap each Inertia page's content in an ErrorBoundary component. This ensures users see a helpful error message instead of a blank page when something goes wrong during render."
    examples = {"bad": "import { usePage } from '@inertiajs/react'; export default function Page() { return <main /> }", "good": "return <ErrorBoundary><main /></ErrorBoundary>"}
    priority = 3
    group = "React Stability"
    applies_to = ["page", "react-component"]
    references = ["React Error Boundaries", "Inertia.js"]
    related_rules = ["missing-error-boundary-general", "route-shell-missing-error-boundary"]
    false_positive_notes = "Does not fire on layout files because layouts may provide the shared error boundary."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "quality", "concern": "inertia-error-boundary"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        norm = (file_path or "").replace("\\", "/").lower()
        if "layout" in norm or "@inertiajs/react" not in (content or ""):
            return []
        if "ErrorBoundary" in (content or ""):
            return []
        if not self._has_page_data_signal(content or ""):
            return []
        line = self._first_signal_line(content or "")
        return [
            self.create_finding(
                title="Inertia page lacks an ErrorBoundary wrapper",
                file=file_path,
                line_start=line,
                context=f"{file_path}:inertia-error-boundary",
                description="This Inertia page consumes page/form/prop data but does not render an ErrorBoundary wrapper.",
                why_it_matters="Render crashes in page components can blank the whole page without a recovery UI.",
                suggested_fix=self.fix_suggestion,
                confidence=0.72,
                tags=["react", "inertia", "stability"],
                evidence_signals=["inertia_import=true", "error_boundary=false", "page_data_signal=true"],
            ),
        ]

    def _has_page_data_signal(self, content: str) -> bool:
        return bool(
            re.search(r"\busePage\s*\(|\buseForm\s*\(", content)
            or re.search(r"function\s+[A-Z][A-Za-z0-9_]*\s*\(\s*\{", content)
            or re.search(r"const\s+[A-Z][A-Za-z0-9_]*\s*=\s*\(\s*\{", content),
        )

    def _first_signal_line(self, content: str) -> int:
        positions = [pos for token in ("usePage", "useForm", "@inertiajs/react") if (pos := content.find(token)) >= 0]
        return content.count("\n", 0, min(positions)) + 1 if positions else 1
