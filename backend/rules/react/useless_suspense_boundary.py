from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class UselessSuspenseBoundaryRule(Rule):
    id = "useless-suspense-boundary"
    name = "Useless Suspense Boundary"
    description = "Detects Suspense boundaries that wrap only synchronous components"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".tsx", ".ts", ".jsx", ".js"]
    severity_weight = 2
    confidence = "low"
    fix_suggestion = "Remove Suspense boundaries that do not wrap lazy-loaded components. Suspense without a lazy or suspense-enabled data source never activates and adds misleading complexity."
    examples = {"bad": "<Suspense fallback={...}><Profile /></Suspense>", "good": "const Profile = React.lazy(...); <Suspense><Profile /></Suspense>"}
    priority = 4
    group = "React Stability"
    applies_to = ["react-component"]
    references = ["React Suspense"]
    related_rules = ["lazy-without-suspense", "suspense-fallback-missing"]
    false_positive_notes = "LOW confidence. Some libraries use Suspense in non-obvious ways. Verify before acting."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "quality", "concern": "suspense-boundary"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if "<Suspense" not in (content or ""):
            return []
        if re.search(r"(?:React\.)?lazy\s*\(", content or ""):
            return []
        if re.search(r"suspense\s*:\s*true|useSuspenseQuery|RelayEnvironmentProvider", content or "", re.I):
            return []
        line = (content or "").count("\n", 0, (content or "").find("<Suspense")) + 1
        return [
            self.create_finding(
                title="Suspense boundary has no visible async child",
                file=file_path,
                line_start=line,
                context=f"{file_path}:suspense:{line}",
                description="A Suspense boundary is present, but no lazy component or Suspense-enabled data source was detected.",
                why_it_matters="Suspense only activates when a child suspends. Otherwise it adds misleading complexity.",
                suggested_fix=self.fix_suggestion,
                confidence=0.46,
                tags=["react", "suspense", "stability"],
                evidence_signals=["suspense_boundary=true", "lazy_or_suspense_data_signal=false"],
            ),
        ]
