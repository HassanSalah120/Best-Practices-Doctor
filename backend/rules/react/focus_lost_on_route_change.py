"""Evidence-driven SPA route focus restoration rule."""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class FocusLostOnRouteChangeRule(Rule):
    """Review route lifecycle owners that omit visible focus restoration.

    A Link or router.visit call only initiates navigation. It does not own the
    application-wide post-navigation lifecycle, so absence of focus code beside
    those triggers is not evidence of a defect.
    """

    id = "focus-lost-on-route-change"
    name = "Route Lifecycle Missing Focus Restoration"
    description = "Detects SPA route lifecycle handlers without visible focus restoration"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx"]
    severity_weight = 0
    confidence = "medium"
    fix_suggestion = "Move focus to the new page heading or main landmark after the route transition completes."
    examples = {
        "bad": "router.on('finish', () => announceRoute());",
        "good": "router.on('finish', () => mainRef.current?.focus());",
    }
    priority = 3
    group = "React Accessibility"
    applies_to = ["layout", "react-component"]
    references = ["WCAG 2.4.3 Focus Order"]
    related_rules = []
    false_positive_notes = "Navigation triggers such as Link and router.visit are intentionally ignored; focus is normally owned by one root lifecycle boundary."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "accessibility", "concern": "focus-management"}

    _ROUTE_LIFECYCLE = re.compile(
        r"\b(?:router|inertia)\.on\s*\(\s*['\"](?:navigate|finish|success)['\"]"
        r"|\baddEventListener\s*\(\s*['\"]inertia:(?:navigate|finish|success)['\"]",
        re.IGNORECASE,
    )
    _FOCUS_RESTORATION = re.compile(
        r"\b(?:useFocus\w*|restoreFocus|focusMain|focusHeading)\s*\("
        r"|\.focus\s*\("
        r"|document\.activeElement"
        r"|\bautoFocus\b",
        re.IGNORECASE,
    )

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        text = content or ""
        lifecycle = self._ROUTE_LIFECYCLE.search(text)
        if lifecycle is None or self._FOCUS_RESTORATION.search(text):
            return []
        line = text.count("\n", 0, lifecycle.start()) + 1
        return [
            self.create_finding(
                title="Route lifecycle handler lacks visible focus restoration",
                file=file_path,
                line_start=line,
                context=f"{file_path}:route-lifecycle:{line}",
                description=(
                    "This module owns a completed route-transition lifecycle event, but no focus restoration "
                    "is visible in the same boundary."
                ),
                why_it_matters="Keyboard and screen-reader users need a predictable focus destination after client-side navigation.",
                suggested_fix=self.fix_suggestion,
                confidence=0.84,
                tags=["react", "accessibility", "focus", "routing"],
                evidence_signals=[
                    "route_lifecycle_owner=true",
                    "post_navigation_event=true",
                    "focus_restoration_visible=false",
                ],
            ),
        ]
