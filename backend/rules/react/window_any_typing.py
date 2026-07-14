"""
Window Any Typing Rule

Detects `(window as any).property` or `(window as unknown as any).property`
patterns in TypeScript/TSX files. While sometimes intentional for third-party
script integration, this pattern bypasses TypeScript type safety on the global
window object.

LOW confidence — legitimate use cases include third-party analytics, payment
widgets, and feature flags injected at runtime.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class WindowAnyTypingRule(Rule):
    id = "window-any-typing"
    name = "Window Any Typing"
    description = "Detects `(window as any)` or `(window as unknown as any)` patterns in TypeScript"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    type = "regex"
    regex_file_extensions = [".ts", ".tsx"]
    severity_weight = 2
    confidence = "low"
    fix_suggestion = (
        "Declare a typed global interface for window extensions instead of using `as any`:\n"
        "```typescript\n"
        "declare global {\n"
        "  interface Window {\n"
        "    appName: string;\n"
        "  }\n"
        "}\n"
        "```\n"
        "Then use `window.appName` directly with full type safety."
    )
    examples = {
        "bad": "const appName = (window as any).appName;",
        "good": "const appName = window.appName;  // with global.d.ts declaration",
    }
    priority = 3
    group = "Code Quality"
    applies_to = ["react-component"]
    references = ["TypeScript: Global Augmentation"]
    related_rules = ["typescript-type-check", "missing-props-type"]
    false_positive_notes = (
        "Legitimate for third-party SDK integration (Stripe, Google Analytics, "
        "chat widgets) where no type declarations exist. Suppress per-file if intentional."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "quality", "concern": "typescript-typing"}

    _WINDOW_AS_ANY = re.compile(
        r"\(?\bwindow\b\s+as\s+(?:unknown\s+as\s+)?any\)?\s*\.\s*\w+",
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
        if "/tests/" in norm or "/node_modules/" in norm:
            return []

        findings: list[Finding] = []
        for match in self._WINDOW_AS_ANY.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            snippet = match.group(0).strip()[:80]
            findings.append(
                self.create_finding(
                    title="Window accessed via `as any` cast",
                    context=snippet,
                    file=file_path,
                    line_start=line,
                    description=(
                        "The global `window` object is accessed with an `as any` cast "
                        "instead of a typed global declaration. This bypasses type safety."
                    ),
                    why_it_matters=(
                        "Typed window access prevents runtime errors from misspelled property names "
                        "and makes the contract with third-party scripts explicit."
                    ),
                    suggested_fix=self.fix_suggestion,
                    confidence=0.55,
                    tags=["react", "typescript", "type-safety", "quality"],
                    evidence_signals=[
                        "window_any_cast=true",
                        f"snippet={snippet}",
                    ],
                ),
            )

        return findings
