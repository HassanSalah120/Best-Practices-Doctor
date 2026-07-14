from __future__ import annotations

import re

from core.semantic_roles import is_blade_component_source
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class BladeComponentNoFallbackSlotRule(Rule):
    id = "blade-component-no-fallback-slot"
    name = "Blade Component No Fallback Slot"
    description = "Detects anonymous Blade components that render $slot without a fallback or empty-state guard"
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".blade.php"]
    severity_weight = 2
    confidence = "low"
    fix_suggestion = "Guard slot usage with @isset($slot) or provide a default: {{ $slot ?? 'Default content' }}. This prevents silent empty renders when slot is omitted."
    examples = {"bad": "<div>{{ $slot }}</div>", "good": "@if(!$slot->isEmpty()) {{ $slot }} @else Default @endif"}
    priority = 4
    group = "Code Quality"
    applies_to = ["blade"]
    references = ["Laravel Blade Components"]
    related_rules = []
    false_positive_notes = "Many slot usages are intentionally empty-capable. Review context before acting."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "quality", "concern": "blade-slot-fallback"}

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
        if not is_blade_component_source(file_path, content, facts) or "layout" in norm:
            return []
        if "<html" in (content or "").lower():
            return []
        if "{{ $slot }}" not in (content or ""):
            return []
        if re.search(r"@isset\s*\(\s*\$slot\s*\)|\$slot\s*\?\?|\$slot->is(?:Not)?Empty\s*\(|@empty\s*\(\s*\$slot\s*\)", content or ""):
            return []
        line = (content or "").count("\n", 0, (content or "").find("{{ $slot }}")) + 1
        return [
            self.create_finding(
                title="Blade component slot has no fallback",
                file=file_path,
                line_start=line,
                context=f"{file_path}:slot",
                description="This anonymous Blade component renders $slot directly without an empty-slot guard or fallback.",
                why_it_matters="Callers can omit required content and get a silently empty render.",
                suggested_fix=self.fix_suggestion,
                confidence=0.60,
                tags=["laravel", "blade", "component"],
                evidence_signals=["slot_rendered=true", "fallback_guard=false"],
            ),
        ]
