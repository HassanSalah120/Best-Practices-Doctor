"""Animation no pause control rule."""
from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class AnimationNoPauseControlRule(Rule):
    id = "animation-no-pause-control"
    name = "Animation No Pause Control"
    description = "Detects animation utilities without reduced-motion variants or pause controls"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".jsx", ".tsx"]
    severity_weight = 5
    confidence = "medium"
    fix_suggestion = "Use motion-safe: and motion-reduce: Tailwind variants. Users with vestibular disorders need to be able to stop or reduce animations."
    examples = {"bad": "className=\"animate-spin\"", "good": "className=\"motion-safe:animate-spin\""}
    priority = 3
    group = "React Accessibility"
    applies_to = ["react-component"]
    references = ["WCAG 2.2.2 Pause Stop Hide"]
    related_rules = []
    false_positive_notes = "One-time short animations and reduced-motion variants are skipped."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "accessibility", "concern": "motion"}
    _ANIM = re.compile(r"className=\{?['\"][^'\"]*\banimate-[\w-]+|animation\s*:", re.IGNORECASE)
    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]: return []
    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if 'motion-safe:' in content or 'motion-reduce:' in content or 'prefers-reduced-motion' in content: return []
        findings=[]
        for m in self._ANIM.finditer(content):
            snippet=content[m.start():m.start()+120]
            if 'animate-once' in snippet or 'animate-fade-in' in snippet or re.search(r"duration-(?:75|100|150)\b", snippet): continue
            line=content.count('\n',0,m.start())+1
            findings.append(self.create_finding("Animation lacks reduced-motion or pause control", file_path, line, "An animation class/style is used without reduced-motion handling.", "Users with vestibular disorders need motion reduced or stoppable for non-essential animation.", self.fix_suggestion, context=f"{file_path}:{line}", confidence=0.7, tags=["react", "accessibility", "motion"]))
        return findings
