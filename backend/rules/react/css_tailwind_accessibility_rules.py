"""
Accessibility-focused CSS/Tailwind rules.
"""

from __future__ import annotations

import re
from typing import Iterable

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, Severity
from rules.base import Rule


_CLASS_QUOTED_RE = re.compile(r"class(?:Name)?\s*=\s*(['\"])(.*?)\1", re.IGNORECASE | re.DOTALL)
_CLASS_TEMPLATE_RE = re.compile(r"class(?:Name)?\s*=\s*`([^`]*)`", re.IGNORECASE | re.DOTALL)


def _line_of_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _iter_static_class_attrs(content: str) -> Iterable[tuple[int, str]]:
    for match in _CLASS_QUOTED_RE.finditer(content):
        value = (match.group(2) or "").strip()
        if not value or "${" in value:
            continue
        yield _line_of_offset(content, match.start()), value
    for match in _CLASS_TEMPLATE_RE.finditer(content):
        value = (match.group(1) or "").strip()
        if not value or "${" in value:
            continue
        yield _line_of_offset(content, match.start()), value


class TailwindMotionReduceMissingRule(Rule):
    id = "tailwind-motion-reduce-missing"
    name = "Tailwind Motion Reduce Missing"
    description = "Detects animation-heavy class strings without motion-safe/motion-reduce variants"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        for line, class_value in _iter_static_class_attrs(content or ""):
            if len(findings) >= max_findings:
                break
            tokens = class_value.split()
            motion_tokens = [t for t in tokens if t.startswith("animate-")]
            if not motion_tokens:
                continue
            if any(t.startswith("motion-safe:") or t.startswith("motion-reduce:") for t in tokens):
                continue
            findings.append(
                self.create_finding(
                    title="Animation classes found without motion-reduce/motion-safe variant",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:{line}",
                    description=f"Found animation utility tokens without reduced-motion companion: {', '.join(motion_tokens[:3])}.",
                    why_it_matters="Users with reduced-motion preferences should be able to avoid non-essential animation.",
                    suggested_fix="Add `motion-reduce:` fallback or `motion-safe:` guard to animation classes.",
                    tags=["tailwind", "a11y", "motion", "wcag"],
                    confidence=0.9,
                    evidence_signals=["animation_tokens_present=true", "motion_reduce_variant_missing=true"],
                )
            )
        return findings


class TailwindAppearanceNoneRiskRule(Rule):
    id = "tailwind-appearance-none-risk"
    name = "Tailwind Appearance None Risk"
    description = "Flags appearance-none on form controls without compensating focus/usability cues"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _CONTROL_TAG_RE = re.compile(
        r"<(?P<tag>input|select|textarea)\b(?P<attrs>[^>]*)>",
        re.IGNORECASE | re.DOTALL,
    )

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        text = content or ""
        for m in self._CONTROL_TAG_RE.finditer(text):
            if len(findings) >= max_findings:
                break
            attrs = m.group("attrs") or ""
            if "appearance-none" not in attrs:
                continue
            has_focus = bool(re.search(r"focus:|focus-visible:|ring-|outline-", attrs))
            has_visual = bool(re.search(r"border|bg-|px-|py-|h-|w-", attrs))
            if has_focus and has_visual:
                continue
            line = text.count("\n", 0, m.start()) + 1
            findings.append(
                self.create_finding(
                    title="appearance-none used without strong accessibility affordances",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:{line}",
                    description="Form control uses `appearance-none` but lacks clear focus/visual affordance signals.",
                    why_it_matters="Removing native control appearance can reduce usability in forced-colors/high-contrast and keyboard modes.",
                    suggested_fix="Add explicit focus-visible, border/background, and control affordances, or keep native appearance.",
                    tags=["tailwind", "a11y", "forms", "wcag"],
                    confidence=0.88,
                    evidence_signals=[f"focus_affordance_present={int(has_focus)}", f"visual_affordance_present={int(has_visual)}"],
                )
            )
        return findings


class CssFocusOutlineWithoutReplacementRule(Rule):
    id = "css-focus-outline-without-replacement"
    name = "CSS Focus Outline Without Replacement"
    description = "Detects focus styles that remove outline without visible replacement"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".css", ".scss", ".sass", ".less"]

    _BLOCK_RE = re.compile(r"(?P<selector>[^{]+)\{(?P<body>[^}]*)\}", re.IGNORECASE | re.DOTALL)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        for m in self._BLOCK_RE.finditer(content or ""):
            if len(findings) >= max_findings:
                break
            selector = (m.group("selector") or "").strip()
            body = (m.group("body") or "").strip()
            if ":focus" not in selector and ":focus-visible" not in selector:
                continue
            if not re.search(r"outline\s*:\s*(none|0)\b", body, re.IGNORECASE):
                continue
            has_replacement = bool(re.search(r"box-shadow\s*:|border\s*:|outline\s*:\s*\d+|outline-color\s*:", body, re.IGNORECASE))
            if has_replacement:
                continue
            line = _line_of_offset(content or "", m.start())
            findings.append(
                self.create_finding(
                    title="Focus outline removed without replacement in CSS",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:{line}",
                    description=f"Selector `{selector}` removes focus outline without visible replacement.",
                    why_it_matters="Keyboard users rely on visible focus indication to navigate interfaces.",
                    suggested_fix="Keep native outline or add a strong custom focus-visible style.",
                    tags=["css", "a11y", "focus", "wcag"],
                    confidence=0.95,
                    evidence_signals=["focus_outline_removed=true", "focus_replacement_missing=true"],
                )
            )
        return findings


class CssHoverOnlyInteractionRule(Rule):
    id = "css-hover-only-interaction"
    name = "CSS Hover-Only Interaction"
    description = "Detects hover interaction selectors without corresponding focus styles"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".css", ".scss", ".sass", ".less"]

    _BLOCK_RE = re.compile(r"(?P<selector>[^{]+)\{(?P<body>[^}]*)\}", re.IGNORECASE | re.DOTALL)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        text = content or ""
        hover_bases: set[str] = set()
        focus_bases: set[str] = set()
        for m in self._BLOCK_RE.finditer(text):
            selector = (m.group("selector") or "").strip()
            base = selector.replace(":hover", "").replace(":focus-visible", "").replace(":focus", "").strip()
            if ":hover" in selector:
                hover_bases.add(base)
            if ":focus" in selector or ":focus-visible" in selector:
                focus_bases.add(base)

        offenders = sorted(base for base in hover_bases if base and base not in focus_bases)
        if not offenders:
            return []
        line = 1
        return [
            self.create_finding(
                title="Hover-only interaction styles detected without focus equivalent",
                file=file_path,
                line_start=line,
                context=f"{file_path}:{line}",
                description=f"Selectors have `:hover` interaction styles without matching focus selectors: {', '.join(offenders[:3])}.",
                why_it_matters="Keyboard users need equivalent interaction feedback when an element receives focus.",
                suggested_fix="Add `:focus`/`:focus-visible` styles mirroring hover interaction affordances.",
                tags=["css", "a11y", "keyboard", "wcag"],
                confidence=0.88,
                evidence_signals=["hover_styles_present=true", "focus_equivalent_missing=true"],
            )
        ]


class CssColorOnlyStateIndicatorRule(Rule):
    id = "css-color-only-state-indicator"
    name = "CSS Color-Only State Indicator"
    description = "Detects likely state/error indicators conveyed only by color"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".css", ".scss", ".sass", ".less"]

    _BLOCK_RE = re.compile(r"(?P<selector>[^{]+)\{(?P<body>[^}]*)\}", re.IGNORECASE | re.DOTALL)
    _STATE_SELECTOR_RE = re.compile(r"(error|invalid|required|active|selected|warning|success)", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        for m in self._BLOCK_RE.finditer(content or ""):
            if len(findings) >= max_findings:
                break
            selector = (m.group("selector") or "").strip()
            if not self._STATE_SELECTOR_RE.search(selector):
                continue
            body = (m.group("body") or "").strip()
            lines = [x.strip().lower() for x in body.split(";") if x.strip()]
            if not lines:
                continue
            color_only = all(
                line.startswith("color:")
                or line.startswith("background")
                or line.startswith("border-color")
                for line in lines
            )
            has_non_color_signal = any(
                line.startswith("content:")
                or line.startswith("font-weight")
                or line.startswith("text-decoration")
                or line.startswith("outline")
                for line in lines
            )
            if not color_only or has_non_color_signal:
                continue
            line = _line_of_offset(content or "", m.start())
            findings.append(
                self.create_finding(
                    title="State indicator may rely on color alone",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:{line}",
                    description=f"Selector `{selector}` appears to indicate state using color-only styling.",
                    why_it_matters="State and error information should not rely on color alone.",
                    suggested_fix="Add non-color cues such as iconography, text, weight, or pattern changes for state communication.",
                    tags=["css", "a11y", "wcag", "contrast"],
                    confidence=0.84,
                    evidence_signals=["state_selector_detected=true", "color_only_signal=true"],
                )
            )
        return findings

