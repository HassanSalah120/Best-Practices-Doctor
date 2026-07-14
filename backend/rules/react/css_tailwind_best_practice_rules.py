"""
CSS/Tailwind best-practice rules (low-noise batch).

This batch converts style guidance into enforceable checks with conservative
thresholds to avoid policy spam.
"""

from __future__ import annotations

import re

from core.tailwind_analysis import (
    has_tailwind_evidence,
    iter_static_class_values,
    split_tailwind_tokens,
    tailwind_base_utility,
)
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

_TAILWIND_ARBITRARY_RE = re.compile(r"\[[^\]]+\]")
_PX_VALUE_RE = re.compile(r"(-?\d+(?:\.\d+)?)px\b", re.IGNORECASE)


def _line_of_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _iter_static_class_attrs(content: str):
    for item in iter_static_class_values(content):
        yield item.line, item.value


def _split_tailwind_tokens(class_value: str) -> list[str]:
    return split_tailwind_tokens(class_value)


def _token_has_arbitrary(token: str) -> bool:
    return bool(_TAILWIND_ARBITRARY_RE.search(token))


def _extract_px_from_token(token: str) -> float | None:
    match = _PX_VALUE_RE.search(token)
    if not match:
        return None
    try:
        return float(match.group(1))
    except Exception:
        return None


def _is_structural_arbitrary_exception(token: str) -> bool:
    """Identify arbitrary syntax with no behavior-preserving scale equivalent."""
    low = str(token or "").lower().replace("_", " ")
    return any(
        marker in low
        for marker in (
            "var(",
            "theme(",
            "calc(",
            "min(",
            "max(",
            "clamp(",
            "linear-gradient(",
            "radial-gradient(",
            "conic-gradient(",
            "rgb(from ",
            "hsl(from ",
            "url(",
        )
    )


class CssFontSizePxRule(Rule):
    id = "css-font-size-px"
    name = "CSS Font Size Uses px"
    description = "Detects font-size declared in px instead of rem"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".css", ".scss", ".sass", ".less"]

    _FONT_SIZE_RE = re.compile(r"\bfont-size\s*:\s*([^;]+);", re.IGNORECASE)
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the css font size uses px pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'css-font-size'}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_px = float(self.get_threshold("min_px", 12))
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for match in self._FONT_SIZE_RE.finditer(content or ""):
            if len(findings) >= max_findings:
                break
            value = (match.group(1) or "").strip()
            if "rem" in value.lower():
                continue
            px_match = _PX_VALUE_RE.search(value)
            if not px_match:
                continue
            try:
                px = float(px_match.group(1))
            except Exception:
                continue
            if abs(px) < min_px:
                continue

            rem = round(px / 16.0, 4)
            line = _line_of_offset(content, match.start())
            findings.append(
                self.create_finding(
                    title="font-size uses px instead of rem",
                    file=file_path,
                    line_start=line,
                    context=f"line:{line}",
                    description=f"`font-size: {value}` uses px sizing.",
                    why_it_matters=(
                        "Text sizing in rem scales better with zoom and accessibility settings, and supports a consistent "
                        "typography system."
                    ),
                    suggested_fix=f"Prefer rem for typography, e.g. `font-size: {rem}rem;`.",
                    confidence=0.9,
                    tags=["css", "typography", "units", "accessibility"],
                    evidence_signals=["property=font-size", f"value={value}"],
                ),
            )
        return findings


class CssSpacingPxRule(Rule):
    id = "css-spacing-px"
    name = "CSS Spacing Uses px"
    description = "Detects margin/padding/gap spacing declared in px instead of rem scale"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".css", ".scss", ".sass", ".less"]

    _SPACING_RE = re.compile(
        r"\b(margin(?:-[a-z-]+)?|padding(?:-[a-z-]+)?|gap|row-gap|column-gap)\s*:\s*([^;]+);",
        re.IGNORECASE,
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the css spacing uses px pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'css-spacing-px'}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_px = float(self.get_threshold("min_px", 8))
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 4)))

        for match in self._SPACING_RE.finditer(content or ""):
            if len(findings) >= max_findings:
                break
            prop = (match.group(1) or "").strip().lower()
            value = (match.group(2) or "").strip()
            if "rem" in value.lower():
                continue
            px_values = []
            for px_match in _PX_VALUE_RE.finditer(value):
                try:
                    px_values.append(float(px_match.group(1)))
                except Exception:
                    continue
            if not px_values:
                continue
            if max(abs(x) for x in px_values) < min_px:
                continue

            line = _line_of_offset(content, match.start())
            findings.append(
                self.create_finding(
                    title="spacing utility uses px instead of rem scale",
                    file=file_path,
                    line_start=line,
                    context=f"line:{line}",
                    description=f"`{prop}: {value}` uses px spacing.",
                    why_it_matters=(
                        "Spacing rhythm is easier to keep consistent and accessible when it follows a shared rem-based scale."
                    ),
                    suggested_fix="Prefer rem-based spacing tokens for margin/padding/gap values.",
                    confidence=0.88,
                    tags=["css", "spacing", "units", "design-system"],
                    evidence_signals=[f"property={prop}", f"value={value}"],
                ),
            )
        return findings


class CssFixedLayoutPxRule(Rule):
    id = "css-fixed-layout-px"
    name = "CSS Fixed Layout px Dimensions"
    description = "Detects rigid large px width/height values in layout declarations"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".css", ".scss", ".sass", ".less"]

    _LAYOUT_RE = re.compile(
        r"\b(width|height|min-width|min-height|max-width|max-height)\s*:\s*(-?\d+(?:\.\d+)?)px\b",
        re.IGNORECASE,
    )
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Refactor the component code to remove the css fixed layout px dimensions pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 4
    group = 'Code Quality'
    applies_to = ['react-component', 'layout']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'css-fixed-layout'}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_px = float(self.get_threshold("min_px", 240))
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for match in self._LAYOUT_RE.finditer(content or ""):
            if len(findings) >= max_findings:
                break
            prop = (match.group(1) or "").strip().lower()
            try:
                px_value = float(match.group(2))
            except Exception:
                continue
            if abs(px_value) < min_px:
                continue
            line = _line_of_offset(content, match.start())
            findings.append(
                self.create_finding(
                    title="large fixed px layout dimension detected",
                    file=file_path,
                    line_start=line,
                    context=f"line:{line}",
                    description=f"`{prop}: {px_value}px` may be too rigid for responsive layouts.",
                    why_it_matters=(
                        "Rigid large pixel dimensions often break responsive behavior and reduce layout adaptability."
                    ),
                    suggested_fix="Prefer fluid layout patterns (`width: 100%`, `max-width` in rem, grid/flex, minmax).",
                    confidence=0.86,
                    tags=["css", "layout", "responsive"],
                    evidence_signals=[f"property={prop}", f"value_px={px_value}"],
                ),
            )
        return findings


class TailwindArbitraryValueOveruseRule(Rule):
    id = "tailwind-arbitrary-value-overuse"
    name = "Tailwind Arbitrary Value Overuse"
    description = "Detects class strings with excessive arbitrary Tailwind values"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Refactor the component code to remove the tailwind arbitrary value overuse pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 4
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'tailwind-arbitrary-value'}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if not has_tailwind_evidence(facts, content):
            return []
        findings: list[Finding] = []
        min_count = max(2, int(self.get_threshold("min_arbitrary_count", 3)))
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for line, class_value in _iter_static_class_attrs(content or ""):
            if len(findings) >= max_findings:
                break
            tokens = _split_tailwind_tokens(class_value)
            arbitrary_tokens = [
                token
                for token in tokens
                if _token_has_arbitrary(token) and not _is_structural_arbitrary_exception(token)
            ]
            if len(arbitrary_tokens) < min_count:
                continue
            # Skip decorative elements (blur, pointer-events-none, negative z-index)
            if 'blur-' in class_value or 'pointer-events-none' in class_value or '-z-' in class_value:
                continue
            # Skip when all arbitrary values are percentage-based (fluid layout)
            if all('%' in t for t in arbitrary_tokens):
                continue
            # Skip micro-UI elements: badges, pills, counters — elements with
            # very small arbitrary text sizes (< 12px) or dimensions (< 24px)
            px_tokens = [t for t in arbitrary_tokens if _extract_px_from_token(t) is not None]
            if px_tokens:
                px_vals = [_extract_px_from_token(t) for t in px_tokens]
                if all(v is not None and v <= 12 for v in px_vals):
                    continue
            sample = ", ".join(arbitrary_tokens[:4])
            findings.append(
                self.create_finding(
                    title="Tailwind arbitrary values are overused in one class string",
                    file=file_path,
                    line_start=line,
                    context=f"line:{line}",
                    description=f"Found {len(arbitrary_tokens)} arbitrary Tailwind values: {sample}.",
                    why_it_matters=(
                        "Heavy use of arbitrary values weakens design-system consistency and makes UI maintenance harder."
                    ),
                    suggested_fix=(
                        "Use Tailwind scale tokens first, and keep arbitrary values only for strict spec exceptions."
                    ),
                    confidence=0.9,
                    tags=["tailwind", "design-system", "maintainability"],
                    evidence_signals=[f"arbitrary_count={len(arbitrary_tokens)}", f"line={line}"],
                ),
            )
        return findings


class TailwindArbitraryTextSizeRule(Rule):
    id = "tailwind-arbitrary-text-size"
    name = "Tailwind Arbitrary Text Size"
    description = "Detects text-[..px] arbitrary sizing instead of Tailwind text scale"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _TEXT_ARBITRARY_RE = re.compile(r"^(?:[a-z0-9-]+:)*text-\[[^\]]+\]$", re.IGNORECASE)
    # Known Tailwind text scale values in px — values not in this set have no scale equivalent
    _TAILWIND_TEXT_SCALE_PX = frozenset({
        12, 14, 16, 18, 20, 24, 30, 36, 48, 60, 72, 96,
    })
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the tailwind arbitrary text size pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'tailwind-arbitrary-text'}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if not has_tailwind_evidence(facts, content):
            return []
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for line, class_value in _iter_static_class_attrs(content or ""):
            if len(findings) >= max_findings:
                break
            tokens = _split_tailwind_tokens(class_value)
            bad = [t for t in tokens if self._TEXT_ARBITRARY_RE.match(tailwind_base_utility(t))]
            if not bad:
                continue
            # Skip sizes below 12px (Tailwind scale has gap between xs/12px and sm/14px)
            # Also skip values that have no exact scale equivalent (between-scale design choices)
            filtered = []
            for t in bad:
                px_value = _extract_px_from_token(t)
                # Only suggest a built-in utility when there is an exact px
                # scale equivalent. CSS variables, other units, and Tailwind
                # theme expressions are legitimate arbitrary-value uses.
                if px_value is None:
                    continue
                if px_value <= 11:
                    continue
                # Skip values not in the Tailwind text scale — they're intentional between-scale choices
                if px_value not in self._TAILWIND_TEXT_SCALE_PX:
                    continue
                filtered.append(t)
            bad = filtered
            if not bad:
                continue
            findings.append(
                self.create_finding(
                    title="Tailwind arbitrary text size detected",
                    file=file_path,
                    line_start=line,
                    context=f"line:{line}",
                    description=f"Found arbitrary text size token(s): {', '.join(bad[:3])}.",
                    why_it_matters=(
                        "Typography is more predictable and maintainable when it uses a small, shared text scale."
                    ),
                    suggested_fix="Prefer built-in text scale utilities (`text-sm`..`text-3xl`) before arbitrary text values.",
                    confidence=0.9,
                    tags=["tailwind", "typography", "design-system"],
                    evidence_signals=[f"line={line}", f"token_count={len(bad)}"],
                ),
            )
        return findings


class TailwindArbitrarySpacingRule(Rule):
    id = "tailwind-arbitrary-spacing"
    name = "Tailwind Arbitrary Spacing"
    description = "Detects p/m/gap/space arbitrary spacing values"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _SPACING_ARBITRARY_RE = re.compile(
        r"^(?:[a-z0-9-]+:)*(?:p|px|py|pt|pb|pl|pr|m|mx|my|mt|mb|ml|mr|gap|gap-x|gap-y|space-x|space-y)-\[[^\]]+\]$",
        re.IGNORECASE,
    )
    # Known Tailwind spacing scale values in px — values not in this set have no scale equivalent
    _TAILWIND_SPACING_SCALE_PX = frozenset({
        0, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32, 36, 40, 44, 48,
        56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
        288, 320, 384,
    })
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the tailwind arbitrary spacing pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'tailwind-arbitrary-spacing'}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if not has_tailwind_evidence(facts, content):
            return []
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for line, class_value in _iter_static_class_attrs(content or ""):
            if len(findings) >= max_findings:
                break
            tokens = _split_tailwind_tokens(class_value)
            bad = [t for t in tokens if self._SPACING_ARBITRARY_RE.match(tailwind_base_utility(t))]
            # Only report values for which a direct built-in replacement is
            # knowable. Custom properties, percentages, other CSS units,
            # between-scale values, and <=4px optical adjustments are valid.
            bad = [
                token
                for token in bad
                if (px := _extract_px_from_token(token)) is not None
                and abs(px) > 4
                and abs(px) in self._TAILWIND_SPACING_SCALE_PX
            ]
            if not bad:
                continue
            replacements: list[str] = []
            for token in bad:
                px = abs(float(_extract_px_from_token(token) or 0.0))
                scale = px / 4.0
                scale_text = str(int(scale)) if scale.is_integer() else str(scale).rstrip("0").rstrip(".")
                base = tailwind_base_utility(token)
                utility = base.split("-[", 1)[0]
                replacements.append(f"{token} -> {utility}-{scale_text}")
            findings.append(
                self.create_finding(
                    title="Tailwind arbitrary spacing detected",
                    file=file_path,
                    line_start=line,
                    context=f"line:{line}",
                    description=f"Found arbitrary spacing token(s): {', '.join(bad[:3])}.",
                    why_it_matters=(
                        "Spacing consistency is stronger when components share the Tailwind spacing scale."
                    ),
                    suggested_fix=(
                        "Use the exact Tailwind spacing-scale equivalent: "
                        + ", ".join(replacements[:3])
                        + "."
                    ),
                    confidence=0.89,
                    tags=["tailwind", "spacing", "design-system"],
                    evidence_signals=[
                        f"line={line}",
                        f"token_count={len(bad)}",
                        *[f"replacement={item}" for item in replacements[:3]],
                    ],
                ),
            )
        return findings


class TailwindArbitraryLayoutSizeRule(Rule):
    id = "tailwind-arbitrary-layout-size"
    name = "Tailwind Arbitrary Layout Size"
    description = "Detects rigid arbitrary width/height Tailwind values"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _LAYOUT_ARBITRARY_RE = re.compile(
        r"^(?:[a-z0-9-]+:)*(?:w|h|min-w|min-h|max-w|max-h)-\[[^\]]+\]$",
        re.IGNORECASE,
    )
    # Known Tailwind spacing scale values in px — layout (w/h/min-w/max-w) uses the same scale
    _TAILWIND_LAYOUT_SCALE_PX = frozenset({
        0, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32, 36, 40, 44, 48,
        56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
        288, 320, 384,
    })
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Refactor the component code to remove the tailwind arbitrary layout size pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 4
    group = 'Code Quality'
    applies_to = ['react-component', 'layout']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'tailwind-arbitrary-layout'}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if not has_tailwind_evidence(facts, content):
            return []
        findings: list[Finding] = []
        min_px = float(self.get_threshold("min_px", 200))
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for line, class_value in _iter_static_class_attrs(content or ""):
            if len(findings) >= max_findings:
                break
            tokens = _split_tailwind_tokens(class_value)
            bad: list[str] = []
            for token in tokens:
                if not self._LAYOUT_ARBITRARY_RE.match(tailwind_base_utility(token)):
                    continue
                px = _extract_px_from_token(token)
                if px is None:
                    continue
                if abs(px) < min_px:
                    continue
                # Skip values not in the Tailwind layout scale (between-scale intentional design)
                if int(px) not in self._TAILWIND_LAYOUT_SCALE_PX:
                    continue
                bad.append(token)
            if not bad:
                continue
            # Skip decorative elements (blur, pointer-events-none, negative z-index)
            if 'blur-' in class_value or 'pointer-events-none' in class_value or '-z-' in class_value:
                continue
            # Skip fixed sidebar/panel sizes (intentionally designed fixed-width panels)
            if 'sticky' in class_value or 'shrink-0' in class_value or 'overflow-hidden' in class_value:
                continue
            findings.append(
                self.create_finding(
                    title="Tailwind arbitrary layout dimension detected",
                    file=file_path,
                    line_start=line,
                    context=f"line:{line}",
                    description=f"Found rigid arbitrary layout token(s): {', '.join(bad[:3])}.",
                    why_it_matters=(
                        "Large fixed dimensions reduce responsiveness and often create layout breakpoints that are hard to maintain."
                    ),
                    suggested_fix="Prefer fluid sizing (`w-full`, `max-w-*`, grid/flex) for reusable responsive components.",
                    confidence=0.88,
                    tags=["tailwind", "layout", "responsive"],
                    evidence_signals=[f"line={line}", f"token_count={len(bad)}"],
                ),
            )
        return findings


class TailwindArbitraryRadiusShadowRule(Rule):
    id = "tailwind-arbitrary-radius-shadow"
    name = "Tailwind Arbitrary Radius Has Scale Equivalent"
    description = "Detects arbitrary radius values with an exact built-in Tailwind equivalent"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _RADIUS_SHADOW_RE = re.compile(
        r"^(?:[a-z0-9-]+:)*(?:rounded(?:-[trblxy]{1,2})?|shadow)-\[[^\]]+\]$",
        re.IGNORECASE,
    )
    _RADIUS_SCALE_PX = frozenset({0, 2, 4, 6, 8, 12, 16, 24})
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Replace arbitrary radius values only when an exact built-in rounded-* scale equivalent exists.'
    examples = {}
    priority = 4
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = 'Arbitrary shadows are intentionally excluded because no behavior-preserving built-in equivalent can be inferred locally.'
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'tailwind-arbitrary-radius'}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if not has_tailwind_evidence(facts, content):
            return []
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        entries = list(_iter_static_class_attrs(content or ""))

        for line, class_value in entries:
            if len(findings) >= max_findings:
                break
            tokens = _split_tailwind_tokens(class_value)
            bad: list[str] = []
            for token in tokens:
                base = tailwind_base_utility(token)
                if not self._RADIUS_SHADOW_RE.match(base):
                    continue
                if base.startswith("shadow-["):
                    # No behavior-preserving built-in equivalent can be
                    # inferred for arbitrary shadow geometry. Project-wide
                    # repetition belongs in a separate token-consolidation
                    # rule, not one finding at every JSX location.
                    continue
                px = _extract_px_from_token(token)
                if px is not None and abs(px) in self._RADIUS_SCALE_PX:
                    bad.append(token)
            if not bad:
                continue
            # Skip focus ring/shadow patterns — these are accessibility-
            # required focus indicators, not design-system arbitrary values
            if any("focus:" in t for t in bad):
                continue
            findings.append(
                self.create_finding(
                    title="Tailwind arbitrary radius has an exact scale equivalent",
                    file=file_path,
                    line_start=line,
                    context=f"line:{line}",
                    description=f"Found arbitrary radius token(s) with exact built-in equivalents: {', '.join(bad[:3])}.",
                    why_it_matters=(
                        "Surface consistency improves when radius values use the shared Tailwind scale."
                    ),
                    suggested_fix="Replace the arbitrary radius with its exact built-in `rounded-*` scale equivalent.",
                    confidence=0.87,
                    tags=["tailwind", "surface", "design-system"],
                    evidence_signals=[f"line={line}", f"token_count={len(bad)}"],
                ),
            )
        return findings
