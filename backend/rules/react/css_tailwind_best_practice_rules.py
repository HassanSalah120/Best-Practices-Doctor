"""
CSS/Tailwind best-practice rules (low-noise batch).

This batch converts style guidance into enforceable checks with conservative
thresholds to avoid policy spam.
"""

from __future__ import annotations

import re
from typing import Iterable

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


_CLASS_QUOTED_RE = re.compile(r"class(?:Name)?\s*=\s*(['\"])(.*?)\1", re.IGNORECASE | re.DOTALL)
_CLASS_TEMPLATE_RE = re.compile(r"class(?:Name)?\s*=\s*`([^`]*)`", re.IGNORECASE | re.DOTALL)
_TAILWIND_TOKEN_RE = re.compile(r"^[!a-zA-Z0-9:_/\-.\[\]%]+$")
_TAILWIND_ARBITRARY_RE = re.compile(r"\[[^\]]+\]")
_PX_VALUE_RE = re.compile(r"(-?\d+(?:\.\d+)?)px\b", re.IGNORECASE)


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


def _split_tailwind_tokens(class_value: str) -> list[str]:
    out: list[str] = []
    for token in re.split(r"\s+", class_value.strip()):
        t = token.strip()
        if not t:
            continue
        if not _TAILWIND_TOKEN_RE.match(t):
            continue
        out.append(t)
    return out


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
                    evidence_signals=[f"property=font-size", f"value={value}"],
                )
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
                )
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
                )
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
        min_count = max(2, int(self.get_threshold("min_arbitrary_count", 3)))
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for line, class_value in _iter_static_class_attrs(content or ""):
            if len(findings) >= max_findings:
                break
            tokens = _split_tailwind_tokens(class_value)
            arbitrary_tokens = [t for t in tokens if _token_has_arbitrary(t)]
            if len(arbitrary_tokens) < min_count:
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
                )
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
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for line, class_value in _iter_static_class_attrs(content or ""):
            if len(findings) >= max_findings:
                break
            tokens = _split_tailwind_tokens(class_value)
            bad = [t for t in tokens if self._TEXT_ARBITRARY_RE.match(t)]
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
                )
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
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for line, class_value in _iter_static_class_attrs(content or ""):
            if len(findings) >= max_findings:
                break
            tokens = _split_tailwind_tokens(class_value)
            bad = [t for t in tokens if self._SPACING_ARBITRARY_RE.match(t)]
            if not bad:
                continue
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
                    suggested_fix="Prefer built-in spacing scale (`p-*`, `m-*`, `gap-*`, `space-*`) before arbitrary spacing.",
                    confidence=0.89,
                    tags=["tailwind", "spacing", "design-system"],
                    evidence_signals=[f"line={line}", f"token_count={len(bad)}"],
                )
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
        min_px = float(self.get_threshold("min_px", 200))
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for line, class_value in _iter_static_class_attrs(content or ""):
            if len(findings) >= max_findings:
                break
            tokens = _split_tailwind_tokens(class_value)
            bad: list[str] = []
            for token in tokens:
                if not self._LAYOUT_ARBITRARY_RE.match(token):
                    continue
                px = _extract_px_from_token(token)
                if px is None:
                    continue
                if abs(px) < min_px:
                    continue
                bad.append(token)
            if not bad:
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
                )
            )
        return findings


class TailwindArbitraryRadiusShadowRule(Rule):
    id = "tailwind-arbitrary-radius-shadow"
    name = "Tailwind Arbitrary Radius/Shadow"
    description = "Detects arbitrary rounded/shadow values where scale tokens are preferred"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _RADIUS_SHADOW_RE = re.compile(
        r"^(?:[a-z0-9-]+:)*(?:rounded(?:-[trblxy]{1,2})?|shadow)-\[[^\]]+\]$",
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
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))

        for line, class_value in _iter_static_class_attrs(content or ""):
            if len(findings) >= max_findings:
                break
            tokens = _split_tailwind_tokens(class_value)
            bad = [t for t in tokens if self._RADIUS_SHADOW_RE.match(t)]
            if not bad:
                continue
            findings.append(
                self.create_finding(
                    title="Tailwind arbitrary radius/shadow token detected",
                    file=file_path,
                    line_start=line,
                    context=f"line:{line}",
                    description=f"Found arbitrary radius/shadow token(s): {', '.join(bad[:3])}.",
                    why_it_matters=(
                        "Surface consistency improves when radius and elevation come from a small shared token set."
                    ),
                    suggested_fix="Prefer built-in radius/shadow utilities (`rounded-*`, `shadow-*`) before arbitrary values.",
                    confidence=0.87,
                    tags=["tailwind", "surface", "design-system"],
                    evidence_signals=[f"line={line}", f"token_count={len(bad)}"],
                )
            )
        return findings
