"""
Touch Target Size Rule (deterministic evidence only).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class TouchTargetSizeRule(Rule):
    id = "touch-target-size"
    name = "Touch Target Size"
    description = "Detects interactive controls with explicit size below 44x44px"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
    )
    _INTERACTIVE_RE = re.compile(
        r"<(?P<tag>button|a|input|select|textarea|summary)\b(?P<attrs>[^>]*)>",
        re.IGNORECASE | re.DOTALL,
    )
    _W_RE = re.compile(r"\bw-(?P<v>\d+)\b")
    _H_RE = re.compile(r"\bh-(?P<v>\d+)\b")
    _SIZE_RE = re.compile(r'\bsize=["\'](?P<v>\d+)["\']', re.IGNORECASE)
    _W_STYLE_RE = re.compile(r"width\s*:\s*(?P<v>\d+)\s*(?:px)?", re.IGNORECASE)
    _H_STYLE_RE = re.compile(r"height\s*:\s*(?P<v>\d+)\s*(?:px)?", re.IGNORECASE)
    _TW_SIZE_MAP = {
        "0": 0,
        "1": 4,
        "2": 8,
        "3": 12,
        "4": 16,
        "5": 20,
        "6": 24,
        "7": 28,
        "8": 32,
        "9": 36,
        "10": 40,
        "11": 44,
        "12": 48,
    }

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
        if self._is_allowlisted_path(file_path):
            return []

        min_touch = int(self.get_threshold("min_touch_target_px", 44))
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 3)))
        text = content or ""

        for m in self._INTERACTIVE_RE.finditer(text):
            if len(findings) >= max_findings:
                break
            attrs = m.group("attrs") or ""
            tag = (m.group("tag") or "").lower()
            width, height, source = self._extract_explicit_size(attrs)
            if width is None or height is None:
                continue
            if width >= min_touch and height >= min_touch:
                continue

            line = text.count("\n", 0, m.start()) + 1
            findings.append(
                self.create_finding(
                    title="Explicit touch target size is below 44x44px",
                    context=f"{file_path}:{line}:{tag}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"`<{tag}>` has explicit size `{width}x{height}px` from `{source}`, below "
                        f"the `{min_touch}x{min_touch}px` touch target guideline."
                    ),
                    why_it_matters="Small explicit touch targets are harder to activate for touch and motor-impaired users.",
                    suggested_fix=(
                        "Increase explicit control dimensions to at least 44x44px, or use component primitives with accessible sizing defaults."
                    ),
                    tags=["a11y", "wcag", "touch", "mobile"],
                    confidence=0.94,
                    evidence_signals=[
                        f"width={width}",
                        f"height={height}",
                        f"size_source={source}",
                    ],
                )
            )
        return findings

    def _extract_explicit_size(self, attrs: str) -> tuple[int | None, int | None, str]:
        size_match = self._SIZE_RE.search(attrs)
        if size_match:
            v = int(size_match.group("v"))
            return v, v, "size-attribute"

        w = None
        h = None

        w_m = self._W_RE.search(attrs)
        h_m = self._H_RE.search(attrs)
        if w_m and h_m:
            w = self._TW_SIZE_MAP.get(w_m.group("v"))
            h = self._TW_SIZE_MAP.get(h_m.group("v"))
            if w is not None and h is not None:
                return w, h, "tailwind-wh"

        sw = self._W_STYLE_RE.search(attrs)
        sh = self._H_STYLE_RE.search(attrs)
        if sw and sh:
            return int(sw.group("v")), int(sh.group("v")), "inline-style"

        return None, None, "unknown"

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)

