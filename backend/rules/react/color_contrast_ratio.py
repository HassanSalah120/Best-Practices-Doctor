"""
Color Contrast Ratio Rule

Detects potential color contrast issues in inline styles and Tailwind classes.
Note: This is a heuristic check - actual contrast requires computed styles.
"""

from __future__ import annotations

import re
from typing import Iterable

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ColorContrastRatioRule(Rule):
    id = "color-contrast-ratio"
    name = "Color Contrast Ratio"
    description = "Detects potential color contrast issues in text elements"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Text elements
    _TEXT_PATTERN = re.compile(
        r"<(?P<tag>p|h[1-6]|span|div|li|td|th|label|a|button|small|strong|em)\b(?P<attrs>[^>]*)>",
        re.IGNORECASE,
    )
    
    _CLASS_ATTR = re.compile(r'\b(?:className|class)\s*=\s*["\'](?P<classes>[^"\']+)["\']', re.IGNORECASE)
    _INLINE_COLOR = re.compile(r"(?:^|[,{;]\s*)(?:color)\s*:\s*(?P<color>#[0-9a-fA-F]{3,8}|rgba?\([^)]+\))", re.IGNORECASE)
    _INLINE_BG = re.compile(
        r"(?:^|[,{;]\s*)(?:backgroundColor|background-color|background)\s*:\s*(?P<color>#[0-9a-fA-F]{3,8}|rgba?\([^)]+\))",
        re.IGNORECASE,
    )
    _LARGE_TEXT_CLASS = re.compile(r"\btext-(?:lg|xl|2xl|3xl|4xl|5xl|6xl)\b|\bfont-(?:semibold|bold|extrabold)\b", re.IGNORECASE)
    _LOW_CONTRAST_DEFAULT_TEXT = {
        "text-gray-200",
        "text-gray-300",
        "text-slate-200",
        "text-slate-300",
        "text-zinc-200",
        "text-zinc-300",
        "text-neutral-200",
        "text-neutral-300",
        "text-stone-200",
        "text-stone-300",
    }
    _TAILWIND_PALETTE = {
        "white": "#ffffff",
        "black": "#000000",
        "gray-50": "#f9fafb",
        "gray-100": "#f3f4f6",
        "gray-200": "#e5e7eb",
        "gray-300": "#d1d5db",
        "gray-400": "#9ca3af",
        "gray-500": "#6b7280",
        "gray-600": "#4b5563",
        "gray-700": "#374151",
        "gray-800": "#1f2937",
        "gray-900": "#111827",
        "slate-50": "#f8fafc",
        "slate-100": "#f1f5f9",
        "slate-200": "#e2e8f0",
        "slate-300": "#cbd5e1",
        "slate-400": "#94a3b8",
        "slate-500": "#64748b",
        "slate-600": "#475569",
        "slate-700": "#334155",
        "slate-800": "#1e293b",
        "slate-900": "#0f172a",
        "zinc-200": "#e4e4e7",
        "zinc-300": "#d4d4d8",
        "zinc-400": "#a1a1aa",
        "zinc-900": "#18181b",
        "neutral-200": "#e5e5e5",
        "neutral-300": "#d4d4d4",
        "neutral-400": "#a3a3a3",
        "neutral-900": "#171717",
        "stone-200": "#e7e5e4",
        "stone-300": "#d6d3d1",
        "stone-400": "#a8a29e",
        "stone-900": "#1c1917",
    }

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
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
        if self._is_allowlisted_path(file_path):
            return []

        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for m in self._TEXT_PATTERN.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            if line in seen_lines:
                continue
            
            tag = m.group("tag").lower()
            attrs = m.group("attrs") or ""
            
            classes = self._extract_classes(attrs)
            is_large_text = tag in {"h1", "h2", "h3", "h4", "h5", "h6"} or self._LARGE_TEXT_CLASS.search(" ".join(classes))
            threshold = 3.0 if is_large_text else 4.5

            text_color_token = self._extract_tailwind_token(classes, "text")
            bg_color_token = self._extract_tailwind_token(classes, "bg")
            inline_color = self._extract_inline_style_color(attrs, self._INLINE_COLOR)
            inline_bg = self._extract_inline_style_color(attrs, self._INLINE_BG)

            text_color = self._resolve_color_token(text_color_token) or self._parse_css_color(inline_color)
            background_color = self._resolve_color_token(bg_color_token) or self._parse_css_color(inline_bg)

            ratio: float | None = None
            source = None
            if text_color and background_color:
                ratio = self._contrast_ratio(text_color, background_color)
                source = "dynamic"
            elif text_color_token in self._LOW_CONTRAST_DEFAULT_TEXT:
                default_bg = self._TAILWIND_PALETTE["white"]
                ratio = self._contrast_ratio(text_color or default_bg, default_bg)
                source = "default-light"

            if ratio is None or ratio >= threshold:
                continue

            confidence = 0.86 if source == "dynamic" else 0.62
            seen_lines.add(line)
            findings.append(
                self.create_finding(
                    title="Low contrast text color",
                    context=f"{file_path}:{line}:{tag}",
                    file=file_path,
                    line_start=line,
                    description=self._contrast_description(tag, text_color_token or inline_color or "text color", bg_color_token or inline_bg, ratio, threshold),
                    why_it_matters=(
                        "Low contrast text:\n"
                        "- Is difficult to read for users with low vision\n"
                        "- Fails WCAG 2.1 Success Criterion 1.4.3\n"
                        "- Affects users in bright environments\n"
                        "- Becomes unreliable across themes when colors are near the threshold"
                    ),
                    suggested_fix=(
                        "Use a darker text color or a higher-contrast background, then verify the final pair "
                        f"meets at least {threshold:.1f}:1 contrast."
                    ),
                    tags=["ux", "a11y", "contrast", "accessibility", "wcag"],
                    confidence=confidence,
                    evidence_signals=[
                        f"tag={tag}",
                        f"text_color={text_color_token or inline_color or 'unknown'}",
                        f"background_color={bg_color_token or inline_bg or 'default-light-surface'}",
                        f"contrast_ratio={ratio:.2f}",
                        f"threshold={threshold:.1f}",
                    ],
                )
            )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)

    def _extract_classes(self, attrs: str) -> list[str]:
        match = self._CLASS_ATTR.search(attrs or "")
        if not match:
            return []
        raw = match.group("classes") or ""
        return [token.strip() for token in raw.split() if token.strip() and ":" not in token]

    def _extract_tailwind_token(self, classes: Iterable[str], prefix: str) -> str | None:
        for token in classes:
            if prefix == "text" and token.startswith("text-") and token not in {"text-xs", "text-sm", "text-base", "text-lg", "text-xl", "text-2xl", "text-3xl", "text-4xl", "text-5xl", "text-6xl"}:
                return token.lower()
            if prefix == "bg" and token.startswith("bg-"):
                return token.lower()
        return None

    def _resolve_color_token(self, token: str | None) -> tuple[int, int, int] | None:
        if not token:
            return None
        key = token.lower().replace("text-", "").replace("bg-", "")
        hex_color = self._TAILWIND_PALETTE.get(key)
        if not hex_color:
            return None
        return self._parse_css_color(hex_color)

    def _extract_inline_style_color(self, attrs: str, pattern: re.Pattern[str]) -> str | None:
        match = pattern.search(attrs or "")
        if not match:
            return None
        return (match.group("color") or "").strip()

    def _parse_css_color(self, color: str | None) -> tuple[int, int, int] | None:
        raw = str(color or "").strip().lower()
        if not raw or "var(" in raw:
            return None
        if raw.startswith("#"):
            hex_part = raw[1:]
            if len(hex_part) == 3:
                hex_part = "".join(ch * 2 for ch in hex_part)
            if len(hex_part) >= 6:
                try:
                    return tuple(int(hex_part[i : i + 2], 16) for i in (0, 2, 4))
                except ValueError:
                    return None
        rgb_match = re.match(r"rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})", raw)
        if rgb_match:
            return tuple(max(0, min(255, int(rgb_match.group(i)))) for i in (1, 2, 3))
        return None

    def _contrast_ratio(self, foreground: tuple[int, int, int], background: tuple[int, int, int]) -> float:
        fg = self._relative_luminance(foreground)
        bg = self._relative_luminance(background)
        lighter = max(fg, bg)
        darker = min(fg, bg)
        return (lighter + 0.05) / (darker + 0.05)

    def _relative_luminance(self, color: tuple[int, int, int]) -> float:
        def channel(value: int) -> float:
            normalized = value / 255.0
            if normalized <= 0.03928:
                return normalized / 12.92
            return ((normalized + 0.055) / 1.055) ** 2.4

        r, g, b = color
        return (0.2126 * channel(r)) + (0.7152 * channel(g)) + (0.0722 * channel(b))

    def _contrast_description(
        self,
        tag: str,
        text_color: str,
        background_color: str | None,
        ratio: float,
        threshold: float,
    ) -> str:
        if background_color:
            return (
                f"`<{tag}>` combines `{text_color}` with `{background_color}`, which computes to "
                f"about {ratio:.2f}:1 contrast. WCAG requires at least {threshold:.1f}:1 here."
            )
        return (
            f"`<{tag}>` uses `{text_color}` on an assumed light surface, which looks to be about "
            f"{ratio:.2f}:1 contrast. Verify the actual rendered background meets at least {threshold:.1f}:1."
        )
