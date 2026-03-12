"""
Autoplay Media Rule

Detects auto-playing audio/video that cannot be controlled (WCAG 1.4.2, 2.2.2).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class AutoplayMediaRule(Rule):
    id = "autoplay-media"
    name = "Autoplay Media"
    description = "Detects auto-playing audio/video without user controls"
    category = Category.ACCESSIBILITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx", ".html"]

    # Video/audio with autoplay
    _AUTOPLAY_PATTERN = re.compile(
        r"<(?:video|audio)\b(?P<attrs>[^>]*)autoplay[^>]*>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Controls attribute
    _CONTROLS_PATTERN = re.compile(r"\bcontrols\b", re.IGNORECASE)
    
    # Muted attribute (muted autoplay is allowed)
    _MUTED_PATTERN = re.compile(r"\bmuted\b", re.IGNORECASE)
    
    # Play method calls
    _PLAY_CALL_PATTERN = re.compile(
        r"\.play\s*\(\s*\)",
        re.IGNORECASE,
    )
    
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

        # Check for autoplay attribute
        for m in self._AUTOPLAY_PATTERN.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            if line in seen_lines:
                continue
            
            attrs = m.group("attrs") or ""
            
            # Check if muted (muted autoplay is acceptable)
            is_muted = bool(self._MUTED_PATTERN.search(attrs))
            if is_muted:
                continue  # Muted autoplay is allowed
            
            # Check if has controls
            has_controls = bool(self._CONTROLS_PATTERN.search(attrs))
            
            seen_lines.add(line)
            
            if not has_controls:
                findings.append(
                    self.create_finding(
                        title="Autoplay media without user controls",
                        context=f"{file_path}:{line}:autoplay-media",
                        file=file_path,
                        line_start=line,
                        description=(
                            "Video or audio element has autoplay but no controls attribute. "
                            "Users cannot pause or stop the media."
                        ),
                        why_it_matters=(
                            "WCAG 1.4.2 and 2.2.2 require user control over auto-playing content.\n"
                            "- Auto-playing audio can startle screen reader users\n"
                            "- Users with vestibular disorders may be affected by motion\n"
                            "- Users cannot control the volume or playback\n"
                            "- This is a Level A requirement (mandatory)"
                        ),
                        suggested_fix=(
                            "1. Add controls attribute: <video autoplay controls>\n"
                            "2. Or remove autoplay and let user start playback\n"
                            "3. For background video, add muted: <video autoplay muted loop>\n"
                            "4. Provide visible pause/play buttons"
                        ),
                        tags=["ux", "a11y", "media", "autoplay", "accessibility", "wcag"],
                        confidence=0.90,
                        evidence_signals=[
                            "autoplay=true",
                            "controls_missing=true",
                            "muted=false",
                        ],
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        title="Autoplay media should be avoided",
                        context=f"{file_path}:{line}:autoplay-media",
                        file=file_path,
                        line_start=line,
                        description=(
                            "Video or audio element has autoplay. While controls are provided, "
                            "auto-playing media can still disrupt screen reader users."
                        ),
                        why_it_matters=(
                            "WCAG 2.2.2 recommends against auto-play.\n"
                            "- Auto-playing audio can interfere with screen readers\n"
                            "- Users may be in a quiet environment\n"
                            "- Unexpected audio can startle users\n"
                            "- Consider letting users start playback manually"
                        ),
                        suggested_fix=(
                            "1. Remove autoplay and let user start playback\n"
                            "2. Or ensure autoplay is muted: <video autoplay muted controls>\n"
                            "3. Provide clear indication that media will play"
                        ),
                        tags=["ux", "a11y", "media", "autoplay", "accessibility", "wcag"],
                        confidence=0.75,
                        evidence_signals=[
                            "autoplay=true",
                            "controls_present=true",
                        ],
                    )
                )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
