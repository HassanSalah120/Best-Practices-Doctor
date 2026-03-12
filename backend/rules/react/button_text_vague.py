"""
Button Text Vague Rule

Detects buttons with vague text like "Submit", "Click", "Go" without context.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ButtonTextVagueRule(Rule):
    id = "button-text-vague"
    name = "Button Text Vague"
    description = "Detects buttons with vague text that lacks context"
    category = Category.ACCESSIBILITY
    default_severity = Severity.LOW
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Vague button text patterns
    _VAGUE_PATTERNS = [
        re.compile(r"^submit$", re.IGNORECASE),
        re.compile(r"^click$", re.IGNORECASE),
        re.compile(r"^go$", re.IGNORECASE),
        re.compile(r"^ok$", re.IGNORECASE),
        re.compile(r"^yes$", re.IGNORECASE),
        re.compile(r"^no$", re.IGNORECASE),
        re.compile(r"^cancel$", re.IGNORECASE),
        re.compile(r"^close$", re.IGNORECASE),
        re.compile(r"^save$", re.IGNORECASE),
        re.compile(r"^delete$", re.IGNORECASE),
        re.compile(r"^add$", re.IGNORECASE),
        re.compile(r"^remove$", re.IGNORECASE),
        re.compile(r"^edit$", re.IGNORECASE),
        re.compile(r"^done$", re.IGNORECASE),
        re.compile(r"^apply$", re.IGNORECASE),
        re.compile(r"^confirm$", re.IGNORECASE),
    ]
    
    # Button patterns
    _BUTTON_PATTERN = re.compile(
        r"<button\b(?P<attrs>[^>]*)>(?P<text>.*?)</button>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Input submit/button
    _INPUT_BUTTON = re.compile(
        r"<input\b(?P<attrs>[^>]*)(?:type=[\"'](?:submit|button|reset)[\"'])[^>]*>",
        re.IGNORECASE | re.DOTALL,
    )
    
    # Check for aria-label
    _ARIA_LABEL = re.compile(r"aria-label=[\"'](?P<label>[^\"']+)[\"']", re.IGNORECASE)
    
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

        # Check <button> elements
        for m in self._BUTTON_PATTERN.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            if line in seen_lines:
                continue
            
            attrs = m.group("attrs") or ""
            text = m.group("text") or ""
            
            # Strip JSX and HTML from button content
            plain_text = self._extract_plain_text(text).strip()
            
            if not plain_text:
                # Icon button - check aria-label
                aria_match = self._ARIA_LABEL.search(attrs)
                if aria_match:
                    plain_text = aria_match.group("label")
                else:
                    continue  # Icon button without label - different issue
            
            # Check if text is vague
            is_vague, matched = self._is_vague_text(plain_text)
            if not is_vague:
                continue
            
            # Skip if has aria-label with more context
            aria_match = self._ARIA_LABEL.search(attrs)
            if aria_match and len(aria_match.group("label")) > len(plain_text) + 5:
                continue
            
            seen_lines.add(line)
            findings.append(
                self.create_finding(
                    title="Button text is vague or lacks context",
                    context=f"{file_path}:{line}:button-text",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Button text \"{plain_text}\" is vague. When there are multiple buttons, "
                        "users need to know what each button does."
                    ),
                    why_it_matters=(
                        "Vague button text:\n"
                        "- Confuses users when multiple similar buttons exist\n"
                        "- Screen reader users may not know which action to take\n"
                        "- Users with cognitive impairments need clear actions\n"
                        "- Reduces cognitive load for all users"
                    ),
                    suggested_fix=(
                        "1. Be specific: \"Submit registration\" instead of \"Submit\"\n"
                        "2. Use verb + object: \"Delete account\" instead of \"Delete\"\n"
                        "3. Add aria-label for icon buttons: aria-label=\"Close dialog\"\n"
                        "4. Use visually-hidden text for context"
                    ),
                    tags=["ux", "a11y", "buttons", "accessibility"],
                    confidence=0.75,
                    evidence_signals=[
                        f"button_text={plain_text}",
                        f"matched_pattern={matched}",
                    ],
                )
            )

        # Check <input type="submit/button">
        for m in self._INPUT_BUTTON.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            if line in seen_lines:
                continue
            
            attrs = m.group("attrs") or ""
            
            # Get value attribute
            value_match = re.search(r'value=["\'](?P<value>[^"\']+)["\']', attrs)
            if not value_match:
                continue  # No value - uses default "Submit"
            
            value = value_match.group("value")
            
            is_vague, matched = self._is_vague_text(value)
            if not is_vague:
                continue
            
            seen_lines.add(line)
            findings.append(
                self.create_finding(
                    title="Input button value is vague",
                    context=f"{file_path}:{line}:input-button",
                    file=file_path,
                    line_start=line,
                    description=f"Input button value \"{value}\" is vague.",
                    why_it_matters="Vague button labels confuse users about the action being taken.",
                    suggested_fix="Use specific action text: value=\"Send message\" instead of value=\"Submit\"",
                    tags=["ux", "a11y", "buttons", "accessibility"],
                    confidence=0.75,
                    evidence_signals=[f"button_value={value}", f"matched_pattern={matched}"],
                )
            )

        return findings

    def _extract_plain_text(self, text: str) -> str:
        """Extract plain text from JSX/HTML content."""
        # Remove JSX expressions
        text = re.sub(r"\{[^}]*\}", "", text)
        # Remove HTML tags
        text = re.sub(r"<[^>]+>", "", text)
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def _is_vague_text(self, text: str) -> tuple[bool, str]:
        """Check if text matches vague patterns."""
        for pattern in self._VAGUE_PATTERNS:
            if pattern.search(text):
                return True, pattern.pattern
        return False, ""

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
