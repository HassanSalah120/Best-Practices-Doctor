"""
Redundant Entry Rule

Detects forms that ask users to re-enter information (WCAG 3.3.7).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class RedundantEntryRule(Rule):
    id = "redundant-entry"
    name = "Redundant Entry"
    description = "Detects forms that may ask users to re-enter previously provided information"
    category = Category.ACCESSIBILITY
    default_severity = Severity.LOW
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Patterns suggesting redundant entry
    _REDUNDANT_PATTERNS = [
        re.compile(r"confirm\s+(?:email|password|address)", re.IGNORECASE),
        re.compile(r"re-?enter\s+(?:email|password|address)", re.IGNORECASE),
        re.compile(r"verify\s+(?:email|password|address)", re.IGNORECASE),
        re.compile(r"repeat\s+(?:email|password|address)", re.IGNORECASE),
        re.compile(r"(?:email|password|address)\s+again", re.IGNORECASE),
        re.compile(r"same\s+(?:email|password|address)", re.IGNORECASE),
    ]
    
    # Autofill patterns (good - prevents redundant entry)
    _AUTOFILL_PATTERNS = [
        re.compile(r'autocomplete=["\'][^"\']+["\']', re.IGNORECASE),
        re.compile(r'defaultValue=', re.IGNORECASE),
        re.compile(r'value=\{[^}]+\}', re.IGNORECASE),
    ]
    
    # Multi-step form patterns
    _MULTI_STEP_PATTERNS = [
        re.compile(r"step\s*\d+", re.IGNORECASE),
        re.compile(r"wizard", re.IGNORECASE),
        re.compile(r"multi.?step", re.IGNORECASE),
    ]
    
    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/i18n/",
        "/lang/",
        "/locales/",
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

        # Check for redundant entry patterns
        for pattern in self._REDUNDANT_PATTERNS:
            for m in pattern.finditer(content):
                line = content.count("\n", 0, m.start()) + 1
                if line in seen_lines:
                    continue
                
                matched_text = m.group(0)
                seen_lines.add(line)
                
                # Check if there's autofill nearby (which mitigates the issue)
                nearby = content[max(0, m.start() - 200):min(len(content), m.end() + 200)]
                has_autofill = any(p.search(nearby) for p in self._AUTOFILL_PATTERNS)
                
                if has_autofill:
                    continue  # Autofill present, likely mitigated

                if self._is_security_confirmation_context(file_path, matched_text, nearby):
                    continue

                findings.append(
                    self.create_finding(
                        title="Potential redundant entry requirement",
                        context=f"{file_path}:{line}:redundant-entry",
                        file=file_path,
                        line_start=line,
                        description=(
                            f"Found \"{matched_text}\" which suggests users may need to re-enter "
                            "information they've already provided. This creates extra work and "
                            "increases error risk."
                        ),
                        why_it_matters=(
                            "WCAG 3.3.7 (Level A 2.2) discourages redundant entry.\n"
                            "- Users with cognitive impairments may forget what they entered\n"
                            "- Increases cognitive load and frustration\n"
                            "- More opportunities for typos and errors\n"
                            "- Particularly difficult for users with motor impairments"
                        ),
                        suggested_fix=(
                            "1. Auto-populate confirmed fields from previous input\n"
                            "2. Show the original value and let user verify it\n"
                            "3. Use autocomplete attribute for browser autofill\n"
                            "4. For password confirmation, consider show/hide toggle instead\n"
                            "5. Only ask for re-entry if security requires it"
                        ),
                        tags=["ux", "a11y", "forms", "cognitive", "accessibility", "wcag"],
                        confidence=0.60,
                        evidence_signals=[
                            f"pattern={matched_text}",
                            "autofill_missing=true",
                        ],
                    )
                )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS) or low.endswith("/i18n.ts")

    def _is_security_confirmation_context(self, file_path: str, matched_text: str, nearby: str) -> bool:
        low_match = matched_text.lower()
        low_path = (file_path or "").lower().replace("\\", "/")
        low_nearby = nearby.lower()

        if "password" not in low_match:
            return False

        security_markers = (
            "password_confirmation",
            "confirm_password",
            "type=\"password\"",
            "type='password'",
            "autocomplete=\"new-password\"",
            "autocomplete='new-password'",
            "autocomplete=\"current-password\"",
            "autocomplete='current-password'",
        )
        auth_paths = ("/auth/", "/register", "/reset-password", "/profile/")

        return any(marker in low_nearby for marker in security_markers) or any(marker in low_path for marker in auth_paths)
