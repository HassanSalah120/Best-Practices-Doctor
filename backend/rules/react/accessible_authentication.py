"""
Accessible Authentication Rule

Detects authentication flows that may require excessive cognitive effort (WCAG 3.3.8).
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class AccessibleAuthenticationRule(Rule):
    id = "accessible-authentication"
    name = "Accessible Authentication"
    description = "Detects authentication flows that may be difficult for users with cognitive impairments"
    category = Category.ACCESSIBILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Authentication patterns
    _AUTH_PATTERNS = [
        re.compile(r"<form[^>]*>(?P<content>.*?)</form>", re.IGNORECASE | re.DOTALL),
        re.compile(r"login", re.IGNORECASE),
        re.compile(r"signin", re.IGNORECASE),
        re.compile(r"authenticate", re.IGNORECASE),
    ]
    
    # Cognitive barrier patterns
    _COGNITIVE_BARRIER_PATTERNS = [
        re.compile(r"captcha", re.IGNORECASE),
        re.compile(r"recaptcha", re.IGNORECASE),
        re.compile(r"remember\s+(?:password|email)", re.IGNORECASE),
        re.compile(r"memorize", re.IGNORECASE),
        re.compile(r"security\s+question", re.IGNORECASE),
        re.compile(r"secret\s+question", re.IGNORECASE),
        re.compile(r"mother'?s?\s+maiden\s+name", re.IGNORECASE),
        re.compile(r"pet'?s?\s+name", re.IGNORECASE),
        re.compile(r"first\s+car", re.IGNORECASE),
        re.compile(r"born\s+city", re.IGNORECASE),
    ]
    
    # Accessible alternatives (good)
    _ACCESSIBLE_ALTERNATIVES = [
        re.compile(r"passwordless", re.IGNORECASE),
        re.compile(r"magic\s+link", re.IGNORECASE),
        re.compile(r"email\s+link", re.IGNORECASE),
        re.compile(r"o[ta]p", re.IGNORECASE),  # OTP/OTP
        re.compile(r"one.?time.?password", re.IGNORECASE),
        re.compile(r"passkey", re.IGNORECASE),
        re.compile(r"webauthn", re.IGNORECASE),
        re.compile(r"fido", re.IGNORECASE),
        re.compile(r"biometric", re.IGNORECASE),
        re.compile(r"face\s+id", re.IGNORECASE),
        re.compile(r"touch\s+id", re.IGNORECASE),
        re.compile(r"social\s+login", re.IGNORECASE),
        re.compile(r"google\s+login", re.IGNORECASE),
        re.compile(r"facebook\s+login", re.IGNORECASE),
        re.compile(r"sso", re.IGNORECASE),
        re.compile(r"single.?sign.?on", re.IGNORECASE),
        re.compile(r"show\s+password", re.IGNORECASE),
        re.compile(r"toggle\s+password", re.IGNORECASE),
        re.compile(r"copy\s+password", re.IGNORECASE),
        re.compile(r"password\s+manager", re.IGNORECASE),
    ]
    
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
        
        # Check if this is an authentication-related file
        is_auth_file = any(p.search(file_path.lower()) for p in [
            re.compile(r"login"),
            re.compile(r"signin"),
            re.compile(r"auth"),
            re.compile(r"register"),
            re.compile(r"signup"),
        ])
        
        if not is_auth_file:
            return findings
        
        # Check for cognitive barriers
        has_barrier = False
        barrier_type = None
        for pattern in self._COGNITIVE_BARRIER_PATTERNS:
            m = pattern.search(content)
            if m:
                has_barrier = True
                barrier_type = m.group(0)
                break
        
        if not has_barrier:
            return findings
        
        # Check for accessible alternatives
        has_alternative = any(p.search(content) for p in self._ACCESSIBLE_ALTERNATIVES)
        if has_alternative:
            return findings  # Has accessible alternative
        
        line = 1
        for pattern in self._COGNITIVE_BARRIER_PATTERNS:
            m = pattern.search(content)
            if m:
                line = content.count("\n", 0, m.start()) + 1
                break
        
        findings.append(
            self.create_finding(
                title="Authentication may require excessive cognitive effort",
                context=f"{file_path}:{line}:auth-cognitive",
                file=file_path,
                line_start=line,
                description=(
                    f"Found \"{barrier_type}\" in authentication flow. This requires users to "
                    "perform cognitive tasks like remembering information or solving puzzles, "
                    "which can be difficult for users with cognitive impairments."
                ),
                why_it_matters=(
                    "WCAG 3.3.8 requires accessible authentication.\n"
                    "- Users with cognitive impairments struggle with memory tasks\n"
                    "- CAPTCHAs are difficult for users with visual or cognitive disabilities\n"
                    "- Security questions require memory recall\n"
                    "- This creates barriers to accessing services"
                ),
                suggested_fix=(
                    "1. Offer passwordless authentication:\n"
                    "   - Magic link (email login)\n"
                    "   - Passkeys / WebAuthn\n"
                    "   - Biometric authentication\n"
                    "2. Allow social login (Google, Apple, etc.)\n"
                    "3. Support password managers (autocomplete)\n"
                    "4. Show password option instead of double-entry\n"
                    "5. Use accessible CAPTCHA alternatives (hCaptcha, etc.)"
                ),
                tags=["ux", "a11y", "authentication", "cognitive", "accessibility", "wcag"],
                confidence=0.70,
                evidence_signals=[
                    f"barrier={barrier_type}",
                    "accessible_alternative_missing=true",
                ],
            )
        )

        return findings

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATHS)
