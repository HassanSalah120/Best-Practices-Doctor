"""
Session Fixation Regenerate Missing Rule

Detects login/authentication flows that do not regenerate session ID after auth.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class SessionFixationRegenerateMissingRule(Rule):
    id = "session-fixation-regenerate-missing"
    name = "Session Regeneration Missing After Login"
    description = "Detects authentication flows missing session regeneration"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]

    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/")
    _AUTH_CALL = re.compile(
        r"(?:auth\s*\(\s*\)\s*->\s*attempt\s*\(|auth::attempt\s*\(|auth::login\s*\(|auth\s*\(\s*\)\s*->\s*login\s*\(|loginUsingId\s*\()",
        re.IGNORECASE,
    )
    _REGENERATE_SIGNAL = re.compile(
        r"(?:session\s*\(\s*\)\s*->\s*regenerate\s*\(|\$request->session\s*\(\s*\)\s*->\s*regenerate\s*\()",
        re.IGNORECASE,
    )
    _AUTH_CONTEXT_HINTS = ("login", "authenticate", "signin", "twofactor", "fortify", "auth")

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
        text = content or ""
        low_path = str(file_path or "").replace("\\", "/").lower()
        if any(marker in low_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if not any(hint in low_path for hint in self._AUTH_CONTEXT_HINTS) and "attempt(" not in text.lower():
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        findings: list[Finding] = []

        for match in self._AUTH_CALL.finditer(text):
            window = self._window(text, match.start(), before=24, after=28)
            if self._REGENERATE_SIGNAL.search(window):
                continue
            line = text.count("\n", 0, match.start()) + 1
            confidence = 0.88
            if confidence + 1e-9 < min_confidence:
                continue
            findings.append(
                self.create_finding(
                    title="Authentication flow may miss session regeneration",
                    context=f"{file_path}:{line}:auth-login",
                    file=file_path,
                    line_start=line,
                    description=(
                        "Detected authentication/login call without visible `session()->regenerate()` in nearby flow."
                    ),
                    why_it_matters=(
                        "Not regenerating session IDs after login increases session fixation risk and account takeover exposure."
                    ),
                    suggested_fix=(
                        "Regenerate session immediately after successful authentication, for example: "
                        "`$request->session()->regenerate();`."
                    ),
                    tags=["laravel", "security", "session", "fixation", "auth"],
                    confidence=confidence,
                    evidence_signals=[
                        "auth_login_call=true",
                        "session_regenerate_missing=true",
                    ],
                )
            )
            break

        return findings

    def _window(self, text: str, start_idx: int, before: int = 24, after: int = 12) -> str:
        lines = text.splitlines()
        line = text.count("\n", 0, start_idx) + 1
        start_line = max(0, line - before - 1)
        end_line = min(len(lines), line + after)
        return "\n".join(lines[start_line:end_line])

