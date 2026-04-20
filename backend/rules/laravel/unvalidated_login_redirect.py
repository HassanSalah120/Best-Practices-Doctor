"""
Unvalidated login redirect detector.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class UnvalidatedLoginRedirectRule(Rule):
    id = "unvalidated-login-redirect"
    name = "Unvalidated Login Redirect"
    description = "Detects login/verification redirects that trust request-provided next/redirect URLs"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    _ALLOWLIST = ("/tests/", "/test/", "/vendor/")
    _REDIRECT_LINE = re.compile(
        r"(redirect\s*\(\s*\)\s*->\s*(?:to|away)\s*\(|redirect\s*\()",
        re.IGNORECASE,
    )
    _USER_INPUT = re.compile(
        r"request\s*\(\s*['\"](?:redirect|next|return_url|continue)['\"]\s*\)"
        r"|->\s*(?:input|query|get)\s*\(\s*['\"](?:redirect|next|return_url|continue)['\"]",
        re.IGNORECASE,
    )
    _SAFETY_SIGNAL = re.compile(
        r"(starts_with|str_starts_with|parse_url|validateRedirect|allowlist|trusted_hosts|in_array)",
        re.IGNORECASE,
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
        norm = (file_path or "").replace("\\", "/").lower()
        if any(marker in norm for marker in self._ALLOWLIST):
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_low = line.lower()
            if not self._REDIRECT_LINE.search(line_low):
                continue
            if not self._USER_INPUT.search(line_low):
                continue

            window = "\n".join(lines[max(0, idx - 6):min(len(lines), idx + 3)])
            if self._SAFETY_SIGNAL.search(window):
                continue

            findings.append(
                self.create_finding(
                    title="Login redirect appears unvalidated",
                    context=line.strip()[:80],
                    file=file_path,
                    line_start=idx,
                    description=(
                        "Detected redirect logic using request-provided `next/redirect` input without visible host/path validation."
                    ),
                    why_it_matters=(
                        "Login-flow open redirects can be abused for phishing and token theft chains."
                    ),
                    suggested_fix=(
                        "Allow only relative paths (for example `str_starts_with($next, '/')`) or validate hosts against an explicit allowlist."
                    ),
                    confidence=0.86,
                    tags=["laravel", "security", "redirect", "auth-flow"],
                    evidence_signals=["redirect_input_unvalidated=true"],
                )
            )
        return findings
