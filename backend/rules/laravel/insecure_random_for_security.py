"""
Insecure Random for Security Rule

Detects use of rand() or mt_rand() in security-sensitive contexts.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class InsecureRandomForSecurityRule(Rule):
    id = "insecure-random-for-security"
    name = "Insecure Random for Security"
    description = "Detects use of rand() or mt_rand() in security-sensitive contexts"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    regex_file_extensions = [".php"]

    # Insecure random functions
    _INSECURE_RANDOM = [
        re.compile(r"\brand\s*\(", re.IGNORECASE),
        re.compile(r"\bmt_rand\s*\(", re.IGNORECASE),
        re.compile(r"\barray_rand\s*\(", re.IGNORECASE),
        re.compile(r"\bshuffle\s*\(", re.IGNORECASE),
    ]

    # Security-sensitive context keywords
    _SECURITY_CONTEXTS = [
        re.compile(r"['\"]token['\"]", re.IGNORECASE),
        re.compile(r"['\"]password['\"]", re.IGNORECASE),
        re.compile(r"['\"]secret['\"]", re.IGNORECASE),
        re.compile(r"['\"]otp['\"]", re.IGNORECASE),
        re.compile(r"['\"]code['\"]", re.IGNORECASE),
        re.compile(r"['\"]pin['\"]", re.IGNORECASE),
        re.compile(r"['\"]verification['\"]", re.IGNORECASE),
        re.compile(r"['\"]confirmation['\"]", re.IGNORECASE),
        re.compile(r"['\"]reset['\"]", re.IGNORECASE),
        re.compile(r"\$token", re.IGNORECASE),
        re.compile(r"\$code", re.IGNORECASE),
        re.compile(r"\$otp", re.IGNORECASE),
        re.compile(r"\$pin", re.IGNORECASE),
        re.compile(r"generateToken", re.IGNORECASE),
        re.compile(r"generateCode", re.IGNORECASE),
        re.compile(r"generateOtp", re.IGNORECASE),
        re.compile(r"generatePin", re.IGNORECASE),
        re.compile(r"verification", re.IGNORECASE),
        re.compile(r"confirmation", re.IGNORECASE),
        re.compile(r"reset.*token", re.IGNORECASE),
        re.compile(r"one.?time", re.IGNORECASE),
    ]

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/vendor/",
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
        metrics: dict[str, MethodMetrics] | None = None,
        facts: Facts = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Skip allowlisted paths
        norm_path = (file_path or "").replace("\\", "/").lower()
        if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
            return findings

        lines = content.split("\n")

        # Track context - look at surrounding lines for security context
        context_window = 5

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            # Check for insecure random function
            has_insecure_random = any(pattern.search(line) for pattern in self._INSECURE_RANDOM)
            if not has_insecure_random:
                continue

            # Check for security context in current line
            has_security_context = any(pattern.search(line) for pattern in self._SECURITY_CONTEXTS)

            # Also check surrounding lines for context
            if not has_security_context:
                start = max(0, i - context_window - 1)
                end = min(len(lines), i + context_window)
                context_lines = "\n".join(lines[start:end])
                has_security_context = any(
                    pattern.search(context_lines) for pattern in self._SECURITY_CONTEXTS
                )

            if not has_security_context:
                continue

            context = line.strip()[:80]

            findings.append(
                self.create_finding(
                    title="Insecure random function in security context",
                    context=context,
                    file=file_path,
                    line_start=i,
                    description=(
                        "Detected use of `rand()` or `mt_rand()` in a security-sensitive context. "
                        "These functions are not cryptographically secure and should not be used "
                        "for generating tokens, passwords, OTPs, or verification codes."
                    ),
                    why_it_matters=(
                        "Using non-cryptographic random for security:\n"
                        "- rand() and mt_rand() are predictable\n"
                        "- Can be guessed or brute-forced by attackers\n"
                        "- May allow bypassing authentication or verification\n"
                        "- OWASP recommends using cryptographically secure random"
                    ),
                    suggested_fix=(
                        "1. Use random_int() for integer generation:\n"
                        "   $code = random_int(100000, 999999);\n\n"
                        "2. Use Str::random() for string tokens:\n"
                        "   $token = Str::random(64);\n\n"
                        "3. Use Str::uuid() for unique identifiers:\n"
                        "   $uuid = (string) Str::uuid();\n\n"
                        "4. For OTPs, use:\n"
                        "   $otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);"
                    ),
                    code_example=(
                        "// Before (insecure)\n"
                        "$token = rand(100000, 999999);\n"
                        "$code = mt_rand(1000, 9999);\n\n"
                        "// After (secure)\n"
                        "$token = Str::random(64);\n"
                        "$code = random_int(1000, 9999);\n\n"
                        "// For OTP\n"
                        "$otp = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);"
                    ),
                    confidence=0.75,
                    tags=["security", "cryptography", "random", "owasp-a2"],
                )
            )

        return findings
