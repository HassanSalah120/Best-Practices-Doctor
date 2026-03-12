"""
Sensitive Data Logging Rule

Detects logging of passwords, tokens, and other sensitive data.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class SensitiveDataLoggingRule(Rule):
    id = "sensitive-data-logging"
    name = "Sensitive Data Logging Detection"
    description = "Detects logging of passwords, tokens, and other sensitive data"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    regex_file_extensions = [".php"]

    # Logging methods
    _LOG_PATTERNS = [
        re.compile(r"\bLog::(info|debug|warning|error|notice|critical|alert|emergency)\s*\(", re.IGNORECASE),
        re.compile(r"\blogger\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"\blogger\s*\(\s*\$", re.IGNORECASE),
        re.compile(r"\binfo\s*\(", re.IGNORECASE),
        re.compile(r"\bdebug\s*\(", re.IGNORECASE),
        re.compile(r"\bdump\s*\(", re.IGNORECASE),
        re.compile(r"\bdd\s*\(", re.IGNORECASE),
        re.compile(r"\bvar_dump\s*\(", re.IGNORECASE),
        re.compile(r"\bprint_r\s*\(", re.IGNORECASE),
    ]

    # Sensitive field patterns
    _SENSITIVE_PATTERNS = [
        re.compile(r"['\"]password['\"]", re.IGNORECASE),
        re.compile(r"['\"]password_confirmation['\"]", re.IGNORECASE),
        re.compile(r"['\"]current_password['\"]", re.IGNORECASE),
        re.compile(r"['\"]new_password['\"]", re.IGNORECASE),
        re.compile(r"['\"]token['\"]", re.IGNORECASE),
        re.compile(r"['\"]access_token['\"]", re.IGNORECASE),
        re.compile(r"['\"]refresh_token['\"]", re.IGNORECASE),
        re.compile(r"['\"]api_key['\"]", re.IGNORECASE),
        re.compile(r"['\"]secret['\"]", re.IGNORECASE),
        re.compile(r"['\"]secret_key['\"]", re.IGNORECASE),
        re.compile(r"['\"]private_key['\"]", re.IGNORECASE),
        re.compile(r"['\"]credit_card['\"]", re.IGNORECASE),
        re.compile(r"['\"]card_number['\"]", re.IGNORECASE),
        re.compile(r"['\"]cvv['\"]", re.IGNORECASE),
        re.compile(r"['\"]ssn['\"]", re.IGNORECASE),
        re.compile(r"['\"]social_security['\"]", re.IGNORECASE),
        re.compile(r"['\"]tax_id['\"]", re.IGNORECASE),
        re.compile(r"->password", re.IGNORECASE),
        re.compile(r"->token", re.IGNORECASE),
        re.compile(r"->secret", re.IGNORECASE),
        re.compile(r"->api_key", re.IGNORECASE),
        re.compile(r"->remember_token", re.IGNORECASE),
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
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Skip allowlisted paths
        norm_path = (file_path or "").replace("\\", "/").lower()
        if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
            return findings

        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            # Check if this line has logging
            has_logging = any(pattern.search(line) for pattern in self._LOG_PATTERNS)
            if not has_logging:
                continue

            # Check if logging sensitive data
            sensitive_match = None
            for pattern in self._SENSITIVE_PATTERNS:
                match = pattern.search(line)
                if match:
                    sensitive_match = match.group(0)
                    break

            if not sensitive_match:
                continue

            findings.append(
                self.create_finding(
                    title="Sensitive data logged",
                    context=line.strip()[:80],
                    file=file_path,
                    line_start=i,
                    description=(
                        f"Detected logging of sensitive data: `{sensitive_match}`. "
                        "Logging passwords, tokens, or other secrets can expose them in log files, "
                        "monitoring systems, or error traces."
                    ),
                    why_it_matters=(
                        "Sensitive data in logs is a security and compliance risk:\n"
                        "- Log files may be accessed by unauthorized users\n"
                        "- Logs are often sent to third-party monitoring services\n"
                        "- Violates GDPR, HIPAA, PCI-DSS requirements\n"
                        "- Passwords/tokens may persist in logs indefinitely"
                    ),
                    suggested_fix=(
                        "1. Exclude sensitive fields before logging:\n"
                        "   $data = $request->except(['password', 'token']);\n"
                        "   Log::info('User action', $data);\n\n"
                        "2. Use Laravel's hidden attributes on models:\n"
                        "   protected $hidden = ['password', 'remember_token'];\n\n"
                        "3. Never log request->all() directly\n"
                        "4. Use Log::info('message') without sensitive context"
                    ),
                    code_example=(
                        "// Before (vulnerable)\n"
                        "Log::info('User login', $request->all()); // logs password!\n\n"
                        "// After (secure)\n"
                        "Log::info('User login', $request->except(['password', 'token']));"
                    ),
                    confidence=0.90,
                    tags=["security", "logging", "sensitive-data", "compliance", "owasp-a3"],
                )
            )

        return findings
