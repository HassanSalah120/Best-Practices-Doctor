"""
Hardcoded Secrets Rule

Detects hardcoded passwords, API keys, tokens, and other secrets in code.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class HardcodedSecretsRule(Rule):
    id = "hardcoded-secrets"
    name = "Hardcoded Secrets Detection"
    description = "Detects hardcoded passwords, API keys, tokens, and other sensitive values"
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

    # Patterns that suggest a secret assignment
    _SECRET_PATTERNS = [
        # Password patterns
        re.compile(r"['\"]password['\"]\s*=>\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"['\"]password['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"\$password\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        # API key patterns
        re.compile(r"['\"]api_key['\"]\s*=>\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"['\"]api_key['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"['\"]apikey['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"\$apiKey\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        # Token patterns
        re.compile(r"['\"]token['\"]\s*=>\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"['\"]token['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"['\"]access_token['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"['\"]secret['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"['\"]secret_key['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        # AWS patterns
        re.compile(r"['\"]aws_access_key_id['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"['\"]aws_secret_access_key['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        # Database patterns
        re.compile(r"['\"]db_password['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"['\"]database_password['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        # Private key patterns
        re.compile(r"['\"]private_key['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"['\"]private_key['\"]\s*=>\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    ]

    # Values that should NOT be flagged (placeholders, empty, env calls)
    _SAFE_VALUES = re.compile(
        r"env\s*\(|"
        r"config\s*\(|"
        r"['\"]your[_-]?password['\"]|"
        r"['\"]your[_-]?api[_-]?key['\"]|"
        r"['\"]your[_-]?secret['\"]|"
        r"['\"]your[_-]?token['\"]|"
        r"['\"]xxx+['\"]|"
        r"['\"]placeholder['\"]|"
        r"['\"]changeme['\"]|"
        r"['\"]secret[_-]?here['\"]|"
        r"['\"]\s*['\"]"  # Empty string
    )

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/vendor/",
        "/database/migrations/",
        "/database/factories/",
        "/config/",  # Config files use env() - already safe
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

            for pattern in self._SECRET_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue

                # Check if it's a safe value (env, config, placeholder)
                if self._SAFE_VALUES.search(line):
                    continue

                # Extract the matched text
                matched = match.group(0)

                findings.append(
                    self.create_finding(
                        title="Hardcoded secret detected",
                        context=matched[:80],
                        file=file_path,
                        line_start=i,
                        description=(
                            f"Detected a hardcoded secret pattern: `{matched[:50]}...`. "
                            "Hardcoding secrets in source code is a security risk as they can be "
                            "committed to version control and exposed in logs or error traces."
                        ),
                        why_it_matters=(
                            "Hardcoded secrets are a leading cause of security breaches. "
                            "Attackers can find them in public repositories, compiled code, "
                            "or through source code leaks. Once exposed, secrets can be used "
                            "to access production systems, databases, or third-party APIs."
                        ),
                        suggested_fix=(
                            "1. Use environment variables: `env('API_KEY')`\n"
                            "2. Store secrets in .env file (not committed to version control)\n"
                            "3. Use Laravel's config system: `config('services.api.key')`\n"
                            "4. For databases, use config/database.php with env() calls\n"
                            "5. Consider using a secrets manager (AWS Secrets Manager, Vault)"
                        ),
                        code_example=(
                            "// Before (vulnerable)\n"
                            "$apiKey = 'sk-live-abc123xyz';\n\n"
                            "// After (secure)\n"
                            "$apiKey = env('API_KEY');\n"
                            "// In .env (not committed):\n"
                            "API_KEY=sk-live-abc123xyz"
                        ),
                        confidence=0.85,
                        tags=["security", "secrets", "credentials", "owasp-a2"],
                    )
                )
                break  # One finding per line is enough

        return findings
