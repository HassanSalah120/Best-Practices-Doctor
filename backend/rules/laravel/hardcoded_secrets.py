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

    # Values that should NOT be flagged (placeholders, empty, env calls, Laravel patterns)
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
        r"['\"]\s*['\"]|"  # Empty string
        # Laravel validation rules
        r"['\"]required['\"]|"
        r"['\"]required_with['\"]|"
        r"['\"]required_if['\"]|"
        r"['\"]nullable['\"]|"
        r"['\"]sometimes['\"]|"
        r"['\"]filled['\"]|"
        r"['\"]present['\"]|"
        r"['\"]string['\"]|"
        r"['\"]email['\"]|"
        r"['\"]unique['\"]|"
        r"['\"]exists['\"]|"
        r"['\"]confirmed['\"]|"
        r"['\"]min:\d+['\"]|"
        r"['\"]max:\d+['\"]|"
        r"['\"]between:\d+,\d+['\"]|"
        r"[\"']\w+:\w+[\"']|"  # validation rule with colon like "min:8"
        # Laravel cast types
        r"['\"]hashed['\"]|"
        r"['\"]datetime['\"]|"
        r"['\"]date['\"]|"
        r"['\"]timestamp['\"]|"
        r"['\"]array['\"]|"
        r"['\"]json['\"]|"
        r"['\"]object['\"]|"
        r"['\"]collection['\"]|"
        r"['\"]boolean['\"]|"
        r"['\"]bool['\"]|"
        r"['\"]integer['\"]|"
        r"['\"]int['\"]|"
        r"['\"]real['\"]|"
        r"['\"]float['\"]|"
        r"['\"]double['\"]|"
        r"['\"]decimal:\d+['\"]|"
        r"['\"]encrypted['\"]|"
        r"['\"]encrypted:array['\"]|"
        r"['\"]immutable_date['\"]|"
        r"['\"]immutable_datetime['\"]"
    )

    # Patterns that indicate an ACTUAL secret (high entropy, API keys, etc.)
    _ACTUAL_SECRET_INDICATORS = [
        # API key prefixes
        re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE),  # Stripe keys
        re.compile(r"pk-[a-zA-Z0-9]{20,}", re.IGNORECASE),  # Stripe public keys
        re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),  # AWS access keys
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36}", re.IGNORECASE),  # GitHub tokens
        re.compile(r"glpat-[A-Za-z0-9-]{20}", re.IGNORECASE),  # GitLab tokens
        re.compile(r"Bearer\s+[a-zA-Z0-9_-]{20,}", re.IGNORECASE),  # Bearer tokens
        # High entropy patterns (random strings that look like secrets)
        re.compile(r"[a-zA-Z0-9]{20,}", re.IGNORECASE),  # Long alphanumeric strings
        re.compile(r"[a-z0-9]{32,}", re.IGNORECASE),  # MD5-like hashes
        re.compile(r"[a-f0-9]{40,}", re.IGNORECASE),  # SHA1-like hashes
        re.compile(r"[a-f0-9]{64,}", re.IGNORECASE),  # SHA256-like hashes
        # Base64 patterns (common for encoded secrets)
        re.compile(r"[A-Za-z0-9+/]{40,}={0,2}", re.IGNORECASE),
    ]

    # Common weak passwords that should be flagged
    _WEAK_PASSWORDS = re.compile(
        r"['\"](password|admin|123456|qwerty|letmein|welcome|monkey|dragon)['\"]\d*",
        re.IGNORECASE
    )

    def _looks_like_actual_secret(self, value: str) -> bool:
        """
        Determine if a value looks like an actual secret vs a Laravel pattern.
        Returns True if the value appears to be a real secret.
        """
        # If it matches weak passwords, it's a secret (bad practice)
        if self._WEAK_PASSWORDS.search(value):
            return True

        # If it has high entropy or API key patterns, it's a secret
        for pattern in self._ACTUAL_SECRET_INDICATORS:
            if pattern.search(value):
                return True

        # Laravel validation rules often have colons (min:8, max:255)
        if re.search(r"\w+:\d+", value):
            return False

        # Laravel casts and validation rules are typically lowercase single words
        # that are in our safe values list - but if we get here, it wasn't matched
        # Check for simple lowercase words (likely Laravel patterns)
        if re.match(r"^[a-z_]+$", value.strip("'\"")):
            return False

        # If the value is short (less than 8 chars), probably not a secret
        if len(value.strip("'\"")) < 8:
            return False

        # Default: if it looks complex enough, treat as secret
        return len(value) >= 10

    def _extract_value_from_match(self, matched: str) -> str:
        """Extract the actual value from a pattern match like 'password' => 'value'."""
        # Look for the value after =>
        value_match = re.search(r"=>\s*['\"]([^'\"]+)['\"]", matched)
        if value_match:
            return value_match.group(1)
        # Look for the value after =
        value_match = re.search(r"=\s*['\"]([^'\"]+)['\"]", matched)
        if value_match:
            return value_match.group(1)
        return matched

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

                # Check if it's a safe value (env, config, placeholder, Laravel patterns)
                if self._SAFE_VALUES.search(line):
                    continue

                # Extract the matched text and value
                matched = match.group(0)
                value = self._extract_value_from_match(matched)

                # Check if it looks like an actual secret (not Laravel validation/cast)
                if not self._looks_like_actual_secret(value):
                    continue

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
