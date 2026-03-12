"""
CORS Misconfiguration Rule

Detects overly permissive CORS configurations that could expose sensitive data.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class CorsMisconfigurationRule(Rule):
    id = "cors-misconfiguration"
    name = "CORS Misconfiguration"
    description = "Detects overly permissive CORS settings that could expose sensitive data"
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

    # Dangerous CORS patterns
    _WILDCARD_ORIGIN = re.compile(
        r"['\"]allowed_origins['\"]\s*=>\s*\[\s*['\"]\*['\"]\s*\]|"
        r"['\"]allowed_origins['\"]\s*=>\s*\[\s*['\"]\*['\"]\s*,|"
        r"['\"]supports_credentials['\"]\s*=>\s*true",
        re.IGNORECASE
    )
    
    _WILDCARD_WITH_CREDENTIALS = re.compile(
        r"['\"]supports_credentials['\"]\s*=>\s*(true|1)",
        re.IGNORECASE
    )
    
    _WILDCARD_ORIGIN_PATTERN = re.compile(
        r"['\"]allowed_origins['\"]\s*=>\s*\[[^\]]*['\"]\*['\"][^\]]*\]",
        re.IGNORECASE
    )
    
    _PATHS_CONFIG = ("config/cors.php", "config/sanctum.php")

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

        # Only check CORS config files
        is_cors_config = any(path in norm_path for path in self._PATHS_CONFIG)
        if not is_cors_config:
            return findings

        text = content or ""
        lines = text.split("\n")

        # Track if we have wildcard origin and credentials
        has_wildcard_origin = False
        has_credentials = False
        wildcard_line = 0
        credentials_line = 0

        for i, line in enumerate(lines, 1):
            # Check for wildcard origin
            if self._WILDCARD_ORIGIN_PATTERN.search(line):
                has_wildcard_origin = True
                wildcard_line = i

            # Check for credentials enabled
            if self._WILDCARD_WITH_CREDENTIALS.search(line):
                has_credentials = True
                credentials_line = i

        # Critical: wildcard origin with credentials
        if has_wildcard_origin and has_credentials:
            findings.append(
                self.create_finding(
                    title="CORS wildcard origin with credentials enabled",
                    context="config/cors.php",
                    file=file_path,
                    line_start=min(wildcard_line, credentials_line),
                    description=(
                        "CORS configuration allows any origin (*) while also allowing credentials. "
                        "This combination is extremely dangerous as it allows any website to make "
                        "authenticated requests to your API, potentially stealing user data."
                    ),
                    why_it_matters=(
                        "When Access-Control-Allow-Origin: * is combined with Access-Control-Allow-Credentials: true:\n"
                        "- Any malicious website can make authenticated requests\n"
                        "- User cookies and sessions are sent to attacker-controlled origins\n"
                        "- Enables CSRF attacks from any origin\n"
                        "- Violates CORS security specification\n"
                        "- OWASP API Security Top 10 risk"
                    ),
                    suggested_fix=(
                        "1. Specify exact allowed origins instead of wildcard:\n"
                        "   'allowed_origins' => ['https://yourdomain.com', 'https://app.yourdomain.com'],\n\n"
                        "2. If you need credentials, NEVER use wildcard origins\n\n"
                        "3. Use 'allowed_origins' => ['*'] only if 'supports_credentials' => false\n\n"
                        "4. For development, use specific localhost origins:\n"
                        "   'allowed_origins' => ['http://localhost:3000', 'http://127.0.0.1:3000'],"
                    ),
                    code_example=(
                        "// DANGEROUS - Never do this!\n"
                        "'allowed_origins' => ['*'],\n"
                        "'supports_credentials' => true,\n\n"
                        "// SAFE - Specify exact origins\n"
                        "'allowed_origins' => ['https://yourdomain.com'],\n"
                        "'supports_credentials' => true,\n\n"
                        "// SAFE - Wildcard without credentials\n"
                        "'allowed_origins' => ['*'],\n"
                        "'supports_credentials' => false,"
                    ),
                    confidence=0.95,
                    tags=["security", "cors", "api", "owasp-a1", "credentials"],
                )
            )
        elif has_wildcard_origin:
            # Warning: wildcard origin (less severe but still worth noting)
            findings.append(
                self.create_finding(
                    title="CORS wildcard origin configured",
                    context="config/cors.php",
                    file=file_path,
                    line_start=wildcard_line,
                    description=(
                        "CORS configuration allows any origin (*). While this may be intentional for "
                        "public APIs, it should be reviewed to ensure it's appropriate for your use case."
                    ),
                    why_it_matters=(
                        "Wildcard CORS origin means:\n"
                        "- Any website can make requests to your API\n"
                        "- May expose sensitive data to malicious sites\n"
                        "- Should only be used for truly public APIs\n"
                        "- Consider if this is necessary for your use case"
                    ),
                    suggested_fix=(
                        "1. For public APIs without sensitive data: This may be acceptable\n\n"
                        "2. For APIs with sensitive data: Specify exact origins:\n"
                        "   'allowed_origins' => ['https://yourdomain.com'],\n\n"
                        "3. For development: Use environment-based config:\n"
                        "   'allowed_origins' => env('CORS_ORIGINS') ? explode(',', env('CORS_ORIGINS')) : ['*'],"
                    ),
                    code_example=(
                        "// For public APIs (acceptable)\n"
                        "'allowed_origins' => ['*'],\n"
                        "'supports_credentials' => false,\n\n"
                        "// For private APIs (recommended)\n"
                        "'allowed_origins' => ['https://yourdomain.com', 'https://app.yourdomain.com'],"
                    ),
                    confidence=0.70,
                    severity=Severity.MEDIUM,
                    tags=["security", "cors", "api"],
                )
            )

        return findings
