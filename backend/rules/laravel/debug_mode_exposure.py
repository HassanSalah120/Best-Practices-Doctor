"""
Debug Mode Exposure Rule

Detects APP_DEBUG=true risks and debug settings in production.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class DebugModeExposureRule(Rule):
    id = "debug-mode-exposure"
    name = "Debug Mode Exposure Risk"
    description = "Detects debug mode settings that could expose sensitive information"
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
    regex_file_extensions = [".php", ".env.example"]

    _DEBUG_TRUE_PATTERNS = [
        re.compile(r"APP_DEBUG\s*=\s*true", re.IGNORECASE),
        re.compile(r"APP_DEBUG\s*=\s*1", re.IGNORECASE),
        re.compile(r"['\"]debug['\"]\s*=>\s*true", re.IGNORECASE),
        re.compile(r"['\"]debug['\"]\s*=>\s*env\s*\(\s*['\"][^'\"]+['\"]\s*,\s*true\s*\)", re.IGNORECASE),
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

        # Only check specific files
        is_env_example = norm_path.endswith(".env.example")
        is_config = "config/" in norm_path or norm_path.endswith("config.php")

        if not is_env_example and not is_config:
            return findings

        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern in self._DEBUG_TRUE_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue

                # .env.example is documentation - warn differently
                if is_env_example:
                    findings.append(
                        self.create_finding(
                            title="Debug mode enabled in .env.example",
                            context=line.strip()[:60],
                            file=file_path,
                            line_start=i,
                            description=(
                                "`.env.example` shows `APP_DEBUG=true`. While this is documentation, "
                                "developers may copy it directly without changing to `false` in production."
                            ),
                            why_it_matters=(
                                "APP_DEBUG=true in production:\n"
                                "- Exposes sensitive environment variables\n"
                                "- Shows database credentials in error pages\n"
                                "- Reveals application structure and paths\n"
                                "- May expose API keys and secrets\n"
                                "- Major security risk (OWASP Top 10)"
                            ),
                            suggested_fix=(
                                "1. Set APP_DEBUG=false in .env.example as the default:\n"
                                "   APP_DEBUG=false\n\n"
                                "2. Add a comment explaining:\n"
                                "   # Set to true only in local development\n"
                                "   APP_DEBUG=false\n\n"
                                "3. Never commit .env file (add to .gitignore)\n"
                                "4. Use environment-based config in production"
                            ),
                            code_example=(
                                "# .env.example (safe default)\n"
                                "APP_NAME=Laravel\n"
                                "APP_ENV=local\n"
                                "APP_KEY=\n"
                                "APP_DEBUG=false  # Safe default\n"
                                "APP_URL=http://localhost"
                            ),
                            confidence=0.60,
                            tags=["security", "configuration", "debug", "owasp-a6"],
                        )
                    )
                else:
                    findings.append(
                        self.create_finding(
                            title="Debug mode enabled in config",
                            context=line.strip()[:60],
                            file=file_path,
                            line_start=i,
                            description=(
                                "Configuration file has debug mode enabled. "
                                "This should use environment variables and default to false."
                            ),
                            why_it_matters=(
                                "Debug mode in production exposes:\n"
                                "- Stack traces with file paths\n"
                                "- Environment variables and secrets\n"
                                "- Database credentials\n"
                                "- Session data and cookies\n"
                                "- Application internal structure"
                            ),
                            suggested_fix=(
                                "1. Use env() with safe default:\n"
                                "   'debug' => env('APP_DEBUG', false),\n\n"
                                "2. Set APP_DEBUG=false in production .env\n"
                                "3. Use APP_ENV=production in production\n"
                                "4. Consider adding an environment check"
                            ),
                            code_example=(
                                "// config/app.php\n"
                                "'debug' => env('APP_DEBUG', false),\n\n"
                                "// .env (production)\n"
                                "APP_ENV=production\n"
                                "APP_DEBUG=false"
                            ),
                            confidence=0.75,
                            tags=["security", "configuration", "debug", "owasp-a6"],
                        )
                    )
                break

        return findings
