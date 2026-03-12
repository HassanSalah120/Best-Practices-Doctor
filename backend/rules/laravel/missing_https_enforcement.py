"""
Missing HTTPS Enforcement Rule

Detects missing force HTTPS in production configuration.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingHttpsEnforcementRule(Rule):
    id = "missing-https-enforcement"
    name = "Missing HTTPS Enforcement"
    description = "Detects missing force HTTPS configuration for production"
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

    _FORCE_HTTPS_PATTERNS = [
        re.compile(r"forceHttps\s*\(\s*\)", re.IGNORECASE),
        re.compile(r"forceScheme\s*\(\s*['\"]https['\"]\s*\)", re.IGNORECASE),
        re.compile(r"URL::forceScheme\s*\(\s*['\"]https['\"]\s*\)", re.IGNORECASE),
    ]

    _PROVIDER_FILE = "app/Providers/AppServiceProvider.php"

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
        findings: list[Finding] = []

        # Check if project has production routes (indicates production use)
        has_production_routes = len(facts.routes) > 0
        if not has_production_routes:
            return findings

        # Check if AppServiceProvider exists
        has_app_provider = any(
            "AppServiceProvider" in (c.name or "")
            for c in facts.classes
        )

        # Check for force HTTPS in any method call sites
        has_force_https = False
        for m in facts.methods:
            for call in m.call_sites or []:
                if any(pattern.search(call) for pattern in self._FORCE_HTTPS_PATTERNS):
                    has_force_https = True
                    break
            if has_force_https:
                break

        # Check for TrustProxies middleware (Laravel 7+)
        has_trust_proxies = any(
            "TrustProxies" in (c.name or "") or "TrustHosts" in (c.name or "")
            for c in facts.middleware
        )

        # If no force HTTPS found, suggest it
        if not has_force_https and has_app_provider:
            # Find AppServiceProvider file
            app_provider_file = None
            for c in facts.classes:
                if c.name == "AppServiceProvider":
                    app_provider_file = c.file_path
                    break

            findings.append(
                self.create_finding(
                    title="Missing HTTPS enforcement in production",
                    context="AppServiceProvider::boot()",
                    file=app_provider_file or self._PROVIDER_FILE,
                    line_start=1,
                    description=(
                        "No HTTPS enforcement detected. In production, your application "
                        "should force HTTPS to protect sensitive data in transit."
                    ),
                    why_it_matters=(
                        "Without HTTPS enforcement:\n"
                        "- Credentials and tokens sent in plain text\n"
                        "- Session cookies vulnerable to interception\n"
                        "- Man-in-the-middle attacks possible\n"
                        "- GDPR, HIPAA, PCI-DSS require encryption\n"
                        "- Browsers mark HTTP as 'Not Secure'"
                    ),
                    suggested_fix=(
                        "1. Add force HTTPS in AppServiceProvider::boot():\n"
                        "   if (app()->environment('production')) {\n"
                        "       URL::forceScheme('https');\n"
                        "   }\n\n"
                        "2. Configure TrustProxies middleware:\n"
                        "   protected $proxies = '*';\n\n"
                        "3. Set APP_URL with https:// in .env:\n"
                        "   APP_URL=https://yourdomain.com\n\n"
                        "4. Configure session.cookie_secure = true"
                    ),
                    code_example=(
                        "// app/Providers/AppServiceProvider.php\n"
                        "use Illuminate\\Support\\Facades\\URL;\n\n"
                        "public function boot(): void\n"
                        "{\n"
                        "    if (app()->environment('production')) {\n"
                        "        URL::forceScheme('https');\n"
                        "    }\n"
                        "}\n\n"
                        "// config/session.php\n"
                        "'secure' => env('SESSION_SECURE_COOKIE', true),"
                    ),
                    confidence=0.65,
                    tags=["security", "https", "encryption", "owasp-a6"],
                )
            )

        return findings

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []
