"""
User Model Missing MustVerifyEmail Rule

Detects Laravel user models that extend Authenticatable but do not implement MustVerifyEmail.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class UserModelMissingMustVerifyEmailRule(Rule):
    id = "user-model-missing-must-verify-email"
    name = "User Model Missing MustVerifyEmail"
    description = "Detects User models that do not implement Laravel email verification"
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

    _USER_MODEL_PATH = re.compile(r"(^|/)(app/)?models/user\.php$", re.IGNORECASE)
    _AUTHENTICATABLE_CLASS = re.compile(
        r"class\s+User\b[^{\n]*extends\s+(?:\\?[A-Za-z_][A-Za-z0-9_\\]*\\)?Authenticatable\b",
        re.IGNORECASE,
    )
    _IMPLEMENTS_MUST_VERIFY = re.compile(r"implements[^{\n]*\bMustVerifyEmail\b", re.IGNORECASE)
    # Detect when MustVerifyEmail is intentionally disabled via comment
    _INTENTIONALLY_DISABLED = re.compile(
        r"//\s*use\s+Illuminate\\Contracts\\Auth\\MustVerifyEmail|//\s*implements.*MustVerifyEmail",
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
        norm = (file_path or "").replace("\\", "/")
        if not self._USER_MODEL_PATH.search(norm):
            return []
        if not self._AUTHENTICATABLE_CLASS.search(content or ""):
            return []
        if self._IMPLEMENTS_MUST_VERIFY.search(content or ""):
            return []
        # Skip if MustVerifyEmail is intentionally disabled (commented out)
        if self._INTENTIONALLY_DISABLED.search(content or ""):
            return []

        return [
            self.create_finding(
                title="User model does not implement MustVerifyEmail",
                context="App\\Models\\User",
                file=file_path,
                line_start=1,
                description=(
                    "Detected a Laravel `User` model extending `Authenticatable` without `MustVerifyEmail`."
                ),
                why_it_matters=(
                    "Without email verification on the user model, `verified` middleware and Laravel's"
                    " built-in verification flow cannot reliably protect sensitive areas."
                ),
                suggested_fix=(
                    "Implement `Illuminate\\Contracts\\Auth\\MustVerifyEmail` on the User model and"
                    " ensure verification notifications/events are enabled in onboarding flows."
                ),
                tags=["laravel", "security", "email-verification", "auth"],
                confidence=0.92,
                evidence_signals=[
                    f"file={file_path}",
                    "extends_authenticatable=true",
                    "implements_mustverifyemail=false",
                ],
            )
        ]
