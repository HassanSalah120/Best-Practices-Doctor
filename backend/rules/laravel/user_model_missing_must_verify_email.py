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

        skip_for_token_api_only = bool(self.get_threshold("skip_for_token_api_only", True))
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        token_api_only = self._is_token_api_only_context(facts)
        if skip_for_token_api_only and token_api_only:
            return []

        confidence = 0.92
        if str(getattr(facts.project_context, "backend_architecture_profile", "") or "").lower() == "api-first":
            confidence -= 0.08
        if str(getattr(facts.project_context, "project_business_context", "") or "").lower() == "api_backend":
            confidence -= 0.05
        confidence = max(0.0, min(0.96, confidence))
        if confidence + 1e-9 < min_confidence:
            return []

        evidence = [
            f"file={file_path}",
            "extends_authenticatable=true",
            "implements_mustverifyemail=false",
            f"token_api_only_context={'true' if token_api_only else 'false'}",
        ]

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
                confidence=confidence,
                evidence_signals=evidence,
            )
        ]

    def _is_token_api_only_context(self, facts: Facts) -> bool:
        routes = list(facts.routes or [])
        profile = str(getattr(facts.project_context, "backend_architecture_profile", "") or "").lower()
        project_type = str(getattr(facts.project_context, "project_business_context", "") or "").lower()
        is_api_context = profile == "api-first" or project_type == "api_backend"
        if not is_api_context:
            return False
        if self._has_email_verification_signal(routes):
            return False
        if not routes:
            return True

        token_auth_routes = 0
        non_api_routes = 0
        for route in routes:
            route_file = (route.file_path or "").replace("\\", "/").lower()
            if not (route_file == "routes/api.php" or route_file.endswith("/routes/api.php")):
                non_api_routes += 1

            uri = str(route.uri or "").lower()
            middleware_txt = " ".join(str(x).lower() for x in (route.middleware or []))
            if any(tok in middleware_txt for tok in ("sanctum", "passport", "jwt", "token")):
                token_auth_routes += 1
            elif any(tok in uri for tok in ("token", "login", "auth")):
                token_auth_routes += 1

        return non_api_routes == 0 and token_auth_routes > 0

    def _has_email_verification_signal(self, routes: list) -> bool:
        for route in routes:
            uri = str(route.uri or "").lower()
            action = str(route.action or "").lower()
            if "verify" in uri or "verification" in uri:
                return True
            if "verify" in action or "verification" in action:
                return True
        return False
