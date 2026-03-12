"""
Registration Missing Registered Event Rule

Detects onboarding/self-service registration flows that create users but never dispatch
Laravel's Registered event.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class RegistrationMissingRegisteredEventRule(Rule):
    id = "registration-missing-registered-event"
    name = "Registration Missing Registered Event"
    description = "Detects user registration flows that create users without dispatching Registered"
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

    _ALLOWLIST = ("/tests/", "/test/", "/vendor/", "/database/", "/factory", "/seed")
    _SELF_SERVICE_PATH = re.compile(
        r"(register|registration|signup|sign-up|onboarding|invite|invitation|auth|createclinic|clinic)",
        re.IGNORECASE,
    )
    _USER_CREATE = re.compile(
        r"(User\s*::\s*(query\s*\(\)\s*->\s*)?(create|forceCreate)\s*\()|(\bnew\s+User\b)",
        re.IGNORECASE,
    )
    _REGISTERED_EVENT = re.compile(
        r"(event\s*\(\s*new\s+Registered\s*\()|(Registered\s*::\s*dispatch\s*\()|(dispatch\s*\(\s*new\s+Registered\s*\()",
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
        if "/app/" not in f"/{norm}":
            return []
        if not self._SELF_SERVICE_PATH.search(norm):
            return []
        if not self._USER_CREATE.search(content or ""):
            return []
        if self._REGISTERED_EVENT.search(content or ""):
            return []

        idx = (content or "").find("User")
        line_no = (content or "").count("\n", 0, max(0, idx)) + 1 if idx >= 0 else 1
        return [
            self.create_finding(
                title="Registration flow appears to miss Laravel Registered event dispatch",
                context=norm,
                file=file_path,
                line_start=line_no,
                description=(
                    "Detected a likely self-service onboarding/registration flow creating a `User`"
                    " without dispatching Laravel's `Registered` event."
                ),
                why_it_matters=(
                    "If `Registered` is not dispatched, email verification notifications and related"
                    " onboarding hooks may never run, leaving sensitive routes insufficiently protected."
                ),
                suggested_fix=(
                    "Dispatch `event(new Registered($user))` after creating self-service users and"
                    " keep billing/account routes behind `verified` middleware."
                ),
                tags=["laravel", "security", "email-verification", "registration"],
                confidence=0.76,
                evidence_signals=[
                    f"file={file_path}",
                    "user_creation_detected=true",
                    "registered_event_missing=true",
                ],
            )
        ]
