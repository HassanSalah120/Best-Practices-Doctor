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
    _NON_IMPLEMENTATION_PATH_MARKERS = ("/contracts/", "/interfaces/")
    _SELF_SERVICE_PATH = re.compile(
        r"(register|registration|signup|sign-up|onboarding|invite|invitation|auth)",
        re.IGNORECASE,
    )
    _SELF_SERVICE_URI = re.compile(
        r"(register|registration|signup|sign-up|onboarding|invite|invitation|verify|verification|password|forgot|reset)",
        re.IGNORECASE,
    )
    _ADMIN_URI = re.compile(r"(^|/)(admin|internal|backoffice|staff)(/|$)", re.IGNORECASE)
    _CLASS_PATTERN = re.compile(r"class\s+([A-Z][A-Za-z0-9_]*)", re.IGNORECASE)
    _INTERFACE_PATTERN = re.compile(r"\binterface\s+[A-Z][A-Za-z0-9_]*", re.IGNORECASE)
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
        if any(marker in norm for marker in self._NON_IMPLEMENTATION_PATH_MARKERS):
            return []
        if self._INTERFACE_PATTERN.search(content or ""):
            return []
        create_match = self._USER_CREATE.search(content or "")
        if not create_match:
            return []
        if self._REGISTERED_EVENT.search(content or ""):
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        min_self_service_signals = int(self.get_threshold("min_self_service_signals", 1) or 1)
        require_self_service_context = bool(self.get_threshold("require_self_service_context", True))
        suppress_admin_only_flows = bool(self.get_threshold("suppress_admin_only_flows", True))

        class_name = self._extract_class_name(content or "")
        self_service_signals, admin_signals = self._collect_context_signals(norm, class_name, facts)
        if require_self_service_context and len(self_service_signals) < min_self_service_signals:
            return []
        if suppress_admin_only_flows and admin_signals:
            has_guest_or_public = any(
                s in self_service_signals
                for s in ("route_middleware=guest", "route_self_service_uri=true", "path_auth_context=true")
            )
            if not has_guest_or_public:
                return []

        confidence = 0.62 + min(0.24, len(self_service_signals) * 0.08)
        if admin_signals:
            confidence -= 0.12
        confidence = max(0.0, min(0.96, confidence))
        if confidence + 1e-9 < min_confidence:
            return []

        line_no = (content or "").count("\n", 0, max(0, create_match.start())) + 1
        evidence = [
            f"file={file_path}",
            "user_creation_detected=true",
            "registered_event_missing=true",
            f"self_service_signal_count={len(self_service_signals)}",
            f"admin_signal_count={len(admin_signals)}",
        ]
        evidence.extend(self_service_signals[:4])
        evidence.extend(admin_signals[:2])

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
                confidence=confidence,
                evidence_signals=evidence,
            )
        ]

    def _extract_class_name(self, content: str) -> str:
        match = self._CLASS_PATTERN.search(content or "")
        return match.group(1) if match else ""

    def _collect_context_signals(self, norm_path: str, class_name: str, facts: Facts) -> tuple[list[str], list[str]]:
        self_service: list[str] = []
        admin_only: list[str] = []

        if self._SELF_SERVICE_PATH.search(norm_path):
            self_service.append("path_self_service_hint=true")
        if "/auth/" in norm_path:
            self_service.append("path_auth_context=true")
        if "/admin/" in norm_path or "/internal/" in norm_path:
            admin_only.append("path_admin_context=true")

        class_name_low = class_name.lower()
        for route in facts.routes or []:
            controller_ref = str(route.controller or route.action or "")
            if class_name_low and class_name_low not in controller_ref.lower():
                continue
            uri = str(route.uri or "").lower()
            middleware = " ".join(str(x).lower() for x in (route.middleware or []))

            if self._SELF_SERVICE_URI.search(uri):
                self_service.append("route_self_service_uri=true")
            if "guest" in middleware:
                self_service.append("route_middleware=guest")

            if self._ADMIN_URI.search(uri) or "admin" in middleware or "staff" in middleware:
                admin_only.append("route_admin_or_staff=true")

        return self_service, admin_only
