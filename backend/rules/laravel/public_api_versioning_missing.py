"""
Public API Versioning Missing Rule

Detects public API routes that do not appear versioned.
"""

from __future__ import annotations

import re

from rules.base import Rule
from rules.laravel._route_helpers import is_api_route_file
from schemas.facts import Facts, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class PublicApiVersioningMissingRule(Rule):
    id = "public-api-versioning-missing"
    name = "Public API Versioning Missing"
    description = "Detects public API routes that do not expose a versioned URI surface"
    category = Category.COMPATIBILITY
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _AUTH_TOKENS = ("auth", "sanctum", "verified", "signed")
    _VERSION_RE = re.compile(r"^(?:api/)?v\d+(?:/|$)", re.IGNORECASE)
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Move the public api versioning missing responsibility into the appropriate service, action, repository, or boundary object. Keep controllers and UI components focused on orchestration only.'
    examples = {}
    priority = 3
    group = 'API Design'
    applies_to = ['route']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'architecture', 'concern': 'public-api-versioning'}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        routes = list(getattr(facts, "routes", []) or [])
        has_versioned_contract = any(
            self._VERSION_RE.search(str(route.uri or "").strip().lstrip("/"))
            for route in routes
            if self._is_api_surface(route)
        )
        project_context = getattr(facts, "project_context", None)
        api_first = str(
            getattr(project_context, "backend_architecture_profile", "unknown") or "unknown"
        ).lower() == "api-first"
        assume_public = bool(self.get_threshold("assume_api_routes_public", False))

        for route in routes:
            if not self._is_public_api_route(route):
                continue
            if not (
                assume_public
                or api_first
                or has_versioned_contract
                or self._has_explicit_public_marker(route)
            ):
                continue
            uri = str(route.uri or "").strip().lstrip("/")
            if self._VERSION_RE.search(uri):
                continue

            confidence = 0.84 if uri.startswith("api/") or is_api_route_file(route) else 0.76
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="Public API route is not versioned",
                    file=route.file_path,
                    line_start=int(getattr(route, "line_number", 1) or 1),
                    context=f"{str(route.method or '').upper()} {route.uri}",
                    description=(
                        f"Public API route `{str(route.method or '').upper()} {route.uri}` does not show a versioned URI segment such as `/api/v1/...`."
                    ),
                    why_it_matters=(
                        "Versioned public APIs make breaking changes safer and help clients adopt new behavior gradually."
                    ),
                    suggested_fix="Expose public API routes under an explicit version prefix such as `/api/v1/...`.",
                    confidence=confidence,
                    tags=["laravel", "api", "versioning"],
                    evidence_signals=["public_api_route=true", "api_version_prefix_missing=true"],
                ),
            )

        return findings

    def _is_public_api_route(self, route: RouteInfo) -> bool:
        uri = str(route.uri or "").strip().lstrip("/").lower()
        middleware = " ".join(str(item or "").lower() for item in (route.middleware or []))
        is_api_surface = uri.startswith("api/") or is_api_route_file(route) or " api " in f" {middleware} "
        if not is_api_surface:
            return False
        return not any(token in middleware for token in self._AUTH_TOKENS)

    @staticmethod
    def _is_api_surface(route: RouteInfo) -> bool:
        uri = str(route.uri or "").strip().lstrip("/").lower()
        middleware = " ".join(str(item or "").lower() for item in (route.middleware or []))
        return uri.startswith("api/") or is_api_route_file(route) or " api " in f" {middleware} "

    @staticmethod
    def _has_explicit_public_marker(route: RouteInfo) -> bool:
        name = str(route.name or "").lower()
        middleware = " ".join(str(item or "").lower() for item in (route.middleware or []))
        return name.startswith(("public.", "external.")) or any(
            marker in middleware for marker in ("public-api", "external-api")
        )
