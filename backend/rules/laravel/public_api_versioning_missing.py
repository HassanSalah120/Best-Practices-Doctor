"""
Public API Versioning Missing Rule

Detects public API routes that do not appear versioned.
"""

from __future__ import annotations

import re

from schemas.facts import Facts, RouteInfo
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class PublicApiVersioningMissingRule(Rule):
    id = "public-api-versioning-missing"
    name = "Public API Versioning Missing"
    description = "Detects public API routes that do not expose a versioned URI surface"
    category = Category.LARAVEL_BEST_PRACTICE
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

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for route in (getattr(facts, "routes", []) or []):
            if not self._is_public_api_route(route):
                continue
            uri = str(route.uri or "").strip().lstrip("/")
            if self._VERSION_RE.search(uri):
                continue

            confidence = 0.84 if uri.startswith("api/") or str(route.file_path or "").lower().endswith("routes/api.php") else 0.76
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="Public API route is not versioned",
                    file=route.file_path or "routes/api.php",
                    line_start=int(route.line_number or 1),
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
                )
            )

        return findings

    def _is_public_api_route(self, route: RouteInfo) -> bool:
        uri = str(route.uri or "").strip().lstrip("/").lower()
        middleware = " ".join(str(item or "").lower() for item in (route.middleware or []))
        file_path = str(route.file_path or "").lower().replace("\\", "/")
        is_api_surface = uri.startswith("api/") or file_path.endswith("routes/api.php") or " api " in f" {middleware} "
        if not is_api_surface:
            return False
        if any(token in middleware for token in self._AUTH_TOKENS):
            return False
        return True
