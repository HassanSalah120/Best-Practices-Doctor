"""
Duplicate Route Definition Rule

Detects duplicate HTTP method + URI definitions across routes files.
"""

from __future__ import annotations

from collections import defaultdict

from schemas.facts import Facts, RouteInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class DuplicateRouteDefinitionRule(Rule):
    id = "duplicate-route-definition"
    name = "Duplicate Route Definition"
    description = "Detects duplicate route method/URI definitions"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        by_key: dict[tuple[str, str], list[RouteInfo]] = defaultdict(list)

        for r in facts.routes:
            method = (r.method or "").strip().upper()
            uri = (r.uri or "").strip()
            if not method or not uri:
                continue
            if not uri.startswith("/"):
                uri = "/" + uri
            if len(uri) > 1:
                uri = uri.rstrip("/")
            by_key[(method, uri)].append(r)

        findings: list[Finding] = []
        for (method, uri), routes in by_key.items():
            if len(routes) < 2:
                continue

            routes = sorted(routes, key=lambda x: (x.file_path or "", int(x.line_number or 0)))
            first = routes[0]
            locs = [f"{r.file_path}:{int(r.line_number or 0)}" for r in routes[:8]]
            more = f" (+{len(routes) - 8} more)" if len(routes) > 8 else ""

            findings.append(
                self.create_finding(
                    title=f"Duplicate route definition for {method} {uri}",
                    context=f"{method}:{uri}",
                    file=first.file_path,
                    line_start=int(first.line_number or 1),
                    description=(
                        f"Found {len(routes)} definitions for `{method} {uri}`. "
                        f"Locations: {', '.join(locs)}{more}."
                    ),
                    why_it_matters=(
                        "Duplicate routes make behavior order-dependent and can shadow earlier handlers. "
                        "This causes hard-to-debug production behavior and inconsistent middleware coverage."
                    ),
                    suggested_fix=(
                        "Keep one canonical route per HTTP method + URI.\n"
                        "Merge handlers if needed, or change URI/name to make intent explicit.\n"
                        "Ensure middleware and controller target are consistent after deduplication."
                    ),
                    related_files=sorted({r.file_path for r in routes if r.file_path}),
                    tags=["laravel", "routes", "architecture"],
                    confidence=0.95,
                )
            )

        return findings

