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
            routes = self._dedupe_exact(routes)
            if len(routes) < 2:
                continue
            # Prefer artisan route:list as source-of-truth when present.
            artisan_routes = [r for r in routes if (r.source or "").strip().lower() == "artisan"]
            if artisan_routes:
                routes = self._dedupe_exact(artisan_routes)
                if len(routes) < 2:
                    continue
            # Guard static parser alias artifacts for a single declaration.
            if self._likely_single_declaration_alias(routes):
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

    def _dedupe_exact(self, routes: list[RouteInfo]) -> list[RouteInfo]:
        seen: set[tuple[str, ...]] = set()
        deduped: list[RouteInfo] = []
        for route in routes:
            key = (
                str(route.source or "").strip().lower(),
                str(route.file_path or "").strip(),
                str(int(route.line_number or 0)),
                str(route.controller or "").strip(),
                str(route.action or "").strip(),
                str(route.name or "").strip(),
                ",".join(sorted(str(m).strip() for m in (route.middleware or []))),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(route)
        return deduped

    def _likely_single_declaration_alias(self, routes: list[RouteInfo]) -> bool:
        if len(routes) != 2:
            return False
        first, second = routes
        same_file = (first.file_path or "").strip() == (second.file_path or "").strip()
        same_line = int(first.line_number or 0) == int(second.line_number or 0)
        if not (same_file and same_line):
            return False
        first_has_target = bool((first.controller or "").strip() or (first.action or "").strip())
        second_has_target = bool((second.controller or "").strip() or (second.action or "").strip())
        return first_has_target != second_has_target
