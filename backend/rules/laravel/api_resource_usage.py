"""
API Resource Usage Rule

Heuristic rule: in API controllers, flag returning arrays/response()->json([...]) without using Resources.
This is a lightweight lint rule implemented as regex scanning.
"""

from __future__ import annotations

import re

from core.regex_scan import regex_scan
from schemas.facts import Facts, RouteInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ApiResourceUsageRule(Rule):
    id = "api-resource-usage"
    name = "Prefer API Resources"
    description = "Suggests using Laravel API Resources instead of returning raw arrays from API controllers"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = [
        "laravel_api",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_blade",
        "laravel_livewire",
    ]
    regex_file_extensions = [".php"]
    _ALLOWLIST_PATHS = ("tests/", "/tests/", "vendor/", "/vendor/")

    _CLASS_PATTERN = re.compile(r"class\s+([A-Z][a-zA-Z0-9_]*)", re.IGNORECASE)
    _API_NAMESPACE_PATTERN = re.compile(r"namespace\s+[^;]*\\api(?:\\|;)", re.IGNORECASE)
    _RESOURCE_PATTERNS = [
        re.compile(r"Resource\s*::\s*collection\s*\(", re.IGNORECASE),
        re.compile(r"Resource\s*::\s*make\s*\(", re.IGNORECASE),
        re.compile(r"return\s+new\s+[A-Z][a-zA-Z]*Resource\s*\(", re.IGNORECASE),
        re.compile(r"JsonResource", re.IGNORECASE),
        re.compile(r"AnonymousResourceCollection", re.IGNORECASE),
    ]
    _RAW_ARRAY_PATTERNS = [
        re.compile(r"\breturn\s*\[", re.IGNORECASE),
        re.compile(r"\breturn\s+array\s*\(", re.IGNORECASE),
        re.compile(r"response\s*\(\s*\)\s*->\s*json\s*\(\s*\[", re.IGNORECASE),
    ]
    _UTILITY_ARRAY_HINTS = (
        "'status'",
        "\"status\"",
        "'message'",
        "\"message\"",
        "'success'",
        "\"success\"",
        "'error'",
        "\"error\"",
        "'token'",
        "\"token\"",
        "'meta'",
        "\"meta\"",
    )
    _CONTRACT_ARRAY_HINTS = (
        "'data'",
        "\"data\"",
        "'items'",
        "\"items\"",
        "'results'",
        "\"results\"",
        "'pagination'",
        "\"pagination\"",
        "->toarray(",
    )

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        fp = (file_path or "").replace("\\", "/")
        fp_lower = fp.lower()
        if any(allow in fp_lower for allow in self._ALLOWLIST_PATHS):
            return []

        require_api_context = bool(self.get_threshold("require_api_context", True))
        api_context, api_evidence = self._detect_api_context(file_path, content, facts)
        if require_api_context and not api_context:
            return []

        if not bool(self.get_threshold("flag_raw_array_returns", True)):
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        hits = []
        for hit in regex_scan(content, self._RAW_ARRAY_PATTERNS):
            line = hit.line.strip()
            if not line or line.startswith(("//", "*", "/*", "#")):
                continue
            if any(pattern.search(line) for pattern in self._RESOURCE_PATTERNS):
                continue
            low = line.lower()
            # Standard auth/error utility payloads are acceptable for non-resource responses.
            if any(marker in low for marker in self._UTILITY_ARRAY_HINTS) and not any(
                marker in low for marker in self._CONTRACT_ARRAY_HINTS
            ):
                continue
            confidence = 0.7 if any(marker in low for marker in self._CONTRACT_ARRAY_HINTS) else 0.64
            if confidence + 1e-9 < min_confidence:
                continue
            hits.append((hit, confidence))

        if not hits:
            return []

        out: list[Finding] = []
        for hit, confidence in hits:
            evidence = list(api_evidence)
            evidence.append("raw_array_api_response=true")
            evidence.append("api_contract_boundary=resource_consistency")
            out.append(
                self.create_finding(
                    title="Use API Resources instead of returning raw arrays",
                    context=hit.line.strip()[:80],
                    file=file_path,
                    line_start=hit.line_number,
                    description="Detected an API controller returning an array/JSON payload directly.",
                    why_it_matters=(
                        "API Resources centralize response transformation, ensure consistent serialization, "
                        "and make changes safer across endpoints."
                    ),
                    suggested_fix=(
                        "1. Create a Resource: `php artisan make:resource ...Resource`\n"
                        "2. Return `new ...Resource($model)` or `...Resource::collection($models)`\n"
                        "3. Keep controller response mapping thin and consistent"
                    ),
                    tags=["laravel", "api", "resources"],
                    confidence=confidence,
                    evidence_signals=evidence,
                    metadata={
                        "overlap_group": "api-resource-contract",
                        "overlap_scope": f"{file_path}:{hit.line_number}",
                        "overlap_rank": 70,
                    },
                )
            )
        return out

    def _detect_api_context(self, file_path: str, content: str, facts: Facts) -> tuple[bool, list[str]]:
        evidence: list[str] = []
        fp = (file_path or "").replace("\\", "/").lower()
        if "/http/controllers/api/" in fp:
            evidence.append("api_context=controller_path")
            return True, evidence
        if fp.endswith("apicontroller.php"):
            evidence.append("api_context=controller_name")
            return True, evidence
        if self._API_NAMESPACE_PATTERN.search(content or ""):
            evidence.append("api_context=namespace")
            return True, evidence

        class_match = self._CLASS_PATTERN.search(content or "")
        if not class_match:
            return False, evidence
        class_name = class_match.group(1)
        for route in facts.routes or []:
            if not self._is_api_route(route):
                continue
            controller = str(route.controller or "")
            if class_name.lower() in controller.lower():
                evidence.append("api_context=api_route_controller_match")
                return True, evidence
        return False, evidence

    def _is_api_route(self, route: RouteInfo) -> bool:
        route_file = (route.file_path or "").replace("\\", "/").lower()
        return route_file == "routes/api.php" or route_file.endswith("/routes/api.php")
