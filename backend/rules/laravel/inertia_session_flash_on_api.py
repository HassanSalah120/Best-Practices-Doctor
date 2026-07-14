"""
Inertia Session Flash on API Rule

Detects API route controllers that mutate session state (flash, put, push, with).
API endpoints should be stateless. Session mutations in API routes break this contract
and cause issues for mobile/third-party consumers.

Uses method-scoped regex: resolves route → MethodInfo → extracts method source
→ scans only that method's content.
"""

from __future__ import annotations

import re

from rules.laravel._inertia_helpers import read_method_source, is_inertia_project
from rules.base import Rule
from schemas.facts import Facts, MethodInfo
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class InertiaSessionFlashOnApiRule(Rule):
    id = "inertia-session-flash-on-api"
    name = "Inertia Session Flash on API"
    description = "Detects API route controllers mutating session state"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    type = "ast"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _SESSION_MUTATION = [
        re.compile(r"session\s*\(\s*\)\s*->\s*(?:flash|put|push)\s*\(", re.IGNORECASE),
        re.compile(r"\$request\s*->\s*session\s*\(\s*\)\s*->\s*(?:flash|put|push)\s*\(", re.IGNORECASE),
        re.compile(r"Session\s*::\s*(?:flash|put|push)\s*\(", re.IGNORECASE),
        re.compile(r"->with\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"session\s*\(\s*\)\s*->\s*flash\s*\(", re.IGNORECASE),
    ]
    _SESSION_READ = re.compile(
        r"session\s*\(\s*\)\s*->\s*(?:get|has|all|exists|pull|forget|remove)\s*\(",
        re.IGNORECASE,
    )
    _SANCTUM_PATTERNS = re.compile(
        r"(?:createToken|tokens\s*->)\s*\(",
        re.IGNORECASE,
    )

    _ALLOWLIST_PATHS = (
        "tests/",
        "/tests/",
        "test/",
        "/test/",
        "vendor/",
        "/vendor/",
        "routes/",
    )

    severity_weight = 0
    confidence = "medium"
    fix_suggestion = (
        "Remove session mutations from API endpoints. API routes should be stateless. "
        "If you need to pass data to the client, include it in the JSON response. "
        "For flash messages, return them as part of the response payload instead."
    )
    examples = {
        "bad": (
            "// routes/api.php\n"
            "Route::post('/api/users', [UserController::class, 'store']);\n\n"
            "// UserController.php\n"
            "public function store(Request $request)\n"
            "{\n"
            "    $user = User::create($request->validated());\n"
            "    session()->flash('success', 'User created');\n"
            "    return response()->json($user);\n"
            "}"
        ),
        "good": (
            "public function store(Request $request)\n"
            "{\n"
            "    $user = User::create($request->validated());\n"
            "    return response()->json([\n"
            "        'data' => $user,\n"
            "        'message' => 'User created',\n"
            "    ]);\n"
            "}"
        ),
    }
    priority = 2
    group = "Architecture Integrity"
    applies_to = ["controller"]
    references = []
    related_rules = [
        "inertia-api-route-returns-inertia",
        "inertia-route-returns-json-response",
    ]
    false_positive_notes = (
        "May fire on controllers that serve both web and API routes. "
        "Method-scoped analysis reduces this risk. Session reads (get/has) are excluded."
    )
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "api-session-mutation"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not is_inertia_project(facts):
            return findings

        for route in facts.routes:
            uri = (route.uri or "").lower()
            route_file = (route.file_path or "").replace("\\", "/").lower()
            if "api/" not in uri and "api" not in route_file:
                continue

            method = self._resolve_method(facts, route)
            if method is None:
                continue

            norm_path = (method.file_path or "").replace("\\", "/").lower()
            if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
                continue

            findings.extend(self._analyze_method(method, facts))

        return findings

    def _resolve_method(self, facts: Facts, route) -> MethodInfo | None:
        controller = route.controller or ""
        action = route.action or "__invoke"
        for m in facts.methods:
            if m.name == action and m.class_name == controller:
                return m
        return None

    def _analyze_method(self, method: MethodInfo, facts: Facts) -> list[Finding]:
        file_path = method.file_path
        if not file_path:
            return []

        method_source = read_method_source(facts, method)
        if not method_source.strip():
            return []

        if self._SANCTUM_PATTERNS.search(method_source):
            return []

        has_session_read = self._SESSION_READ.search(method_source) is not None
        has_session_write = any(
            p.search(method_source) is not None for p in self._SESSION_MUTATION
        )

        if not has_session_write:
            return []

        if has_session_read and not has_session_write:
            return []

        first_match = None
        for p in self._SESSION_MUTATION:
            m = p.search(method_source)
            if m and (first_match is None or m.start() < first_match.start()):
                first_match = m
        if first_match is None:
            return []

        line = method_source.count("\n", 0, first_match.start()) + 1
        abs_line = method.line_start - 1 + line

        return [
            self.create_finding(
                title="API route controller mutates session state",
                context=method_source[:80].strip(),
                file=file_path,
                line_start=abs_line,
                line_end=method.line_end,
                description=(
                    f"The {method.class_name}::{method.name} method is mapped to an "
                    "API route but mutates session state. API endpoints should be stateless."
                ),
                why_it_matters=(
                    "Mutating session in API endpoints:\n"
                    "- Violates the stateless API contract\n"
                    "- Breaks mobile and third-party consumers\n"
                    "- Causes issues with load-balanced deployments\n"
                    "- Makes API responses non-deterministic\n"
                    "- Prevents proper API caching"
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.75,
                tags=["laravel", "inertia", "architecture", "api", "session"],
            ),
        ]
