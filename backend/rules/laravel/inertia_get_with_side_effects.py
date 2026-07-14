"""
Inertia GET With Side Effects Rule

Detects GET routes where the controller method performs database write operations.
GET requests should be idempotent and safe. Write operations in GET handlers violate
HTTP semantics and can cause unintended data modifications.

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


class InertiaGetWithSideEffectsRule(Rule):
    id = "inertia-get-with-side-effects"
    name = "Inertia GET With Side Effects"
    description = "Detects GET routes performing database write operations"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    type = "ast"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _WRITE_PATTERNS = [
        re.compile(r"->save\s*\(", re.IGNORECASE),
        re.compile(r"->delete\s*\(", re.IGNORECASE),
        re.compile(r"->update\s*\(\s*\[", re.IGNORECASE),
        re.compile(r"[A-Z][a-zA-Z]+::(?:create|insert|update|delete)\s*\(", re.IGNORECASE),
        re.compile(r"DB::(?:table|insert|update|delete)\s*\(", re.IGNORECASE),
        re.compile(r"->forceDelete\s*\(", re.IGNORECASE),
        re.compile(r"->restore\s*\(", re.IGNORECASE),
        re.compile(r"->toggle\s*\(", re.IGNORECASE),
        re.compile(r"->associate\s*\(", re.IGNORECASE),
        re.compile(r"->dissociate\s*\(", re.IGNORECASE),
        re.compile(r"->attach\s*\(", re.IGNORECASE),
        re.compile(r"->detach\s*\(", re.IGNORECASE),
        re.compile(r"->sync\s*\(", re.IGNORECASE),
    ]
    _CACHE_PATTERNS = re.compile(
        r"(?:Cache::|->cache\(|remember\(|Cache\s*::)",
        re.IGNORECASE,
    )
    _LOG_PATTERNS = re.compile(
        r"(?:Log::|logger\(\)->|info\(|debug\(|warning\(|error\()",
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
        "Move write operations to POST/PUT/DELETE/PATCH endpoints. "
        "GET requests should only read data. If you need to update state "
        "on page load, use a separate mutation endpoint triggered by the frontend."
    )
    examples = {
        "bad": (
            "// routes/web.php\n"
            "Route::get('/users/{user}/track', [UserController::class, 'track']);\n\n"
            "// UserController.php\n"
            "public function track(User $user)\n"
            "{\n"
            "    $user->update(['last_viewed_at' => now()]);\n"
            "    return Inertia::render('Users/Show', ['user' => $user]);\n"
            "}"
        ),
        "good": (
            "// routes/web.php — GET only reads\n"
            "Route::get('/users/{user}', [UserController::class, 'show']);\n\n"
            "// routes/api.php — POST for tracking\n"
            "Route::post('/api/users/{user}/track', [UserTrackingController::class, 'track']);"
        ),
    }
    priority = 1
    group = "Architecture Integrity"
    applies_to = ["controller"]
    references = []
    related_rules = [
        "inertia-post-returns-render",
        "inertia-route-returns-json-response",
    ]
    false_positive_notes = (
        "May fire on legitimate patterns like last_seen_at updates, cache warming, "
        "or analytics tracking. Cache and Log writes are excluded. "
        "Acceptable FPs for analytics/tracking — these are still architectural concerns."
    )
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "get-side-effects"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not is_inertia_project(facts):
            return findings

        for route in facts.routes:
            if route.method.upper() != "GET":
                continue

            uri = (route.uri or "").lower()
            route_file = (route.file_path or "").replace("\\", "/").lower()
            if "api/" in uri or "api" in route_file:
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

        if self._CACHE_PATTERNS.search(method_source) and not any(
            p.search(method_source) for p in self._WRITE_PATTERNS
        ):
            return []

        if self._LOG_PATTERNS.search(method_source) and not any(
            p.search(method_source) for p in self._WRITE_PATTERNS
        ):
            return []

        write_matches = []
        for p in self._WRITE_PATTERNS:
            m = p.search(method_source)
            if m:
                write_matches.append(m)

        if not write_matches:
            return []

        first_match = min(write_matches, key=lambda m: m.start())
        line = method_source.count("\n", 0, first_match.start()) + 1
        abs_line = method.line_start - 1 + line

        return [
            self.create_finding(
                title="GET route performs database write operation",
                context=method_source[:80].strip(),
                file=file_path,
                line_start=abs_line,
                line_end=method.line_end,
                description=(
                    f"The {method.class_name}::{method.name} method is mapped to a "
                    "GET route but performs database write operations. GET requests "
                    "should be idempotent and safe."
                ),
                why_it_matters=(
                    "Write operations in GET handlers:\n"
                    "- Violates HTTP idempotency semantics\n"
                    "- Causes unintended data modifications on page refresh\n"
                    "- Breaks browser prefetch and link prerendering\n"
                    "- Can be exploited via CSRF (GET requests don't need CSRF tokens)\n"
                    "- Makes caching unpredictable"
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.65,
                tags=["laravel", "inertia", "architecture", "http-semantics"],
            ),
        ]
