"""
Inertia POST Returns Render Rule

Detects POST/PUT/DELETE/PATCH routes where the controller method returns
Inertia::render() instead of redirecting. In Inertia, mutation requests should
redirect (PRG pattern) to prevent duplicate submissions on page refresh.

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


class InertiaPostReturnsRenderRule(Rule):
    id = "inertia-post-returns-render"
    name = "Inertia POST Returns Render"
    description = "Detects mutation routes returning Inertia::render() instead of redirecting"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    type = "ast"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _MUTATION_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

    _INERTIA_RENDER = re.compile(
        r"(?:return\s+)?Inertia::render\s*\(",
        re.IGNORECASE,
    )
    _REDIRECT_PATTERNS = [
        re.compile(r"redirect\s*\(\s*\)\s*->", re.IGNORECASE),
        re.compile(r"return\s+back\s*\(", re.IGNORECASE),
        re.compile(r"back\s*\(\s*\)\s*->", re.IGNORECASE),
        re.compile(r"redirect\s*\(\s*\)\s*->\s*route\s*\(", re.IGNORECASE),
        re.compile(r"Redirect::", re.IGNORECASE),
    ]
    _API_METHOD_PATTERNS = re.compile(
        r"function\s+(apiIndex|jsonResponse|toJson|apiStore|apiUpdate)\s*\(",
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
    confidence = "high"
    fix_suggestion = (
        "After handling a mutation (POST/PUT/DELETE/PATCH), redirect instead of "
        "rendering. Use redirect()->route('...') or back()->with('success', '...'). "
        "This follows the Post-Redirect-Get pattern and prevents duplicate submissions."
    )
    examples = {
        "bad": (
            "// routes/web.php\n"
            "Route::post('/users', [UserController::class, 'store']);\n\n"
            "// UserController.php\n"
            "public function store(Request $request)\n"
            "{\n"
            "    $user = User::create($request->validated());\n"
            "    return Inertia::render('Users/Show', ['user' => $user]);\n"
            "}"
        ),
        "good": (
            "public function store(Request $request)\n"
            "{\n"
            "    $user = User::create($request->validated());\n"
            "    return redirect()->route('users.show', $user);\n"
            "}"
        ),
    }
    priority = 1
    group = "Architecture Integrity"
    applies_to = ["controller"]
    references = []
    related_rules = [
        "inertia-route-returns-json-response",
        "inertia-api-route-returns-inertia",
        "inertia-conditional-wants-json",
    ]
    false_positive_notes = (
        "May fire on validation error handling where the method renders on failure "
        "and redirects on success. The rule skips methods that contain BOTH "
        "Inertia::render() AND redirect()/back() patterns."
    )
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "inertia-post-render"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not is_inertia_project(facts):
            return findings

        for route in facts.routes:
            if route.method.upper() not in self._MUTATION_METHODS:
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

        if self._API_METHOD_PATTERNS.search(method_source):
            return []

        has_inertia = self._INERTIA_RENDER.search(method_source) is not None
        if not has_inertia:
            return []

        has_redirect = any(
            p.search(method_source) is not None for p in self._REDIRECT_PATTERNS
        )
        if has_redirect:
            return []

        line = method_source.count("\n", 0, self._INERTIA_RENDER.search(method_source).start()) + 1
        abs_line = method.line_start - 1 + line

        return [
            self.create_finding(
                title="Mutation route returns Inertia::render() instead of redirect",
                context=method_source[:80].strip(),
                file=file_path,
                line_start=abs_line,
                line_end=method.line_end,
                description=(
                    f"The {method.class_name}::{method.name} method is mapped to a "
                    f"{method_source.split()[0] if method_source.split() else 'mutation'} "
                    f"route but returns Inertia::render() instead of redirecting."
                ),
                why_it_matters=(
                    "Returning Inertia::render() from a mutation request:\n"
                    "- Violates the Post-Redirect-Get pattern\n"
                    "- Causes duplicate submissions on page refresh\n"
                    "- Breaks browser back-button behavior\n"
                    "- Makes the URL not reflect the current state\n"
                    "- Can lead to form resubmission warnings"
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.80,
                tags=["laravel", "inertia", "architecture", "prg-pattern"],
            ),
        ]
