"""
Inertia API Route Returns Inertia Rule

Detects API route controllers that return Inertia::render() instead of JSON
responses. API endpoints should return structured JSON, not Inertia pages.

This is a cross-file rule: it correlates routes (facts.routes) with controller
method file content to find mismatches.
"""

from __future__ import annotations

import re

from rules.laravel._inertia_helpers import is_api_route, is_inertia_project, route_targets_controller_file
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class InertiaApiRouteReturnsInertiaRule(Rule):
    id = "inertia-api-route-returns-inertia"
    name = "Inertia API Route Returns Inertia"
    description = "Detects API route controllers returning Inertia::render() instead of JSON"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _INERTIA_RENDER = re.compile(
        r"(?:return\s+)?Inertia::render\s*\(",
        re.IGNORECASE,
    )
    _WANTS_JSON = re.compile(
        r"\$request\s*(?:\(\))?\s*->\s*(?:wantsJson|expectsJson)\s*\(",
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

    _API_METHOD_PATTERNS = re.compile(
        r"function\s+(apiIndex|jsonResponse|toJson|apiStore|apiUpdate)\s*\(",
        re.IGNORECASE,
    )

    severity_weight = 0
    confidence = "high"
    fix_suggestion = (
        "Replace Inertia::render() with a JSON response (response()->json() or an API Resource). "
        "API routes should return structured JSON data, not rendered Inertia pages. "
        "If the page needs to be accessible from both web and API, split into "
        "separate controllers for each responsibility."
    )
    examples = {
        "bad": (
            "// routes/api.php\n"
            "Route::get('/api/users', [UserController::class, 'index']);\n\n"
            "// UserController.php\n"
            "public function index()\n"
            "{\n"
            "    $users = User::all();\n"
            "    return Inertia::render('Users/Index', ['users' => $users]);\n"
            "}"
        ),
        "good": (
            "// UserController.php\n"
            "public function index()\n"
            "{\n"
            "    $users = User::all();\n"
            "    return response()->json(['data' => $users]);\n"
            "}"
        ),
    }
    priority = 1
    group = "Architecture Integrity"
    applies_to = ["controller"]
    references = []
    related_rules = [
        "inertia-conditional-wants-json",
        "inertia-route-returns-json-response",
        "controller-returning-view-in-api",
    ]
    false_positive_notes = (
        "This rule fires for API routes that return Inertia::render(). If your API "
        "endpoint intentionally returns an Inertia page (e.g., for server-side rendering), "
        "move it to routes/web.php or prefix the method name with 'api' to suppress."
    )
    detection_type = "cross-file"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "inertia-in-api-route"}

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
        findings: list[Finding] = []

        if not is_inertia_project(facts, file_path):
            return findings

        norm_path = (file_path or "").replace("\\", "/").lower()
        if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
            return findings

        text = content or ""
        if not text.strip():
            return findings

        # Skip if already caught by Rule 2 (wantsJson conditional mixing)
        if self._WANTS_JSON.search(text):
            return findings

        # Skip API-specific method names
        if self._API_METHOD_PATTERNS.search(text):
            return findings

        # Skip controllers in Api namespace (API controllers should return JSON)
        # Also skip service providers
        if "/api/" in norm_path or "/providers/" in norm_path:
            return findings

        # Check for Api namespace declaration in content
        if re.search(r"namespace\s+[^;]+\\\\api(\\\\|;)", content or "", re.IGNORECASE):
            return findings

        # Check for Inertia::render pattern
        inertia_match = self._INERTIA_RENDER.search(text)
        if not inertia_match:
            return findings

        # Extract controller class name from file path
        basename = (file_path or "").replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[0]
        if not basename.endswith("Controller"):
            return findings

        # Check if any API routes point to this controller
        has_api_route = False
        for r in facts.routes:
            if route_targets_controller_file(r, file_path, facts) and is_api_route(r):
                has_api_route = True
                break

        if not has_api_route:
            return findings

        line = text.count("\n", 0, inertia_match.start()) + 1

        return [
            self.create_finding(
                title="API route controller returning Inertia::render() instead of JSON",
                context=text[:80].strip(),
                file=file_path,
                line_start=line,
                description=(
                    "This controller is registered on an API route but returns "
                    "Inertia::render() instead of a JSON response. API endpoints "
                    "should return structured JSON data."
                ),
                why_it_matters=(
                    "Returning Inertia::render() from an API route:\n"
                    "- Sends HTML/JS page content instead of structured JSON data\n"
                    "- Breaks API contracts for mobile or third-party consumers\n"
                    "- Makes the endpoint unusable for non-browser clients\n"
                    "- Violates REST API conventions\n"
                    "- Prevents API versioning and documentation"
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.85,
                tags=["laravel", "inertia", "architecture"],
            ),
        ]
