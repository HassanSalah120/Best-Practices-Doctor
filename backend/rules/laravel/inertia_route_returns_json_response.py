"""
Inertia Route Returns JSON Response Rule

Detects web route controllers that return JSON responses instead of
Inertia::render(). In an Inertia project, web routes should return Inertia
pages, not raw JSON. JSON responses from web routes break the Inertia protocol.

This is a cross-file rule: it correlates routes (facts.routes) with controller
method file content to find mismatches.
"""

from __future__ import annotations

import re

from rules.laravel._inertia_helpers import is_inertia_project, is_web_route, route_targets_controller_file
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class InertiaRouteReturnsJsonResponseRule(Rule):
    id = "inertia-route-returns-json-response"
    name = "Inertia Route Returns JSON Response"
    description = "Detects web route controllers returning JSON instead of Inertia responses"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _JSON_RETURN = re.compile(
        r"(?:return\s+)?(?:response\s*\(\s*\)\s*->\s*json|Response::json)\s*\(",
        re.IGNORECASE,
    )
    _JSON_ENCODE = re.compile(r"return\s+json_encode\s*\(", re.IGNORECASE)
    _JSON_RESOURCE = re.compile(r"return\s+new\s+JsonResponse", re.IGNORECASE)
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

    _SKIP_CONTROLLER_NAMES = (
        "health",
        "healthcheck",
        "health_check",
        "status",
        "ping",
        "heartbeat",
    )

    _SKIP_METHOD_NAMES = (
        "health",
        "healthcheck",
        "health_check",
        "status",
        "ping",
        "heartbeat",
    )

    severity_weight = 0
    confidence = "high"
    fix_suggestion = (
        "Replace the JSON return with Inertia::render(). "
        "If this endpoint needs to serve API consumers, create a dedicated API route "
        "in routes/api.php with a separate controller returning response()->json(). "
        "Web routes in Inertia projects should only return Inertia pages."
    )
    examples = {
        "bad": (
            "// routes/web.php\n"
            "Route::get('/users', [UserController::class, 'index']);\n\n"
            "// UserController.php\n"
            "public function index()\n"
            "{\n"
            "    $users = User::all();\n"
            "    return response()->json($users);\n"
            "}"
        ),
        "good": (
            "// UserController.php\n"
            "public function index()\n"
            "{\n"
            "    $users = User::all();\n"
            "    return Inertia::render('Users/Index', ['users' => $users]);\n"
            "}"
        ),
    }
    priority = 1
    group = "Architecture Integrity"
    applies_to = ["controller"]
    references = []
    related_rules = [
        "inertia-conditional-wants-json",
        "inertia-api-route-returns-inertia",
        "controller-returning-view-in-api",
    ]
    false_positive_notes = (
        "This rule may fire if a controller serves both web and API routes but the "
        "file path does not indicate 'api'. Ensure controllers dedicated to API "
        "responses are in an 'Api' subdirectory or named with 'Api' prefix."
    )
    detection_type = "cross-file"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "inertia-json-in-web-route"}

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

        # Check for JSON return patterns
        has_json_return = bool(
            self._JSON_RETURN.search(text)
            or self._JSON_ENCODE.search(text)
            or self._JSON_RESOURCE.search(text)
        )
        if not has_json_return:
            return findings

        # Skip controllers in Api namespace (API controllers SHOULD return JSON)
        if "/api/" in norm_path:
            return findings
        if re.search(r"namespace\s+[^;]+\\\\api(\\\\|;)", content or "", re.IGNORECASE):
            return findings

        # Extract controller class name from file path
        basename = (file_path or "").replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[0]
        if not basename.endswith("Controller"):
            return findings

        # Skip health check and similar controllers
        controller_lower = basename.lower()
        if any(skip in controller_lower for skip in self._SKIP_CONTROLLER_NAMES):
            return findings

        # Skip controllers that look like they're for realtime/game state updates
        realtime_keywords = {"historie", "history", "game", "state", "realtime", "ajax", "api"}
        if any(keyword in controller_lower for keyword in realtime_keywords):
            return findings

        # Check if any WEB routes point to this controller
        has_web_route = False
        for r in facts.routes:
            if route_targets_controller_file(r, file_path, facts) and is_web_route(r):
                has_web_route = True
                break

        if not has_web_route:
            return findings

        # Find the first JSON pattern match for line number
        match = self._JSON_RETURN.search(text)
        if not match:
            match = self._JSON_ENCODE.search(text)
        if not match:
            match = self._JSON_RESOURCE.search(text)
        line = text.count("\n", 0, match.start()) + 1

        return [
            self.create_finding(
                title="Web route controller returning JSON instead of Inertia response",
                context=text[:80].strip(),
                file=file_path,
                line_start=line,
                description=(
                    "This controller is registered on a web route but returns a JSON "
                    "response instead of Inertia::render(). In Inertia projects, web "
                    "routes should return Inertia pages."
                ),
                why_it_matters=(
                    "Returning JSON from a web route in an Inertia project:\n"
                    "- Breaks the Inertia protocol on the frontend\n"
                    "- Forces the frontend to handle unexpected JSON responses\n"
                    "- Makes the response contract inconsistent\n"
                    "- Bypasses Inertia's automatic page rendering\n"
                    "- Creates confusion between web and API responsibilities"
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.85,
                tags=["laravel", "inertia", "architecture"],
            ),
        ]
