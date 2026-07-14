"""
Inertia Conditional wantsJson Rule

Detects controller methods that conditionally return either JSON or Inertia
responses based on $request->wantsJson() / $request->expectsJson().

This pattern breaks Inertia's mental model. The correct approach is to have
separate dedicated endpoints for web and API responses.
"""

from __future__ import annotations

import re

from rules.laravel._inertia_helpers import is_inertia_project
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class InertiaConditionalWantsJsonRule(Rule):
    id = "inertia-conditional-wants-json"
    name = "Inertia Conditional wantsJson"
    description = "Detects methods mixing JSON and Inertia responses via wantsJson() conditional"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = ["laravel_inertia_react", "laravel_inertia_vue"]
    regex_file_extensions = [".php"]

    _WANTS_JSON = re.compile(
        r"\$request\s*(?:\(\))?\s*->\s*(?:wantsJson|expectsJson)\s*\(",
        re.IGNORECASE,
    )
    _JSON_RETURN = re.compile(
        r"(?:return\s+)?(?:response\s*\(\s*\)\s*->\s*json|Response::json)\s*\(",
        re.IGNORECASE,
    )
    _INERTIA_RENDER = re.compile(
        r"(?:return\s+)?Inertia::render\s*\(",
        re.IGNORECASE,
    )
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
        "/middleware/",
    )

    severity_weight = 0
    confidence = "high"
    fix_suggestion = (
        "Remove the wantsJson() conditional and split this into two separate endpoints. "
        "Keep the web route returning Inertia::render() and create a dedicated API route in "
        "routes/api.php returning response()->json(). Inertia handles content negotiation "
        "internally — you do not need to do it manually."
    )
    examples = {
        "bad": (
            "public function index(Request $request)\n"
            "{\n"
            "    $users = User::latest()->get();\n"
            "    if ($request->wantsJson()) {\n"
            "        return response()->json($users);\n"
            "    }\n"
            "    return Inertia::render('Users/Index', ['users' => $users]);\n"
            "}"
        ),
        "good": (
            "// routes/web.php\n"
            "Route::get('/users', [UserController::class, 'index']);\n\n"
            "// routes/api.php\n"
            "Route::get('/api/users', [UserApiController::class, 'index']);\n\n"
            "// UserController.php returns only Inertia::render()\n"
            "// UserApiController.php returns only response()->json()"
        ),
    }
    priority = 1
    group = "Architecture Integrity"
    applies_to = ["controller"]
    references = []
    related_rules = [
        "inertia-route-returns-json-response",
        "inertia-api-route-returns-inertia",
        "controller-returning-view-in-api",
    ]
    false_positive_notes = (
        "High confidence. This pattern is almost always an architectural mistake in Inertia "
        "projects. The only legitimate exception is a controller that intentionally serves "
        "both a web frontend and a mobile API from the same codebase with explicit team agreement."
    )
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "inertia-wants-json"}

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

        if self._API_METHOD_PATTERNS.search(content or ""):
            return findings

        text = content or ""
        if not text.strip():
            return findings

        wants_json_found = self._WANTS_JSON.search(text) is not None
        json_return_found = self._JSON_RETURN.search(text) is not None
        inertia_found = self._INERTIA_RENDER.search(text) is not None

        if not (wants_json_found and json_return_found and inertia_found):
            return findings

        match = self._WANTS_JSON.search(text)
        line = text.count("\n", 0, match.start()) + 1

        return [
            self.create_finding(
                title="Inertia controller conditionally mixes JSON and Inertia responses",
                context=text[:80].strip(),
                file=file_path,
                line_start=line,
                description=(
                    "Controller conditionally returns JSON or Inertia responses based on "
                    "$request->wantsJson() / $request->expectsJson(). This creates an "
                    "unpredictable response contract."
                ),
                why_it_matters=(
                    "Mixing response types in a single method:\n"
                    "- Breaks the Inertia protocol expectation\n"
                    "- Makes the endpoint's behavior unpredictable\n"
                    "- Forces frontend to handle both response shapes\n"
                    "- Creates a maintenance burden when the API contract changes\n"
                    "- Makes it hard to add API versioning or documentation"
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.95,
                tags=["laravel", "inertia", "architecture"],
            ),
        ]
