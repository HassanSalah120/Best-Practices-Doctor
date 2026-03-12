"""
Controller Returning View in API Rule

Detects API controllers returning Blade views instead of JSON responses.
"""

from __future__ import annotations

import re

from schemas.facts import Facts, RouteInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ControllerReturningViewInApiRule(Rule):
    id = "controller-returning-view-in-api"
    name = "Controller Returning View in API"
    description = "Detects API routes returning Blade views instead of JSON responses"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = [
        "laravel_api",
        "laravel_inertia_react",
        "laravel_inertia_vue",
    ]
    regex_file_extensions = [".php"]

    # Patterns indicating view return
    _VIEW_PATTERNS = [
        re.compile(r"return\s+view\s*\(", re.IGNORECASE),
        re.compile(r"return\s+View::make\s*\(", re.IGNORECASE),
        re.compile(r"return\s+view\s*\(\s*['\"]", re.IGNORECASE),
        re.compile(r"response\s*\(\s*\)\s*->\s*view\s*\(", re.IGNORECASE),
    ]

    # Patterns for JSON/API responses (safe)
    _API_RESPONSE_PATTERNS = [
        re.compile(r"return\s+response\s*\(\s*\)\s*->\s*json", re.IGNORECASE),
        re.compile(r"return\s+response\s*\(\)\s*->\s*json", re.IGNORECASE),
        re.compile(r"return\s+json_encode\s*\(", re.IGNORECASE),
        re.compile(r"return\s+new\s+JsonResponse", re.IGNORECASE),
        re.compile(r"return\s+\$[a-zA-Z_]+\s*;", re.IGNORECASE),  # Direct return (likely model/array)
        re.compile(r"return\s+[a-zA-Z_]+Resource::", re.IGNORECASE),  # API Resource
    ]

    _ALLOWLIST_PATHS = (
        "tests/",
        "/tests/",
        "test/",
        "/test/",
        "vendor/",
        "/vendor/",
    )

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

        # Skip allowlisted paths
        norm_path = (file_path or "").replace("\\", "/").lower()
        if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
            return findings

        # Only check API controllers
        is_api_controller = (
            "api" in norm_path or
            "/api/" in norm_path or
            "ApiController" in file_path or
            "Api\\" in file_path.replace("/", "\\")
        )

        if not is_api_controller:
            # Check if routes indicate this is an API endpoint
            is_api_route = any(
                "api/" in (r.uri or "").lower()
                for r in facts.routes
                if r.file_path == file_path
            )
            if not is_api_route:
                return findings

        text = content or ""
        lines = text.split("\n")

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            # Check for view return patterns
            has_view_return = any(pattern.search(line) for pattern in self._VIEW_PATTERNS)
            if not has_view_return:
                continue

            # Check if this is in a controller method
            if "function " not in text and "public function" not in text:
                continue

            findings.append(
                self.create_finding(
                    title="API controller returning Blade view",
                    context=line.strip()[:60],
                    file=file_path,
                    line_start=i,
                    description=(
                        "Detected a view() return in what appears to be an API controller. "
                        "API endpoints should return JSON responses, not Blade views."
                    ),
                    why_it_matters=(
                        "Returning views from API endpoints:\n"
                        "- Breaks API contract expectations\n"
                        "- Clients expect JSON, receive HTML\n"
                        "- Makes integration with frontend/mobile difficult\n"
                        "- Violates REST API conventions\n"
                        "- Can expose server-side templates to API consumers"
                    ),
                    suggested_fix=(
                        "1. Return JSON responses instead:\n"
                        "   return response()->json(['data' => $data]);\n\n"
                        "2. Use API Resources for transformation:\n"
                        "   return UserResource::collection($users);\n\n"
                        "3. For Inertia apps, return Inertia::render():\n"
                        "   return Inertia::render('Users/Index', ['users' => $users]);\n\n"
                        "4. Move view returns to web routes/controllers"
                    ),
                    code_example=(
                        "// Before (API returning view - wrong)\n"
                        "class ApiUserController extends Controller\n"
                        "{\n"
                        "    public function index()\n"
                        "    {\n"
                        "        $users = User::all();\n"
                        "        return view('users.index', compact('users'));\n"
                        "    }\n"
                        "}\n\n"
                        "// After (API returning JSON - correct)\n"
                        "class ApiUserController extends Controller\n"
                        "{\n"
                        "    public function index()\n"
                        "    {\n"
                        "        $users = User::all();\n"
                        "        return UserResource::collection($users);\n"
                        "        // or: return response()->json(['data' => $users]);\n"
                        "    }\n"
                        "}"
                    ),
                    confidence=0.75,
                    tags=["architecture", "api", "rest", "laravel"],
                )
            )

        return findings
