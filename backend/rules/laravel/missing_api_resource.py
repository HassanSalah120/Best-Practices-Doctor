"""
Missing API Resource Rule

Detects API endpoints returning raw model data instead of using API Resources.
"""

from __future__ import annotations

import re

from schemas.facts import Facts, RouteInfo, QueryUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingApiResourceRule(Rule):
    id = "missing-api-resource"
    name = "Missing API Resource"
    description = "Detects API endpoints returning raw model data instead of using API Resources"
    category = Category.ARCHITECTURE
    default_severity = Severity.LOW
    type = "regex"
    applicable_project_types = [
        "laravel_api",
        "laravel_inertia_react",
        "laravel_inertia_vue",
    ]
    regex_file_extensions = [".php"]

    # Patterns for direct model returns
    _DIRECT_RETURN_PATTERNS = [
        re.compile(r"return\s+[A-Z][a-zA-Z]+\s*::\s*all\s*\(\s*\)\s*;", re.IGNORECASE),
        re.compile(r"return\s+[A-Z][a-zA-Z]+\s*::\s*get\s*\(\s*\)\s*;", re.IGNORECASE),
        re.compile(r"return\s+\$[a-zA-Z_]+\s*->\s*get\s*\(\s*\)\s*;", re.IGNORECASE),
        re.compile(r"return\s+\$[a-zA-Z_]+\s*;", re.IGNORECASE),  # Direct variable return
    ]

    # Patterns for API Resource usage (safe)
    _RESOURCE_PATTERNS = [
        re.compile(r"Resource\s*::\s*collection\s*\(", re.IGNORECASE),
        re.compile(r"Resource\s*::\s*make\s*\(", re.IGNORECASE),
        re.compile(r"return\s+new\s+[A-Z][a-zA-Z]*Resource\s*\(", re.IGNORECASE),
        re.compile(r"JsonResource", re.IGNORECASE),
    ]

    # Patterns for JSON response (also acceptable)
    _JSON_RESPONSE_PATTERNS = [
        re.compile(r"response\s*\(\s*\)\s*->\s*json\s*\(", re.IGNORECASE),
        re.compile(r"response\s*\(\)\s*->\s*json\s*\(", re.IGNORECASE),
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
            "ApiController" in file_path
        )

        if not is_api_controller:
            return findings

        text = content or ""
        lines = text.split("\n")

        # Check if file already uses API Resources
        has_resource = any(pattern.search(text) for pattern in self._RESOURCE_PATTERNS)

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            # Check for direct return patterns
            has_direct_return = any(pattern.search(line) for pattern in self._DIRECT_RETURN_PATTERNS)
            if not has_direct_return:
                continue

            # Skip if it's a simple variable return that might be a Resource
            if re.search(r"return\s+\$[a-zA-Z_]+Resource", line, re.IGNORECASE):
                continue

            # Skip if JSON response is used
            if any(pattern.search(line) for pattern in self._JSON_RESPONSE_PATTERNS):
                continue

            findings.append(
                self.create_finding(
                    title="API endpoint returning raw model data",
                    context=line.strip()[:60],
                    file=file_path,
                    line_start=i,
                    description=(
                        "Detected direct model/array return in API controller. "
                        "Consider using API Resources for consistent response formatting."
                    ),
                    why_it_matters=(
                        "Using API Resources provides:\n"
                        "- Consistent response structure across endpoints\n"
                        "- Easy data transformation and formatting\n"
                        "- Ability to add metadata (pagination, links)\n"
                        "- Clear separation between model and API contract\n"
                        "- Easier API versioning and maintenance\n"
                        "- Automatic handling of relationships"
                    ),
                    suggested_fix=(
                        "1. Create an API Resource:\n"
                        "   php artisan make:resource UserResource\n\n"
                        "2. Define the resource structure:\n"
                        "   public function toArray($request) {\n"
                        "       return ['id' => $this->id, 'name' => $this->name];\n"
                        "   }\n\n"
                        "3. Use in controller:\n"
                        "   return UserResource::collection(User::all());\n"
                        "   return new UserResource($user);"
                    ),
                    code_example=(
                        "// Before (raw model data)\n"
                        "public function index()\n"
                        "{\n"
                        "    return User::all(); // Exposes all columns\n"
                        "}\n\n"
                        "// After (API Resource)\n"
                        "class UserResource extends JsonResource\n"
                        "{\n"
                        "    public function toArray($request)\n"
                        "    {\n"
                        "        return [\n"
                        "            'id' => $this->id,\n"
                        "            'name' => $this->name,\n"
                        "            'email' => $this->email,\n"
                        "            'created_at' => $this->created_at->toISOString(),\n"
                        "        ];\n"
                        "    }\n"
                        "}\n\n"
                        "// Controller\n"
                        "public function index()\n"
                        "{\n"
                        "    return UserResource::collection(User::paginate(15));\n"
                        "}"
                    ),
                    confidence=0.65,
                    tags=["architecture", "api", "resource", "laravel", "rest"],
                )
            )

        return findings
