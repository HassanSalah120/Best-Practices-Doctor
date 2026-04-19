"""
Missing API Resource Rule

Detects API endpoints returning raw model data instead of using API Resources.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
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

    _CLASS_PATTERN = re.compile(r"class\s+([A-Z][a-zA-Z0-9_]*)", re.IGNORECASE)
    _API_NAMESPACE_PATTERN = re.compile(r"namespace\s+[^;]*\\api(?:\\|;)", re.IGNORECASE)
    _DIRECT_QUERY_RETURN_PATTERNS = [
        re.compile(
            r"return\s+[A-Z][A-Za-z0-9_\\]*\s*::\s*(?:query\s*\(\)\s*->\s*)?"
            r"(?:all|get|paginate|simplePaginate|first|find|pluck)\s*\(",
            re.IGNORECASE,
        ),
        re.compile(
            r"return\s+[A-Z][A-Za-z0-9_\\]*\s*::\s*(?:where|latest|oldest|orderBy|query)\b[^;]*->\s*"
            r"(?:get|paginate|simplePaginate|first|find|pluck)\s*\(",
            re.IGNORECASE,
        ),
        re.compile(
            r"return\s+\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*"
            r"(?:get|paginate|simplePaginate|first|find|pluck)\s*\(",
            re.IGNORECASE,
        ),
    ]
    _RETURN_VARIABLE_PATTERN = re.compile(r"return\s+\$([a-zA-Z_][a-zA-Z0-9_]*)\s*;", re.IGNORECASE)
    _RAW_ASSIGNMENT_PATTERN = re.compile(
        r"\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*.*?(::\s*(?:all|get|paginate|simplePaginate|first|find|pluck)\s*\(|->\s*"
        r"(?:get|paginate|simplePaginate|first|find|pluck)\s*\()",
        re.IGNORECASE,
    )

    _RESOURCE_PATTERNS = [
        re.compile(r"Resource\s*::\s*collection\s*\(", re.IGNORECASE),
        re.compile(r"Resource\s*::\s*make\s*\(", re.IGNORECASE),
        re.compile(r"return\s+new\s+[A-Z][a-zA-Z]*Resource\s*\(", re.IGNORECASE),
        re.compile(r"JsonResource", re.IGNORECASE),
        re.compile(r"AnonymousResourceCollection", re.IGNORECASE),
    ]

    _SAFE_RESPONSE_PATTERNS = [
        re.compile(r"response\s*\(\s*\)\s*->\s*json\s*\(", re.IGNORECASE),
        re.compile(r"response\s*\(\)\s*->\s*json\s*\(", re.IGNORECASE),
        re.compile(r"->\s*toResponse\s*\(", re.IGNORECASE),
        re.compile(r"JsonResponse", re.IGNORECASE),
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

        # Skip allowlisted paths.
        norm_path = (file_path or "").replace("\\", "/").lower()
        if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
            return findings

        text = content or ""
        require_api_context = bool(self.get_threshold("require_api_context", True))
        api_context, api_evidence = self._detect_api_context(file_path, text, facts)
        if require_api_context and not api_context:
            return findings

        lines = text.split("\n")
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        min_raw_return_signals = int(self.get_threshold("min_raw_return_signals", 1) or 1)

        raw_vars = self._collect_raw_query_variables(lines)
        candidates: list[tuple[int, str, str, float]] = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            if any(pattern.search(line) for pattern in self._RESOURCE_PATTERNS):
                continue
            if any(pattern.search(line) for pattern in self._SAFE_RESPONSE_PATTERNS):
                continue

            direct_query_return = any(pattern.search(line) for pattern in self._DIRECT_QUERY_RETURN_PATTERNS)
            return_var_match = self._RETURN_VARIABLE_PATTERN.search(line)
            raw_var_return = bool(return_var_match and return_var_match.group(1).lower() in raw_vars)
            if not direct_query_return and not raw_var_return:
                continue

            if re.search(r"return\s+\$[a-zA-Z_][a-zA-Z0-9_]*Resource", line, re.IGNORECASE):
                continue

            return_kind = "direct_query_return" if direct_query_return else "raw_query_variable_return"
            confidence = 0.78 if direct_query_return else 0.67
            if confidence + 1e-9 < min_confidence:
                continue
            candidates.append((i, stripped[:200], return_kind, confidence))

        if len(candidates) < min_raw_return_signals:
            return findings

        for line_no, context_line, return_kind, confidence in candidates:
            evidence = list(api_evidence)
            evidence.append(f"return_kind={return_kind}")
            evidence.append("api_contract_boundary=resource_expected")
            findings.append(
                self.create_finding(
                    title="API endpoint returning raw model data",
                    context=context_line[:80],
                    file=file_path,
                    line_start=line_no,
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
                    confidence=confidence,
                    tags=["architecture", "api", "resource", "laravel", "rest"],
                    evidence_signals=evidence,
                    metadata={
                        "overlap_group": "api-resource-contract",
                        "overlap_scope": f"{file_path}:{line_no}",
                        "overlap_rank": 95,
                    },
                )
            )

        return findings

    def _detect_api_context(self, file_path: str, text: str, facts: Facts) -> tuple[bool, list[str]]:
        evidence: list[str] = []
        norm_path = (file_path or "").replace("\\", "/").lower()

        if "/http/controllers/api/" in norm_path:
            evidence.append("api_context=controller_path")
            return True, evidence
        if norm_path.endswith("apicontroller.php"):
            evidence.append("api_context=controller_name")
            return True, evidence
        if self._API_NAMESPACE_PATTERN.search(text or ""):
            evidence.append("api_context=namespace")
            return True, evidence

        class_match = self._CLASS_PATTERN.search(text or "")
        if not class_match:
            return False, evidence
        class_name = class_match.group(1)
        for route in facts.routes or []:
            route_file = (route.file_path or "").replace("\\", "/").lower()
            if not (route_file == "routes/api.php" or route_file.endswith("/routes/api.php")):
                continue
            controller_ref = str(route.controller or "")
            if class_name and class_name.lower() in controller_ref.lower():
                evidence.append("api_context=api_route_controller_match")
                return True, evidence
        return False, evidence

    def _collect_raw_query_variables(self, lines: list[str]) -> set[str]:
        raw_vars: set[str] = set()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                continue
            match = self._RAW_ASSIGNMENT_PATTERN.search(line)
            if not match:
                continue
            raw_vars.add(match.group(1).lower())
        return raw_vars
