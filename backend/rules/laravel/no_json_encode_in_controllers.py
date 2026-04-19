"""
No JSON Encode In Controllers Rule

Detects json_encode() / ->toJson() usage in controllers.
This is a lightweight lint rule implemented as regex scanning.
"""

from __future__ import annotations

import re

from core.regex_scan import regex_scan
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class NoJsonEncodeInControllersRule(Rule):
    id = "no-json-encode-in-controllers"
    name = "Avoid json_encode/toJson in Controllers"
    description = "Detects json_encode() / ->toJson() usage inside controllers (prefer Response/Resources)"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    _ALLOWLIST_PATHS = ("tests/", "/tests/", "vendor/", "/vendor/")
    _CLASS_PATTERN = re.compile(r"class\s+([A-Z][a-zA-Z0-9_]*)", re.IGNORECASE)
    _API_NAMESPACE_PATTERN = re.compile(r"namespace\s+[^;]*\\api(?:\\|;)", re.IGNORECASE)
    _JSON_RESPONSE_WRAPPERS = (
        "response()->json(",
        "response ()->json(",
        "jsonresponse::fromjsonstring(",
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
        controller_files = {c.file_path for c in facts.controllers}
        if file_path not in controller_files:
            return []
        fp = (file_path or "").replace("\\", "/").lower()
        if any(allow in fp for allow in self._ALLOWLIST_PATHS):
            return []

        require_api_context = bool(self.get_threshold("require_api_context", True))
        require_return_context = bool(self.get_threshold("require_return_context", True))
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        api_context, api_evidence = self._detect_api_context(file_path, content, facts)
        if require_api_context and not api_context:
            return []

        pats = [
            re.compile(r"\bjson_encode\s*\(", re.IGNORECASE),
            re.compile(r"->\s*toJson\s*\(", re.IGNORECASE),
        ]

        hits = []
        for hit in regex_scan(content, pats):
            s = hit.line.strip()
            if not s or s.startswith(("//", "*", "/*", "#")):
                continue
            s_low = s.lower()
            if require_return_context and "return " not in s_low:
                continue
            if any(wrapper in s_low for wrapper in self._JSON_RESPONSE_WRAPPERS):
                continue
            hits.append(hit)

        out: list[Finding] = []
        for h in hits:
            line = h.line.strip()
            line_low = line.lower()
            is_to_json = "tojson(" in line_low
            confidence = 0.72 if is_to_json else 0.78
            if not require_return_context and "return " not in line_low:
                confidence -= 0.08
            if confidence + 1e-9 < min_confidence:
                continue

            evidence = list(api_evidence)
            evidence.append(f"return_context={'yes' if 'return ' in line_low else 'no'}")
            evidence.append(f"pattern={'toJson' if is_to_json else 'json_encode'}")
            out.append(
                self.create_finding(
                    title="Avoid json_encode()/toJson() in controllers",
                    context="json_encode_or_toJson",
                    file=file_path,
                    line_start=h.line_number,
                    description=(
                        "Detected manual JSON serialization in a controller. "
                        "Controllers should return Responses (response()->json) or API Resources instead."
                    ),
                    why_it_matters=(
                        "Manual JSON encoding is easy to get wrong (headers, encoding flags, escaping) and "
                        "bypasses Laravel's response/serialization conventions. Resources also centralize transformation."
                    ),
                    suggested_fix=(
                        "1. Return `response()->json($data)` instead of `json_encode(...)`\n"
                        "2. For APIs, prefer `JsonResource` / `ResourceCollection` for consistent serialization\n"
                        "3. Keep controllers thin: delegate transformation to Resources/DTOs"
                    ),
                    tags=["laravel", "controllers", "json", "resources"],
                    confidence=confidence,
                    evidence_signals=evidence,
                )
            )
        return out

    def _detect_api_context(self, file_path: str, content: str, facts: Facts) -> tuple[bool, list[str]]:
        evidence: list[str] = []
        fp = (file_path or "").replace("\\", "/").lower()
        if "/http/controllers/api/" in fp:
            evidence.append("api_context=controller_path")
            return True, evidence
        if self._API_NAMESPACE_PATTERN.search(content or ""):
            evidence.append("api_context=namespace")
            return True, evidence

        class_match = self._CLASS_PATTERN.search(content or "")
        if not class_match:
            return False, evidence
        class_name = class_match.group(1)
        for route in facts.routes or []:
            route_file = (route.file_path or "").replace("\\", "/").lower()
            if not (route_file == "routes/api.php" or route_file.endswith("/routes/api.php")):
                continue
            controller_ref = str(route.controller or route.action or "")
            if class_name.lower() in controller_ref.lower():
                evidence.append("api_context=api_route_controller_match")
                return True, evidence
        return False, evidence
