from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class ApiResponseInconsistentShapeRule(Rule):
    id = "api-response-inconsistent-shape"
    name = "API Response Inconsistent Shape"
    description = "Detects controllers that mix wrapped JSON, raw JSON arrays, and resource response shapes"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    regex_file_extensions = [".php"]
    severity_weight = 5
    confidence = "medium"
    fix_suggestion = "Standardize all API responses in this controller to use the same shape. Prefer API Resources for all responses. Define a base response format and apply it consistently."
    examples = {
        "bad": "One method returns response()->json(['data' => $items]); another returns response()->json($items);",
        "good": "All methods return API Resources or all wrap payloads under data.",
    }
    priority = 3
    group = "API Design"
    applies_to = ["controller"]
    references = []
    related_rules = ["api-resource-usage", "missing-api-resource"]
    false_positive_notes = "Some controllers intentionally serve different shapes for different client types. Review before acting."
    detection_type = "ast"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "quality", "concern": "api-response-shape"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        norm = (file_path or "").replace("\\", "/").lower()
        if "controller" not in norm or not file_path.endswith(".php"):
            return []
        kinds = self._response_kinds(content or "")
        if len(kinds) < 2:
            return []
        if not ({"wrapped", "raw"} <= kinds or {"resource", "raw"} <= kinds):
            return []
        line = self._first_response_line(content or "")
        return [
            self.create_finding(
                title="Controller mixes API response shapes",
                file=file_path,
                line_start=line,
                context=f"controller:{file_path}:response-shape",
                description=f"This controller mixes response styles: {', '.join(sorted(kinds))}.",
                why_it_matters="Inconsistent response shapes make frontend typing and error handling brittle.",
                suggested_fix=self.fix_suggestion,
                confidence=0.72,
                tags=["laravel", "api", "response-shape"],
                evidence_signals=[f"response_kinds={','.join(sorted(kinds))}"],
            ),
        ]

    def _response_kinds(self, content: str) -> set[str]:
        kinds: set[str] = set()
        response_count = 0
        for match in re.finditer(r"response\s*\(\s*\)\s*->\s*json\s*\((?P<body>.*?)\)\s*;?", content, re.I | re.S):
            response_count += 1
            body = match.group("body")
            if re.search(r"\[\s*['\"]data['\"]\s*=>", body):
                kinds.add("wrapped")
            else:
                kinds.add("raw")
        resource_matches = re.findall(r"return\s+(?:new\s+)?[A-Za-z0-9_\\]+Resource(?:::collection)?\s*\(", content, re.I)
        if resource_matches:
            response_count += len(resource_matches)
            kinds.add("resource")
        if response_count < 2:
            return set()
        return kinds

    def _first_response_line(self, content: str) -> int:
        positions = [pos for pos in (content.find("response()->json"), content.find("Resource")) if pos >= 0]
        return content.count("\n", 0, min(positions)) + 1 if positions else 1
