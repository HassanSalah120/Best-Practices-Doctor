from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class MissingReturnTypeNullableRule(Rule):
    id = "missing-return-type-nullable"
    name = "Missing Return Type Nullable"
    description = "Detects PHP functions that declare a non-nullable return type but return null on some path"
    category = Category.MAINTAINABILITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.DEFECT
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Change the return type to nullable: ?string instead of string, or string|null in PHP 8+. Alternatively eliminate the null return path if null is not a valid result."
    examples = {"bad": "function name(): string { return null; }", "good": "function name(): ?string { return null; }"}
    priority = 2
    group = "PHP Quality"
    applies_to = ["php-function"]
    references = ["PHP Type Declarations"]
    related_rules = ["missing-type-declarations"]
    false_positive_notes = "Generated code or framework magic may intentionally use broad signatures; tests are ignored by default."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "php", "type": "quality", "concern": "nullable-return-type"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._is_test_file(file_path):
            return []
        findings: list[Finding] = []
        for match in re.finditer(
            r"function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*:\s*(?P<type>[^{;\n]+)\{",
            content or "",
            re.I,
        ):
            return_type = match.group("type").strip()
            if self._is_nullable_or_exempt(return_type):
                continue
            body = self._brace_body(content or "", match.end() - 1)
            if not re.search(r"\breturn\s+null\s*;|\breturn\s*;", body):
                continue
            line = (content or "").count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="Function can return null but return type is non-nullable",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:{match.group('name')}",
                    description=f"{match.group('name')}() declares {return_type} but has a null or bare return path.",
                    why_it_matters="PHP will throw a TypeError when that path is hit at runtime.",
                    suggested_fix=self.fix_suggestion,
                    confidence=0.9,
                    tags=["php", "types", "runtime"],
                    evidence_signals=["return_type_non_nullable=true", "null_return_path=true"],
                ),
            )
        return findings

    def _is_nullable_or_exempt(self, return_type: str) -> bool:
        low = return_type.replace(" ", "").lower()
        if low.startswith("?") or "null" in low:
            return True
        return low in {"void", "mixed", "never", "static", "self|null"}

    def _brace_body(self, content: str, brace_index: int) -> str:
        depth = 0
        for idx in range(brace_index, len(content)):
            ch = content[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return content[brace_index + 1 : idx]
        return content[brace_index + 1 :]

    def _is_test_file(self, file_path: str) -> bool:
        norm = (file_path or "").replace("\\", "/").lower()
        return "/tests/" in f"/{norm}" or norm.endswith(("test.php", "tests.php"))
