from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class CatchTooBroadRule(Rule):
    id = "catch-too-broad"
    name = "Catch Too Broad"
    description = "Detects broad catch blocks that return generic fallbacks without logging useful exception detail"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 5
    confidence = "medium"
    fix_suggestion = "Catch specific exception types when possible. When catching broadly, always log the exception message and type before returning a fallback. Broad catches that hide failure details make debugging production incidents extremely difficult."
    examples = {
        "bad": "catch (\\Throwable $e) { return false; }",
        "good": "catch (\\Throwable $e) { report($e); return false; }",
    }
    priority = 3
    group = "PHP Quality"
    applies_to = ["php-function"]
    references = []
    related_rules = ["exception-swallowing"]
    false_positive_notes = "Some top-level exception handlers intentionally catch broadly. Review the context - middleware and global handlers are often acceptable."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "php", "type": "quality", "concern": "broad-catch"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._is_test_file(file_path) or self._is_global_handler(file_path):
            return []
        findings: list[Finding] = []
        for match in re.finditer(r"catch\s*\(\s*\\?(?:Exception|Throwable)\s+\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\{", content or ""):
            body = self._brace_body(content or "", match.end() - 1)
            if "throw" in body or not re.search(r"\breturn\b", body):
                continue
            if self._logs_exception(body, match.group("var")):
                continue
            line = (content or "").count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="Broad catch returns a generic fallback without useful logging",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:catch:{line}",
                    description="This catch block catches Exception/Throwable broadly and returns a fallback without logging exception detail.",
                    why_it_matters="Broad catches that hide failure details make production incidents hard to diagnose.",
                    suggested_fix=self.fix_suggestion,
                    confidence=0.74,
                    tags=["php", "exceptions", "observability"],
                    evidence_signals=["broad_catch=true", "generic_return=true", "exception_detail_logged=false"],
                )
            )
        return findings

    def _logs_exception(self, body: str, var_name: str) -> bool:
        escaped = re.escape(var_name)
        return bool(
            re.search(r"\b(Log::|logger\s*\(|report\s*\(|error_log\s*\()", body)
            and re.search(rf"\${escaped}(?:->getMessage\s*\(|->getTrace|::class|\b)|get_class\s*\(\s*\${escaped}\s*\)", body)
        )

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

    def _is_global_handler(self, file_path: str) -> bool:
        norm = (file_path or "").replace("\\", "/").lower()
        return norm.endswith("app/exceptions/handler.php") or "/middleware/" in f"/{norm}"
