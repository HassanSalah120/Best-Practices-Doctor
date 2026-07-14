from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class ConsoleLogInProductionCodeRule(Rule):
    id = "console-log-in-production-code"
    name = "Console Log In Production Code"
    description = "Detects console calls left in non-test frontend source files"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".tsx", ".ts", ".jsx", ".js"]
    severity_weight = 5
    confidence = "high"
    fix_suggestion = "Remove console statements before committing. Use a proper logging utility that can be disabled in production. Consider using an ESLint rule to catch these automatically in CI."
    examples = {"bad": "console.log(response)", "good": "logger.debug(response) // stripped or disabled in production"}
    priority = 3
    group = "Code Quality"
    applies_to = ["react-component", "page"]
    references = []
    related_rules = ["sensitive-data-logging"]
    false_positive_notes = "Logger wrapper files and ErrorBoundary componentDidCatch logging are intentionally ignored."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "react", "type": "quality", "concern": "console-output"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._is_ignored_file(file_path, content or ""):
            return []
        findings: list[Finding] = []
        source = content or ""
        code_only = self._mask_comments_and_strings(source)
        for match in re.finditer(r"\bconsole\.(?:log|warn|error|info|debug)\s*\(", code_only):
            method = match.group(0).split(".")[1].split("(")[0]
            if method == "error" and self._is_error_boundary_logging(source, match.start()):
                continue
            line = source.count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="Console statement left in production source",
                    file=file_path,
                    line_start=line,
                    context=f"{file_path}:console:{line}",
                    description=f"console.{method}() is present in non-test frontend source.",
                    why_it_matters="Console output can expose internal state, API responses, and user data in browser developer tools.",
                    suggested_fix=self.fix_suggestion,
                    confidence=0.92,
                    tags=["react", "frontend", "logging"],
                    evidence_signals=["console_call=true", "test_file=false"],
                ),
            )
        return findings

    @staticmethod
    def _mask_comments_and_strings(content: str) -> str:
        """Blank JS comments and literals while preserving offsets/newlines."""
        chars = list(content)
        state = "code"
        quote = ""
        escaped = False
        i = 0
        while i < len(chars):
            ch = chars[i]
            nxt = chars[i + 1] if i + 1 < len(chars) else ""
            if state == "code":
                if ch == "/" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    state = "line_comment"
                    i += 2
                    continue
                if ch == "/" and nxt == "*":
                    chars[i] = chars[i + 1] = " "
                    state = "block_comment"
                    i += 2
                    continue
                if ch in {"'", '"', "`"}:
                    quote = ch
                    chars[i] = " "
                    state = "string"
                i += 1
                continue
            if state == "line_comment":
                if ch == "\n":
                    state = "code"
                else:
                    chars[i] = " "
                i += 1
                continue
            if state == "block_comment":
                if ch == "*" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    state = "code"
                    i += 2
                    continue
                if ch != "\n":
                    chars[i] = " "
                i += 1
                continue
            if escaped:
                if ch != "\n":
                    chars[i] = " "
                escaped = False
                i += 1
                continue
            if ch == "\\":
                chars[i] = " "
                escaped = True
                i += 1
                continue
            if ch == quote:
                chars[i] = " "
                state = "code"
                quote = ""
            elif ch != "\n":
                chars[i] = " "
            i += 1
        return "".join(chars)

    def _is_ignored_file(self, file_path: str, content: str) -> bool:
        norm = (file_path or "").replace("\\", "/").lower()
        name = norm.rsplit("/", 1)[-1]
        return (
            ".test." in name
            or ".spec." in name
            or "/__tests__/" in f"/{norm}"
            or self._looks_like_cli_script(content)
            or name in {"logger.ts", "logger.tsx", "logger.js", "logging.ts", "logging.tsx", "logging.js"}
        )

    def _looks_like_cli_script(self, content: str) -> bool:
        text = content or ""
        if text.lstrip().startswith("#!") and "node" in text[:120].lower():
            return True
        return bool(
            re.search(r"\bprocess\.argv\b", text)
            or re.search(r"\bprocess\.exit\s*\(", text)
            or re.search(r"\b(?:readline|commander|yargs|inquirer)\b", text),
        )

    def _is_error_boundary_logging(self, content: str, position: int) -> bool:
        window = content[max(0, position - 800) : position + 300]
        return "componentDidCatch" in window or "ErrorBoundary" in window and "componentDidCatch" in content
