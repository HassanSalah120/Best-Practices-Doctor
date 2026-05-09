"""Exception swallowing rule."""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ExceptionSwallowingRule(Rule):
    id = "exception-swallowing"
    name = "Exception Swallowing"
    description = "Detects catch blocks that are empty or contain only comments"
    category = Category.MAINTAINABILITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Never swallow exceptions silently. At minimum log the exception. Prefer rethrowing or returning a typed error result."
    examples = {"bad": "} catch (Exception $e) { }", "good": "} catch (Exception $e) { Log::error($e->getMessage()); throw $e; }"}
    priority = 2
    group = "PHP Quality"
    applies_to = ["php-class", "php-function"]
    references = []
    related_rules = []
    false_positive_notes = "A catch block with logging, reporting, rethrowing, or an explicit return is treated as intentional handling."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "php", "type": "quality", "concern": "exceptions"}

    _CATCH = re.compile(r"catch\s*\([^)]*\)\s*\{(?P<body>.*?)\}", re.IGNORECASE | re.DOTALL)
    _HANDLED = re.compile(r"\b(Log::|logger\s*\(|report\s*\(|throw\b|return\b)", re.IGNORECASE)

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        return []

    def analyze_regex(self, file_path: str, content: str, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for match in self._CATCH.finditer(content):
            body = re.sub(r"//.*?$|/\*.*?\*/", "", match.group("body"), flags=re.MULTILINE | re.DOTALL).strip()
            if body and self._HANDLED.search(match.group("body")):
                continue
            if body:
                continue
            line = content.count("\n", 0, match.start()) + 1
            findings.append(self.create_finding(
                title="Exception is swallowed silently",
                context=f"{file_path}:{line}",
                file=file_path,
                line_start=line,
                description="This catch block does not handle, log, report, rethrow, or return an explicit error result.",
                why_it_matters="Silent exception handling hides production failures and makes data corruption or partial workflows much harder to debug.",
                suggested_fix=self.fix_suggestion,
                confidence=0.94,
                tags=["php", "quality", "exceptions"],
            ))
        return findings
