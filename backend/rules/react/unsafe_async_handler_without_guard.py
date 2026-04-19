"""
Unsafe Async Handler Without Guard Rule

Detects async mutation handlers lacking double-submit/race guards.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule


class UnsafeAsyncHandlerWithoutGuardRule(Rule):
    id = "unsafe-async-handler-without-guard"
    name = "Unsafe Async Handler Without Guard"
    description = "Detects async event handlers that can be re-triggered without pending/processing guard"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.RISK
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ALLOWLIST_PATH_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _NAMED_HANDLER = re.compile(
        r"(?:const|let|var)\s+(?P<name>(?:handle|on)[A-Z][A-Za-z0-9_]*)\s*=\s*async\s*\([^)]*\)\s*=>\s*\{(?P<body>.*?)\}",
        re.IGNORECASE | re.DOTALL,
    )
    _JSX_HANDLER_USE_TEMPLATE = r"on[A-Z][A-Za-z0-9_]*\s*=\s*\{{\s*{name}\s*\}}"
    _MUTATION_SIGNAL = re.compile(
        r"\b(fetch|axios\.|mutate\(|submit\(|send\(|request\(|post\(|put\(|patch\(|delete\(|save\(|create\(|update\()",
        re.IGNORECASE,
    )
    _AWAIT_SIGNAL = re.compile(r"\bawait\b", re.IGNORECASE)
    _GUARD_VAR = re.compile(
        r"\b(processing|loading|pending|isSubmitting|submitting|isSaving|saving|busy|isPending)\b",
        re.IGNORECASE,
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
        text = content or ""
        normalized_path = (file_path or "").replace("\\", "/").lower()
        if any(marker in normalized_path for marker in self._ALLOWLIST_PATH_MARKERS):
            return []
        if "async" not in text:
            return []

        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        findings: list[Finding] = []

        for match in self._NAMED_HANDLER.finditer(text):
            if len(findings) >= max_findings_per_file:
                break

            handler_name = str(match.group("name") or "").strip()
            handler_body = str(match.group("body") or "")
            if not handler_name or not handler_body:
                continue
            if not self._AWAIT_SIGNAL.search(handler_body):
                continue
            if not self._MUTATION_SIGNAL.search(handler_body):
                continue
            if self._is_guarded(handler_body):
                continue

            usage_re = re.compile(self._JSX_HANDLER_USE_TEMPLATE.format(name=re.escape(handler_name)))
            if not usage_re.search(text):
                continue

            line_number = text.count("\n", 0, match.start()) + 1
            findings.append(
                self.create_finding(
                    title="Async handler lacks pending/processing guard",
                    context=handler_name,
                    file=file_path,
                    line_start=line_number,
                    description=(
                        f"Async handler `{handler_name}` performs mutation/network work but no guard was detected "
                        "to prevent rapid re-entry."
                    ),
                    why_it_matters=(
                        "Unguarded async handlers can trigger duplicate submissions, race conditions, and inconsistent state."
                    ),
                    suggested_fix=(
                        "Add a pending/processing guard (or disable trigger controls) while the async action is in flight."
                    ),
                    confidence=0.82,
                    tags=["react", "async", "handlers", "race-condition"],
                    evidence_signals=[
                        f"handler={handler_name}",
                        "await=1",
                        "mutation_signal=1",
                        "guard=0",
                    ],
                    metadata={"decision_profile": {"handler": handler_name, "guarded": False}},
                )
            )

        return findings

    def _is_guarded(self, handler_body: str) -> bool:
        body = handler_body or ""
        if re.search(r"\bif\s*\([^)]*(processing|loading|pending|isSubmitting|submitting|isSaving|saving|busy|isPending)[^)]*\)\s*return", body, re.IGNORECASE):
            return True
        if re.search(r"\bset[A-Z][A-Za-z0-9_]*\s*\(\s*true\s*\)", body) and re.search(r"\bfinally\s*\{[^{}]*set[A-Z][A-Za-z0-9_]*\s*\(\s*false\s*\)", body, re.IGNORECASE | re.DOTALL):
            return True
        return bool(self._GUARD_VAR.search(body) and re.search(r"\bdisabled\s*=", body, re.IGNORECASE))
