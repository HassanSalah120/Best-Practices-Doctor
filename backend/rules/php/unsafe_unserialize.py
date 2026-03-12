"""
Unsafe Unserialize Rule

Detects unserialize() usage without allowed_classes restrictions, especially on request input.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule

from ._parse_utils import extract_paren_content, split_top_level_args


_UNSER = re.compile(r"\bunserialize\s*\(", re.IGNORECASE)
_REQUESTISH = re.compile(r"(\$request\b|request\s*\(|\$_(get|post|request)\b)", re.IGNORECASE)


def _has_allowed_classes_option(arg_src: str) -> tuple[bool, bool]:
    """
    Returns (has_option, is_safe) for allowed_classes.
    Safe = allowed_classes explicitly false or a list/array.
    """
    s = (arg_src or "")
    if "allowed_classes" not in s.lower():
        return (False, False)

    # Best-effort parse; treat allowed_classes=true as unsafe.
    # Examples:
    # ['allowed_classes' => false]
    # ["allowed_classes" => ["Foo"]]
    # ['allowed_classes'=>true]
    if re.search(r"allowed_classes\s*['\"]?\s*=>\s*true\b", s, re.IGNORECASE):
        return (True, False)
    if re.search(r"allowed_classes\s*['\"]?\s*=>\s*false\b", s, re.IGNORECASE):
        return (True, True)
    if re.search(r"allowed_classes\s*['\"]?\s*=>\s*(\\[|array\\s*\\()", s, re.IGNORECASE):
        return (True, True)

    # Option present, but unknown value.
    return (True, False)


class UnsafeUnserializeRule(Rule):
    id = "unsafe-unserialize"
    name = "Unsafe unserialize() usage"
    description = "Detects unserialize() without allowed_classes restriction or on request input"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types: list[str] = []  # all

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for m in facts.methods:
            risky_calls: list[str] = []
            req_calls: int = 0

            for cs in m.call_sites or []:
                call = str(cs)
                um = _UNSER.search(call)
                if not um:
                    continue

                inside = extract_paren_content(call, um.end() - 1) or ""
                args = split_top_level_args(inside)
                if not args:
                    continue

                has_opt, is_safe = _has_allowed_classes_option(inside)
                if has_opt and is_safe:
                    continue

                if _REQUESTISH.search(args[0]):
                    req_calls += 1

                risky_calls.append("unserialize(...)")

            if not risky_calls:
                continue

            conf = 0.8 if req_calls else 0.7
            extra = " (request input detected)" if req_calls else ""

            findings.append(
                self.create_finding(
                    title="Unsafe unserialize() usage detected",
                    context=m.method_fqn,
                    file=m.file_path,
                    line_start=m.line_start or 1,
                    line_end=m.line_end or None,
                    description=(
                        f"Method `{m.method_fqn}` calls `unserialize()` without a strict `allowed_classes` option"
                        + extra
                        + "."
                    ),
                    why_it_matters=(
                        "Unserializing untrusted data can lead to object injection vulnerabilities, which can escalate "
                        "to RCE depending on available gadget chains."
                    ),
                    suggested_fix=(
                        "1. Prefer JSON for untrusted payloads (`json_decode`) instead of PHP serialization\n"
                        "2. If you must use `unserialize()`, pass `['allowed_classes' => false]` or an explicit allowlist\n"
                        "3. Validate and authenticate the payload source (sign/encrypt)\n"
                        "4. Add tests for malicious payloads"
                    ),
                    tags=["security", "deserialization", "object_injection"],
                    confidence=conf,
                )
            )

        return findings

