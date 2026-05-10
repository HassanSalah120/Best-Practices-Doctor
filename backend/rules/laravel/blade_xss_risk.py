"""
Blade XSS Risk Rule (Heuristic)

Flags raw Blade output `{!! ... !!}` when it appears to output request-derived data.
"""

from __future__ import annotations

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class BladeXssRiskRule(Rule):
    id = "blade-xss-risk"
    name = "Possible XSS risk in Blade raw output"
    description = "Detects `{!! ... !!}` usage that appears to output request-derived content"
    category = Category.SECURITY
    default_severity = Severity.MEDIUM
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Remove the possible xss risk in blade raw output risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 3
    group = 'Injection Risks'
    applies_to = ['blade']
    references = ['OWASP A03:2021 - Injection', 'CWE-79']
    related_rules = ['no-dangerously-set-inner-html', 'dangerous-html-sink-without-sanitizer']
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'security', 'concern': 'blade-xss'}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for e in getattr(facts, "blade_raw_echos", []) or []:
            if not getattr(e, "is_request_source", False):
                continue
            expr = (getattr(e, "expression", "") or "").strip()
            ctx = (expr[:120] if expr else "raw-echo").strip()

            findings.append(
                self.create_finding(
                    title="Possible XSS risk: raw Blade output of request data",
                    context=ctx,
                    file=e.file_path,
                    line_start=e.line_number,
                    description=(
                        "Detected raw Blade output using `{!! ... !!}` with request-derived expression: "
                        f"`{expr}`."
                    ),
                    why_it_matters=(
                        "Blade raw output bypasses HTML escaping. If untrusted input reaches `{!! !!}`, attackers "
                        "can inject HTML/JS (XSS), leading to account compromise and data exfiltration."
                    ),
                    suggested_fix=(
                        "1. Prefer escaped output: `{{ ... }}`\n"
                        "2. If you must render HTML, sanitize it first (e.g., allowlist tags/attributes)\n"
                        "3. Avoid echoing request input directly; validate and transform at the controller/service layer\n"
                        "4. Add tests for XSS payloads (e.g., `<img src=x onerror=alert(1)>`)"
                    ),
                    tags=["security", "xss", "blade"],
                    confidence=0.7,
                ),
            )

        return findings

