"""
Unsafe CSP Policy Rule

Detects Content-Security-Policy definitions that still allow unsafe inline or eval execution.
"""

from __future__ import annotations

import re

from rules.base import Rule
from rules.laravel._security_header_evidence import strip_comments
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class UnsafeCspPolicyRule(Rule):
    id = "unsafe-csp-policy"
    name = "Unsafe CSP Policy"
    description = "Detects CSP definitions that allow unsafe inline or eval sources"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    regex_file_extensions = [".php"]

    _DIRECTIVE = re.compile(
        r"(?P<directive>(?:default|script|style)-src(?:-elem|-attr)?)\s+"
        r"(?P<sources>.*?)(?=;|\r?\n|$)",
        re.IGNORECASE,
    )
    _UNSAFE = re.compile(r"(['\"])(unsafe-(?:inline|eval))\1", re.IGNORECASE)
    _NONCE_OR_HASH = re.compile(
        r"(['\"])(?:nonce-[^'\"\s]+|sha(?:256|384|512)-[^'\"\s]+)\1",
        re.IGNORECASE,
    )
    _DEVELOPMENT_CONDITION = re.compile(
        r"(?:"
        r"->\s*islocal\s*\("
        r"|(?:app\s*\(\s*\)|app)\s*->\s*environment\s*\([^)]*"
        r"(?:local|development|testing)"
        r"|App\s*::\s*environment\s*\([^)]*"
        r"(?:local|development|testing)"
        r"|(?:config\s*\(\s*['\"]app\.env['\"]\s*\)|env\s*\(\s*['\"]APP_ENV['\"]\s*\))"
        r"\s*(?:===?|==)\s*['\"](?:local|development|testing)['\"]"
        r"|!\s*(?:(?:app\s*\(\s*\)|app)\s*->|App\s*::)\s*environment\s*\([^)]*production"
        r")",
        re.IGNORECASE,
    )
    severity_weight = 0
    confidence = "high"
    fix_suggestion = "Remove production-reachable unsafe script sources; use nonces, hashes, or narrowly scoped development-only allowances."
    examples = {}
    priority = 1
    group = "Access Control"
    applies_to = ["config"]
    references = ["OWASP A05:2021 - Security Misconfiguration", "CWE-1021"]
    related_rules = []
    false_positive_notes = "Report-only policies, nonce/hash compatibility fallbacks, and provably development-only allowances are excluded; style-only allowances are reported separately at medium severity."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "unsafe-csp-policy"}

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
        text = strip_comments(content or "")
        low = text.lower()
        if not any(
            signal in low
            for signal in ("content-security-policy", "script-src", "style-src", "default-src")
        ):
            return []
        if self._is_report_only_policy(text):
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, int]] = set()
        for directive_match in self._DIRECTIVE.finditer(text):
            if self._directive_is_report_only(text, directive_match.start()):
                continue
            directive = directive_match.group("directive").lower()
            sources = directive_match.group("sources")
            unsafe_matches = list(self._UNSAFE.finditer(sources))
            if not unsafe_matches:
                continue

            tokens = {match.group(2).lower() for match in unsafe_matches}
            if directive.startswith("style-src"):
                tokens.discard("unsafe-eval")  # This token has no effect in a style directive.
            if (
                "unsafe-inline" in tokens
                and directive.startswith("script-src")
                and self._NONCE_OR_HASH.search(sources)
            ):
                tokens.discard("unsafe-inline")  # CSP2+ ignores this compatibility fallback.
            if not tokens:
                continue

            absolute_offsets = [
                directive_match.start("sources") + match.start()
                for match in unsafe_matches
                if match.group(2).lower() in tokens
            ]
            if all(self._is_development_only(text, offset) for offset in absolute_offsets):
                continue

            line = text.count("\n", 0, directive_match.start()) + 1
            token_label = ", ".join(f"'{token}'" for token in sorted(tokens))
            key = (directive, token_label, line)
            if key in seen:
                continue
            seen.add(key)

            style_only = directive.startswith("style-src")
            severity = Severity.MEDIUM if style_only else Severity.HIGH
            title = (
                "CSP style directive permits inline styles"
                if style_only
                else "CSP script directive permits unsafe execution"
            )
            impact = (
                "Inline style permission weakens protection against CSS/style injection, but it does not by itself "
                "enable inline JavaScript."
                if style_only
                else "This production-reachable script policy weakens CSP protection against XSS or eval-based code execution."
            )
            fix = (
                "Migrate inline styles to nonce/hash-authorized styles or external stylesheets when practical. "
                "If inline styles are an intentional framework requirement, document and narrowly scope the exception."
                if style_only
                else "Remove the unsafe script source. Use per-response nonces or hashes and a narrowly scoped source list; "
                "keep development-only allowances inside a provably local environment branch."
            )
            findings.append(
                self.create_finding(
                    title=title,
                    context=f"{file_path}:{line}:{directive}",
                    file=file_path,
                    line_start=line,
                    description=f"The `{directive}` directive contains {token_label}.",
                    why_it_matters=impact,
                    suggested_fix=fix,
                    severity=severity,
                    tags=["laravel", "security", "csp", "xss"],
                    confidence=0.92 if not style_only else 0.84,
                    evidence_signals=[
                        f"csp_directive={directive}",
                        f"unsafe_tokens={token_label}",
                        "production_reachable=true",
                    ],
                )
            )
        return findings

    def _is_report_only_policy(self, text: str) -> bool:
        lowered = text.lower()
        if "content-security-policy-report-only" not in lowered:
            return False
        enforcing = lowered.replace("content-security-policy-report-only", "")
        return "content-security-policy" not in enforcing

    @staticmethod
    def _directive_is_report_only(text: str, offset: int) -> bool:
        prefix = text[max(0, offset - 1500) : offset].lower()
        report_only = prefix.rfind("content-security-policy-report-only")
        enforcing_matches = list(re.finditer(r"content-security-policy(?!-report-only)", prefix))
        enforcing = enforcing_matches[-1].start() if enforcing_matches else -1
        return report_only > enforcing

    def _is_development_only(self, text: str, offset: int) -> bool:
        line_start = text.rfind("\n", 0, offset) + 1
        line_end = text.find("\n", offset)
        if line_end < 0:
            line_end = len(text)
        line = text[line_start:line_end]
        token_on_line = offset - line_start
        question = line.rfind("?", 0, token_on_line)
        if question >= 0 and self._DEVELOPMENT_CONDITION.search(line[:question]):
            colon = line.find(":", token_on_line)
            if colon >= 0:
                return True

        search_start = max(0, offset - 3000)
        prefix = text[search_start:offset]
        for match in reversed(list(re.finditer(r"\bif\s*\(", prefix, re.IGNORECASE))):
            condition_open = search_start + match.end() - 1
            condition_close = self._matching_delimiter(text, condition_open, "(", ")")
            if condition_close < 0 or condition_close >= offset:
                continue
            condition = text[condition_open + 1 : condition_close]
            if not self._DEVELOPMENT_CONDITION.search(condition):
                continue
            block_open = condition_close + 1
            while block_open < len(text) and text[block_open].isspace():
                block_open += 1
            if block_open >= len(text) or text[block_open] != "{":
                continue
            if self._matching_brace(text, block_open) >= offset:
                return True
        return False

    @staticmethod
    def _matching_brace(text: str, opening: int) -> int:
        return UnsafeCspPolicyRule._matching_delimiter(text, opening, "{", "}")

    @staticmethod
    def _matching_delimiter(text: str, opening: int, left: str, right: str) -> int:
        depth = 0
        for index in range(opening, len(text)):
            if text[index] == left:
                depth += 1
            elif text[index] == right:
                depth -= 1
                if depth == 0:
                    return index
        return -1
