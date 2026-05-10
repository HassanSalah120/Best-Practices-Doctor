"""
Webhook signature parameter unused rule.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class WebhookSignatureParameterUnusedRule(Rule):
    id = "webhook-signature-parameter-unused"
    name = "Webhook Signature Parameter Unused"
    description = "Detects webhook/payment handlers that accept a signature parameter but never use it"
    category = Category.SECURITY
    default_severity = Severity.CRITICAL
    type = "regex"
    regex_file_extensions = [".php"]
    severity_weight = 10
    confidence = "high"
    fix_suggestion = (
        "The signature/HMAC parameter is accepted but never used. Call your signature validation service "
        "immediately at the top of the method before any business logic executes."
    )
    examples = {
        "bad": (
            "public function execute(array $payload, ?string $hmac): bool {\n"
            "    $this->processPayment($payload['id']);\n"
            "}"
        ),
        "good": (
            "public function execute(array $payload, ?string $hmac): bool {\n"
            "    $this->signatureService->validateHmac($payload, $hmac);\n"
            "}"
        ),
    }
    priority = 1
    group = "Security Hardening"
    applies_to = ["service", "controller"]
    references = [
        "OWASP A07:2021 - Identification and Authentication Failures",
        "CWE-345 Insufficient Verification of Data Authenticity",
    ]
    related_rules = ["webhook-signature-missing", "webhook-replay-protection-missing"]
    false_positive_notes = "May trigger if parameter is passed to another method via variable - check that the variable is actually used."
    detection_type = "regex"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "webhook-signature"}

    _METHOD_RE = re.compile(
        r"(?P<signature>(?:public|protected|private)?\s*(?:static\s+)?function\s+"
        r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?::\s*[^{;]+)?\{)"
        r"(?P<body>.*?)\n\s*\}",
        re.DOTALL,
    )
    _PARAM_RE = re.compile(r"\$(hmac|signature|webhookSignature|token|secret|hash)\b")
    _SCOPE_RE = re.compile(r"(webhook|handle|process)", re.IGNORECASE)

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

        path_scope = re.search(r"(webhook|payment|billing)", file_path, re.IGNORECASE)
        findings: list[Finding] = []
        for match in self._METHOD_RE.finditer(content):
            method_name = match.group("name")
            if not path_scope and not self._SCOPE_RE.search(method_name):
                continue

            params = match.group("params")
            body = match.group("body")
            for param in {m.group(1) for m in self._PARAM_RE.finditer(params)}:
                if re.search(rf"\${re.escape(param)}\b", body):
                    continue
                line = content.count("\n", 0, match.start()) + 1
                findings.append(
                    self.create_finding(
                        title="Webhook signature parameter is accepted but unused",
                        file=file_path,
                        line_start=line,
                        line_end=line,
                        context=f"{method_name}(${param})",
                        description=(
                            f"`{method_name}` accepts `${param}` but the parameter is never referenced in the method body."
                        ),
                        why_it_matters=(
                            "Webhook signatures prove authenticity. Ignoring the received HMAC/signature allows forged "
                            "payment or billing events to reach business logic."
                        ),
                        suggested_fix=self.fix_suggestion,
                        tags=["laravel", "security", "webhook", "authenticity"],
                        confidence=0.95,
                    ),
                )
        return findings

    @staticmethod
    def _is_test_file(file_path: str) -> bool:
        low = file_path.lower().replace("\\", "/")
        return "/tests/" in low or low.endswith("test.php")
