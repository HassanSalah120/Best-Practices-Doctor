"""
Sensitive Model Appends Risk Rule

Detects models that append sensitive-looking attributes into serialized output.
"""

from __future__ import annotations

from collections import defaultdict

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class SensitiveModelAppendsRiskRule(Rule):
    id = "sensitive-model-appends-risk"
    name = "Sensitive Model Appends Risk"
    description = "Detects sensitive attributes listed in a model's $appends array"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _SENSITIVE_TOKENS = (
        "token",
        "secret",
        "password",
        "recovery",
        "otp",
        "session",
        "api_key",
    )

    # Attributes that are boolean status flags, not actual secrets
    _SAFE_BOOLEAN_FLAGS = (
        "_enabled",  # e.g., two_factor_enabled, not the secret itself
        "_active",
        "_verified",
        "_status",
        "_url",  # Public URLs like profile_photo_url
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Remove the sensitive model appends risk risk and enforce the relevant Laravel/React security control at the boundary. Add a regression test that proves unsafe input or configuration is rejected.'
    examples = {}
    priority = 1
    group = 'Sensitive Data'
    applies_to = ['model']
    references = ['OWASP A05:2021 - Security Misconfiguration']
    related_rules = []
    false_positive_notes = ''
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'security', 'concern': 'sensitive-model-appends'}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        grouped: dict[str, list] = defaultdict(list)
        for config in (getattr(facts, "model_attribute_configs", []) or []):
            grouped[str(config.file_path)].append(config)

        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for file_path, configs in grouped.items():
            appended: list[str] = []
            model_name = str(configs[0].model_name or "Model")
            first_line = min(int(config.line_number or 1) for config in configs)
            for config in configs:
                if str(config.property_name or "").lower() != "appends":
                    continue
                appended.extend(str(value).lower() for value in (config.values or []))

            sensitive = sorted({
                value for value in appended
                if any(token in value for token in self._SENSITIVE_TOKENS)
                and not any(safe_suffix in value for safe_suffix in self._SAFE_BOOLEAN_FLAGS)
            })
            if not sensitive:
                continue

            confidence = min(0.97, 0.86 + (0.03 * min(len(sensitive), 3)))
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="Model appends sensitive-looking attributes",
                    file=file_path,
                    line_start=first_line,
                    context=f"model:{model_name}",
                    description=(
                        f"Model `{model_name}` appends sensitive-looking attributes to serialized output: {', '.join(sensitive)}."
                    ),
                    why_it_matters=(
                        "Appended attributes are included automatically when the model is serialized, which increases the chance of leaking secrets or auth-related state."
                    ),
                    suggested_fix="Remove sensitive values from `$appends` or expose only a deliberately redacted/derived field.",
                    confidence=confidence,
                    tags=["laravel", "model", "serialization", "security", "appends"],
                    evidence_signals=[
                        "model_appends_sensitive_attribute=true",
                        f"sensitive_append_count={len(sensitive)}",
                    ],
                )
            )

        return findings
