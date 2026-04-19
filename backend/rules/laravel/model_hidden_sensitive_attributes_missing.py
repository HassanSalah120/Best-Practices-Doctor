"""
Model Hidden Sensitive Attributes Missing Rule

Detects models that configure sensitive attributes in casts/visible/appends but
do not hide them.
"""

from __future__ import annotations

from collections import defaultdict

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class ModelHiddenSensitiveAttributesMissingRule(Rule):
    id = "model-hidden-sensitive-attributes-missing"
    name = "Model Hidden Sensitive Attributes Missing"
    description = "Detects models that expose sensitive attributes without listing them in $hidden"
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
        "password",
        "remember_token",
        "api_token",
        "access_token",
        "refresh_token",
        "secret",
        "recovery_code",
        "two_factor",
        "otp",
        "session_token",
    )

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
            hidden = {
                str(value).lower()
                for config in configs
                if str(config.property_name or "").lower() == "hidden"
                for value in (config.values or [])
            }
            candidates: set[str] = set()
            first_line = min(int(config.line_number or 1) for config in configs)
            model_name = str(configs[0].model_name or "Model")

            for config in configs:
                prop = str(config.property_name or "").lower()
                if prop == "casts":
                    raw_values = list((config.mapping or {}).keys())
                else:
                    raw_values = list(config.values or [])
                for value in raw_values:
                    value_l = str(value).lower()
                    if any(token in value_l for token in self._SENSITIVE_TOKENS):
                        candidates.add(value_l)

            missing = sorted(candidate for candidate in candidates if candidate not in hidden)
            if not missing:
                continue

            confidence = min(0.96, 0.82 + (0.04 * min(len(missing), 3)))
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="Model does not hide sensitive attributes",
                    file=file_path,
                    line_start=first_line,
                    context=f"model:{model_name}",
                    description=(
                        f"Model `{model_name}` config references sensitive attributes ({', '.join(missing)}) without listing them in `$hidden`."
                    ),
                    why_it_matters=(
                        "Sensitive attributes can leak through serialization, JSON responses, debug output, or shared frontend payloads when they are not hidden."
                    ),
                    suggested_fix=(
                        "Add the sensitive attributes to `$hidden` so default model serialization does not expose them."
                    ),
                    confidence=confidence,
                    tags=["laravel", "model", "serialization", "security"],
                    evidence_signals=[
                        "model_sensitive_attribute_detected=true",
                        "hidden_sensitive_attribute_missing=true",
                        f"missing_count={len(missing)}",
                    ],
                )
            )

        return findings
