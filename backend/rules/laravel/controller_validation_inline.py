"""
Controller Inline Validation Rule

Flags inline validation inside controllers as a violation (suggest FormRequest).
"""
from schemas.facts import Facts, ValidationUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, FindingClassification, Category, Severity
from rules.base import Rule
from core.project_recommendations import (
    enabled_capabilities,
    enabled_team_standards,
    project_aware_guidance,
    recommendation_context_tags,
)


class ControllerInlineValidationRule(Rule):
    """
    Detects `$request->validate(...)` or `Validator::make(...)` inside controllers.

    MissingFormRequestRule is advisory and keyed on rule-count; this rule is stricter and treats it as a violation.
    """

    id = "controller-inline-validation"
    name = "Inline Validation In Controller"
    description = "Detects inline validation inside controller actions (prefer FormRequest)"
    category = Category.VALIDATION
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    _SMALL_AUTH_MARKERS = (
        "/auth/",
        "login",
        "logout",
        "register",
        "password",
        "reset",
        "forgot",
        "verify",
        "verification",
        "confirm",
        "twofactor",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        controller_files = {c.file_path for c in facts.controllers}
        if not controller_files:
            return findings

        # Escalate to HIGH when validation rule-count is large.
        min_rules = int(self.get_threshold("min_rules", 2))
        high_if_rules_ge = int(self.get_threshold("high_if_rules_ge", 6))
        has_form_requests = bool(facts.form_requests)
        capabilities = enabled_capabilities(facts)
        team_standards = enabled_team_standards(facts)
        auth_flow_context = set(getattr(getattr(facts, "project_context", None), "auth_flow_paths", []) or [])

        grouped: dict[tuple[str, str], list[ValidationUsage]] = {}
        for v in facts.validations:
            if v.file_path not in controller_files:
                continue
            if v.validation_type == "form_request":
                continue
            grouped.setdefault((v.file_path, v.method_name), []).append(v)

        # Best-effort map file -> controller fqcn.
        fqcn_by_file: dict[str, str] = {}
        for c in facts.controllers:
            fqcn_by_file.setdefault(c.file_path, c.fqcn)
        methods_by_key = {
            (m.file_path, (m.name or "").lower()): m
            for m in facts.methods
            if m.file_path in controller_files and m.name
        }

        for (file_path, method_name), vals in grouped.items():
            normalized_method_name = (method_name or "").lower()
            method_info = methods_by_key.get((file_path, normalized_method_name))
            line_start = min(v.line_number for v in vals)
            max_rules = max((sum(len(r) for r in v.rules.values()) for v in vals), default=0)
            max_fields = max((len(v.rules) for v in vals), default=0)

            if self._is_small_auth_validation(file_path, method_name, vals, max_rules, max_fields):
                continue
            if self._matches_auth_flow_context(file_path, method_name, auth_flow_context):
                continue
            if max_rules < min_rules and max_fields < 2:
                continue
            if self._is_delegated_light_validation(method_info, max_rules, max_fields):
                continue

            confidence = self._confidence_for_validation(vals, max_rules, max_fields, has_form_requests, file_path, method_name)

            sev = self.severity
            if max_rules >= high_if_rules_ge:
                sev = Severity.HIGH
            elif confidence < 0.7:
                sev = Severity.LOW
            if "form_requests_expected" in team_standards and sev != Severity.HIGH:
                sev = Severity.MEDIUM

            controller_fqcn = fqcn_by_file.get(file_path, "")
            fallback_ctx = f"{controller_fqcn}::{method_name}" if controller_fqcn else f"{file_path}:{method_name}"
            ctx = method_info.method_fqn if method_info is not None else fallback_ctx
            guidance = project_aware_guidance(facts, focus="controller_boundaries")

            examples = ", ".join(sorted({v.validation_type for v in vals})[:3])
            if len(vals) > 3:
                examples += f", +{len(vals) - 3} more"

            findings.append(
                self.create_finding(
                    title="Inline validation in controller (use FormRequest)",
                    context=ctx,
                    file=file_path,
                    line_start=line_start,
                    description=(
                        f"Detected inline validation inside a controller method ({examples}). "
                        "Prefer a dedicated FormRequest to keep controllers thin and validation reusable."
                        + (f" (Max rules detected: {max_rules}.)" if max_rules else "")
                    ),
                    why_it_matters=(
                        "Inline validation clutters controllers and makes validation rules hard to reuse or test. "
                        "FormRequests centralize rules and authorization, improving maintainability."
                    ),
                    suggested_fix=(
                        "1. Create a FormRequest: `php artisan make:request ...Request`\n"
                        "2. Move the rules into `rules()`\n"
                        "3. Type-hint the FormRequest in the controller method\n"
                        "4. Use `$request->validated()`"
                    ) + (f"\n\nProject-aware guidance:\n{guidance}" if guidance else ""),
                    classification=FindingClassification.ADVISORY,
                    confidence=confidence,
                    severity=sev,
                    tags=["validation", "form-request", "controllers", *recommendation_context_tags(facts)],
                    metadata={
                        "decision_profile": {
                            "decision": "emit",
                            "project_business_context": str(getattr(getattr(facts, "project_context", None), "project_business_context", "unknown") or "unknown"),
                            "capabilities": sorted(capabilities),
                            "team_standards": sorted(team_standards),
                            "decision_summary": "Inline controller validation exceeded context-aware threshold for FormRequest extraction.",
                            "decision_reasons": [
                                f"min_rules={min_rules}",
                                f"max_rules={max_rules}",
                                f"max_fields={max_fields}",
                                f"confidence={confidence:.2f}",
                                f"form_requests_expected={int('form_requests_expected' in team_standards)}",
                            ],
                        },
                        "overlap_group": "controller-layering",
                        "overlap_scope": ctx,
                        "overlap_rank": 130,
                        "overlap_role": "child",
                    },
                )
            )

        return findings

    def _is_small_auth_validation(
        self,
        file_path: str,
        method_name: str,
        vals: list[ValidationUsage],
        max_rules: int,
        max_fields: int,
    ) -> bool:
        low = f"{file_path} {method_name}".lower().replace("\\", "/")
        if not any(marker in low for marker in self._SMALL_AUTH_MARKERS):
            return False
        return len(vals) == 1 and max_rules <= 3 and max_fields <= 2

    def _confidence_for_validation(
        self,
        vals: list[ValidationUsage],
        max_rules: int,
        max_fields: int,
        has_form_requests: bool,
        file_path: str,
        method_name: str,
    ) -> float:
        confidence = 0.56
        if max_rules >= 6:
            confidence += 0.22
        elif max_rules >= 4:
            confidence += 0.14
        elif max_rules >= 2:
            confidence += 0.08
        if len(vals) > 1:
            confidence += 0.08
        if max_fields >= 3:
            confidence += 0.05
        if has_form_requests:
            confidence += 0.04
        low = f"{file_path} {method_name}".lower().replace("\\", "/")
        if not any(marker in low for marker in self._SMALL_AUTH_MARKERS):
            confidence += 0.05
        return min(0.92, confidence)

    def _matches_auth_flow_context(
        self,
        file_path: str,
        method_name: str,
        auth_flow_context: set[str],
    ) -> bool:
        normalized_path = str(file_path or "").replace("\\", "/")
        if normalized_path in auth_flow_context:
            return True
        tail = normalized_path.lower()
        if any(marker in tail for marker in self._SMALL_AUTH_MARKERS):
            return True
        descriptors = {
            method_name or "",
            f"{normalized_path}:{method_name}",
        }
        return any(descriptor in auth_flow_context for descriptor in descriptors)

    def _is_delegated_light_validation(self, method, max_rules: int, max_fields: int) -> bool:
        if method is None:
            return False
        call_sites = [str(cs or "").lower() for cs in (method.call_sites or [])]
        delegation_markers = (
            "->execute(",
            "->handle(",
            "->run(",
            "service->",
            "action->",
            "coordinator->",
            "workflow->",
        )
        has_delegation = any(any(marker in cs for marker in delegation_markers) for cs in call_sites)
        if not has_delegation:
            return False
        return max_rules <= 3 and max_fields <= 2 and int(getattr(method, "loc", 0) or 0) <= 55
