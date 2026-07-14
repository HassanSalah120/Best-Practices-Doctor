"""
Tenant Global Scope Missing Rule

Detects multi-tenant Laravel projects that have tenant-scoped models (models
with `clinic_id`, `tenant_id`, etc.) but no global tenant scope registered in
any ServiceProvider.

A global scope (`addGlobalScope`) is the recommended pattern for enforcing
tenant isolation at the model level — without it, every query must manually
add `->where('clinic_id', ...)`, which is error-prone.

Guards on the tenant detection signal from project context to avoid false
positives on single-tenant or non-tenant projects.
"""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class TenantGlobalScopeMissingRule(Rule):
    id = "tenant-global-scope-missing"
    name = "Tenant Global Scope Missing"
    description = "Detects multi-tenant projects missing a global tenant scope in ServiceProviders"
    category = Category.DATA_INTEGRITY
    default_severity = Severity.HIGH
    type = "ast"
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = (
        "Register a global tenant scope in a ServiceProvider:\n"
        "```php\n"
        "use App\\Models\\Scopes\\TenantScope;\n\n"
        "public function boot(): void\n"
        "{\n"
        "    Patient::addGlobalScope(new TenantScope());\n"
        "    Appointment::addGlobalScope(new TenantScope());\n"
        "}\n"
        "```\n"
        "Or use a trait-based approach with `addGlobalScope` in the model's `booted()` method."
    )
    examples = {
        "bad": "// No global scope — every query must manually add ->where('clinic_id', ...)",
        "good": "Patient::addGlobalScope(fn ($qb) => $qb->where('clinic_id', auth()->user()->clinic_id));",
    }
    priority = 1
    group = "Access Control"
    applies_to = ["provider"]
    references = [
        "Laravel docs: Global Scopes",
        "OWASP A01:2021 - Broken Access Control",
    ]
    related_rules = ["tenant-scope-enforcement", "tenant-access-middleware-missing", "idor-risk-missing-ownership-check"]
    false_positive_notes = (
        "Projects that enforce tenant isolation at the middleware, repository, or database "
        "level (row-level security, separate databases) may not need a global Eloquent scope. "
        "Only flags projects where tenant_mode is detected as 'tenant' and tenant-scoped "
        "models exist but no scope registration is found."
    )
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "tenant-global-scope"}

    _PROVIDER_REGISTRATION = re.compile(
        r"(addGlobalScope|withoutGlobalScope|TenantScope|ClinicScope|"
        r"App\\Models\\Scopes\\|Scopes\\|"
        r"boot\s*\(\s*\)\s*\{)",
        re.IGNORECASE,
    )
    _TENANT_COLUMNS = re.compile(
        r"(clinic_id|tenant_id|workspace_id|organization_id|account_id|practice_id|branch_id)",
        re.IGNORECASE,
    )
    _TENANT_MODEL_NAMES = re.compile(
        r"(clinic|tenant|workspace|organization|account)\b",
        re.IGNORECASE,
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        project_context = getattr(facts, "project_context", None)
        if not project_context:
            return []

        tenant_mode = str(getattr(project_context, "tenant_mode", "unknown") or "unknown").lower()
        if tenant_mode != "tenant":
            return []

        capabilities = (getattr(project_context, "capabilities", {}) or {}).get("multi_tenant", {})
        if not isinstance(capabilities, dict) or not capabilities.get("enabled"):
            backend_caps = (getattr(project_context, "backend_capabilities", {}) or {}).get("multi_tenant", {})
            if not isinstance(backend_caps, dict) or not backend_caps.get("enabled"):
                return []

        provider_files = [
            p for p in (getattr(facts, "files", []) or [])
            if "serviceprovider" in p.lower().replace("\\", "/")
        ]
        if not provider_files:
            return []

        has_scope_registration = False
        for provider_path in provider_files:
            content = self._read_file(facts, provider_path)
            if self._PROVIDER_REGISTRATION.search(content or ""):
                has_scope_registration = True
                break

        if has_scope_registration:
            return []

        tenant_scoped_models = self._find_tenant_models(facts)
        if len(tenant_scoped_models) < 2:
            return []

        models_str = ", ".join(sorted(tenant_scoped_models)[:8])

        return [
            self.create_finding(
                title="Multi-tenant project missing global tenant scope",
                context=f"Providers checked: {len(provider_files)}",
                file=provider_files[0],
                line_start=1,
                description=(
                    f"Project has {len(tenant_scoped_models)} tenant-scoped models "
                    f"({models_str}) but no ServiceProvider registers a global tenant scope "
                    f"(`addGlobalScope` / `TenantScope`). Each model requires manual "
                    f"`->where('clinic_id', ...)` on every query."
                ),
                why_it_matters=(
                    "Without a global tenant scope, tenant isolation depends on every developer "
                    "remembering to add the scope manually. This is the #1 source of "
                    "cross-tenant data leaks in multi-tenant SaaS applications."
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.82,
                tags=["laravel", "security", "multi-tenant", "global-scope"],
                evidence_signals=[
                    "tenant_scope_registration_missing=true",
                    f"tenant_mode={tenant_mode}",
                    f"tenant_models_count={len(tenant_scoped_models)}",
                    f"provider_files_checked={len(provider_files)}",
                ],
            ),
        ]

    def _find_tenant_models(self, facts: Facts) -> list[str]:
        tenant_models: list[str] = []
        for model in (getattr(facts, "models", []) or []):
            name = (model.name or "").lower()
            if self._TENANT_MODEL_NAMES.search(name):
                continue
            file_path = (model.file_path or "").lower().replace("\\", "/")
            content = self._read_file(facts, model.file_path)
            if content and self._TENANT_COLUMNS.search(content):
                tenant_models.append(model.name or model.fqcn or "unknown")
        return tenant_models

    def _read_file(self, facts: Facts, rel_path: str) -> str:
        if not rel_path:
            return ""
        from pathlib import Path
        root = Path(str(getattr(facts, "project_path", "") or "."))
        try:
            p = (root / rel_path).resolve()
            if p.exists():
                return p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
        return ""
