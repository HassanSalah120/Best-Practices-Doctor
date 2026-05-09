"""
Finding Templates

Short, actionable fix templates keyed by rule_id.
Used when a rule does not provide a specific suggested_fix text.
"""

from __future__ import annotations


FIX_TEMPLATES: dict[str, str] = {
    "policy-coverage-on-mutations": (
        "Add explicit authorization in mutation actions (`$this->authorize(...)`) and keep auth/can middleware on routes."
    ),
    "authorization-bypass-risk": (
        "Add policy or Gate authorization before direct model read/write operations in controller mutation paths."
    ),
    "tenant-scope-enforcement": (
        "Apply tenant scope explicitly (for example `where('tenant_id', ...)`) or a shared tenant scope helper."
    ),
    "missing-auth-on-mutating-api-routes": (
        "Protect mutating API routes with auth middleware (`auth:sanctum`) or move them under an authenticated group."
    ),
    "hardcoded-user-facing-strings": (
        "Replace hardcoded UI text with i18n keys (for example `t('...')`) and store strings in locale files."
    ),
    "interactive-element-a11y": (
        "Use semantic controls (`button`/`a`) or add `role`, keyboard handlers, and `tabIndex` to non-semantic clickable elements."
    ),
    "form-label-association": (
        "Associate each label with a control using `htmlFor` + `id`, or wrap the actual input inside the label."
    ),
}


def get_fix_template(rule_id: str) -> str:
    return FIX_TEMPLATES.get(str(rule_id or "").strip().lower(), "")
