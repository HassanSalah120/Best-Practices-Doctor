"""
Authorization Bypass Risk Rule

Detects mutation controller methods that access models directly without policy/gate checks.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class AuthorizationBypassRiskRule(Rule):
    id = "authorization-bypass-risk"
    name = "Authorization Bypass Risk"
    description = "Detects direct model access in mutation actions without authorization checks"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _MUTATION_METHOD_NAMES = {
        "store",
        "update",
        "destroy",
        "delete",
        "remove",
        "sync",
        "attach",
        "detach",
        "toggle",
        "upsert",
    }
    _MODEL_ACCESS_TOKENS = {"find", "findorfail", "first", "where", "query"}
    _WRITE_TOKENS = {"create", "update", "delete", "insert", "upsert", "save", "sync", "attach", "detach"}
    _AUTH_MIDDLEWARE_TOKENS = ("can:", "permission:", "role:", "auth", "sanctum", "passport")
    _PUBLIC_ACTION_NAMES = {"login", "logout", "register", "forgotpassword", "resetpassword", "verify", "callback", "webhook"}
    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/", "/database/migrations/", "/database/factories/")
    _AUTH_PATTERNS = [
        re.compile(r"\bauthorize\s*\(", re.IGNORECASE),
        re.compile(r"\bGate::\s*(authorize|allows|denies|check|any|inspect)\s*\(", re.IGNORECASE),
        re.compile(r"->\s*(can|cannot)\s*\(", re.IGNORECASE),
        re.compile(r"\babort\s*\(\s*(401|403)\b", re.IGNORECASE),
    ]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        controller_names = {c.name for c in facts.controllers}
        if not controller_names:
            return findings

        queries_by_method: dict[tuple[str, str], list] = {}
        for q in facts.queries:
            queries_by_method.setdefault((q.file_path, q.method_name), []).append(q)
        route_protected = self._route_policy_protection_map(facts)
        controller_ctor_protected = self._controller_ctor_protection_map(facts)

        for method in facts.methods:
            if method.class_name not in controller_names:
                continue
            if method.name.startswith("__"):
                continue
            if self._is_allowlisted_path(method.file_path):
                continue
            if method.name.lower() in self._PUBLIC_ACTION_NAMES:
                continue

            qs = queries_by_method.get((method.file_path, method.name), [])
            if not qs:
                continue

            mutation_by_name = method.name.lower() in self._MUTATION_METHOD_NAMES
            has_write = any(self._is_write_query(q.method_chain or "") for q in qs)
            if not mutation_by_name and not has_write:
                continue

            has_model_access = any(self._is_model_access_query(q.method_chain or "", q.model) for q in qs)
            if not has_model_access:
                continue

            if self._method_has_auth_guard(method.call_sites or []):
                continue
            if controller_ctor_protected.get(method.class_name, False):
                continue
            if route_protected.get((method.class_name.lower(), method.name.lower()), False):
                continue

            models = sorted({q.model for q in qs if q.model})[:4]
            model_text = ", ".join(models) if models else "Eloquent models"
            write_count = sum(1 for q in qs if self._is_write_query(q.method_chain or ""))
            confidence = 0.74 + (0.05 * min(write_count, 3))
            confidence = min(0.93, confidence)

            evidence = [
                f"method={method.method_fqn}",
                "direct_model_access=true",
                f"write_queries={write_count}",
                "authorization_guard_missing=true",
            ]
            if models:
                evidence.append(f"models={','.join(models)}")

            findings.append(
                self.create_finding(
                    title="Possible authorization bypass in mutating controller action",
                    context=method.method_fqn,
                    file=method.file_path,
                    line_start=method.line_start,
                    line_end=method.line_end,
                    description=(
                        f"Method `{method.method_fqn}` performs model access/mutation for {model_text} "
                        "but no policy/gate authorization guard was detected."
                    ),
                    why_it_matters=(
                        "Direct model access in mutation flows without explicit authorization can expose "
                        "object-level authorization vulnerabilities."
                    ),
                    suggested_fix=(
                        "1. Add explicit policy checks (`$this->authorize(...)`) around model operations\n"
                        "2. Use Gate checks for non-resource actions\n"
                        "3. Add forbidden-path tests for unauthorized users"
                    ),
                    tags=["laravel", "security", "authorization", "idor"],
                    confidence=confidence if has_write else max(0.7, confidence - 0.08),
                    evidence_signals=evidence,
                )
            )

        return findings

    def _method_has_auth_guard(self, call_sites: list[str]) -> bool:
        joined = "\n".join(call_sites or [])
        return any(p.search(joined) for p in self._AUTH_PATTERNS)

    def _is_model_access_query(self, method_chain: str, model: str | None) -> bool:
        chain = (method_chain or "").lower()
        tokens = [t.strip() for t in chain.split("->") if t.strip()]
        if model:
            return any(tok in self._MODEL_ACCESS_TOKENS for tok in tokens)
        return False

    def _is_write_query(self, method_chain: str) -> bool:
        chain = (method_chain or "").lower()
        tokens = [t.strip() for t in chain.split("->") if t.strip()]
        return any(tok in self._WRITE_TOKENS for tok in tokens)

    def _route_policy_protection_map(self, facts: Facts) -> dict[tuple[str, str], bool]:
        out: dict[tuple[str, str], bool] = {}
        for route in facts.routes or []:
            controller = self._normalize_controller_name(route.controller or "")
            action = str(route.action or "").strip().lower()
            if not controller or not action:
                continue
            mw_text = " ".join([str(x).lower() for x in (route.middleware or [])])
            if any(tok in mw_text for tok in self._AUTH_MIDDLEWARE_TOKENS):
                out[(controller.lower(), action)] = True
        return out

    def _controller_ctor_protection_map(self, facts: Facts) -> dict[str, bool]:
        out: dict[str, bool] = {}
        controller_names = {c.name for c in facts.controllers}
        for m in facts.methods:
            if m.class_name not in controller_names:
                continue
            if m.name != "__construct":
                continue
            lc_calls = " ".join((m.call_sites or [])).lower()
            if "authorizeresource(" in lc_calls:
                out[m.class_name] = True
                continue
            if "middleware(" in lc_calls and any(tok in lc_calls for tok in self._AUTH_MIDDLEWARE_TOKENS):
                out[m.class_name] = True
        return out

    @staticmethod
    def _normalize_controller_name(controller: str) -> str:
        s = str(controller or "").strip().replace("/", "\\")
        if not s:
            return ""
        if "::" in s:
            s = s.split("::", 1)[0]
        while s.startswith("\\"):
            s = s[1:]
        if "\\" in s:
            s = s.split("\\")[-1]
        return s

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(m in low for m in self._ALLOWLIST_PATH_MARKERS)
