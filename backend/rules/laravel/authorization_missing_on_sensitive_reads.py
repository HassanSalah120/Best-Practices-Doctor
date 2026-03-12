"""
Authorization Missing On Sensitive Reads Rule

Detects controller read actions that look tenant/account sensitive but do not
show policy or ability checks.
"""

from __future__ import annotations

import re

from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class AuthorizationMissingOnSensitiveReadsRule(Rule):
    id = "authorization-missing-on-sensitive-reads"
    name = "Authorization Missing On Sensitive Reads"
    description = "Detects sensitive read flows without visible policy or ability checks"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _SENSITIVE_METHOD_NAMES = {
        "show",
        "view",
        "edit",
        "download",
        "export",
        "preview",
        "receipt",
        "statement",
        "invoice",
        "attachment",
    }
    _READ_TOKENS = {
        "find",
        "findorfail",
        "first",
        "firstorfail",
        "get",
        "paginate",
        "simplepaginate",
        "cursorpaginate",
        "all",
        "pluck",
        "count",
        "exists",
        "sole",
        "value",
    }
    _WRITE_TOKENS = {
        "create",
        "update",
        "delete",
        "insert",
        "upsert",
        "save",
        "sync",
        "attach",
        "detach",
    }
    _AUTHZ_MIDDLEWARE_TOKENS = ("can:", "permission:", "role:")
    _AUTH_MIDDLEWARE_TOKENS = ("auth", "sanctum", "passport", "verified")
    _PUBLIC_ACTION_NAMES = {"login", "register", "verify", "callback", "health", "status", "ping", "webhook"}
    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/", "/database/migrations/", "/database/factories/")
    _SENSITIVE_MARKERS = (
        "account",
        "billing",
        "clinic",
        "tenant",
        "workspace",
        "practice",
        "patient",
        "claim",
        "lab",
        "inventory",
        "message",
        "survey",
        "order",
        "invoice",
        "receipt",
        "statement",
        "report",
        "admin",
        "staff",
        "user",
        "profile",
    )
    _AUTH_PATTERNS = [
        re.compile(r"\bauthorize\s*\(", re.IGNORECASE),
        re.compile(r"\bauthorizeResource\s*\(", re.IGNORECASE),
        re.compile(r"\bGate::\s*(authorize|allows|denies|check|any|inspect)\s*\(", re.IGNORECASE),
        re.compile(r"->\s*(can|cannot)\s*\(", re.IGNORECASE),
        re.compile(r"\babort\s*\(\s*(401|403)\b", re.IGNORECASE),
        re.compile(r"\babort_(if|unless)\s*\(", re.IGNORECASE),
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

        routes_by_target = self._routes_by_target(facts)
        ctor_ability_map = self._controller_ctor_ability_map(facts)

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
            if any(self._is_write_query(q.method_chain or "") for q in qs):
                continue

            read_qs = [q for q in qs if self._is_read_query(q.method_chain or "")]
            if not read_qs:
                continue

            route_ctx = routes_by_target.get((method.class_name.lower(), method.name.lower()), [])
            if not self._looks_sensitive(method, route_ctx, read_qs):
                continue

            if self._method_has_authz_guard(method):
                continue
            if ctor_ability_map.get(method.class_name, False):
                continue
            if self._routes_have_ability_guard(route_ctx):
                continue

            models = sorted({q.model for q in read_qs if q.model})[:4]
            model_text = ", ".join(models) if models else "sensitive models"
            confidence = 0.67
            if any(self._route_has_auth_middleware(r) for r in route_ctx):
                confidence += 0.1
            if any("{" in str(getattr(r, "uri", "") or "") for r in route_ctx):
                confidence += 0.08
            if method.name.lower() in self._SENSITIVE_METHOD_NAMES:
                confidence += 0.05
            confidence = min(0.91, confidence)

            evidence = [
                f"method={method.method_fqn}",
                f"read_queries={len(read_qs)}",
                "authorization_guard_missing=true",
            ]
            if models:
                evidence.append(f"models={','.join(models)}")
            if route_ctx:
                evidence.append(f"route_bindings={len(route_ctx)}")
                if any(self._route_has_auth_middleware(r) for r in route_ctx):
                    evidence.append("route_auth_context=true")

            findings.append(
                self.create_finding(
                    title="Sensitive read action appears to be missing authorization checks",
                    context=method.method_fqn,
                    file=method.file_path,
                    line_start=method.line_start,
                    line_end=method.line_end,
                    description=(
                        f"Controller method `{method.method_fqn}` reads {model_text} in a sensitive route or "
                        "domain context but no policy, gate, or ability middleware was detected."
                    ),
                    why_it_matters=(
                        "Read endpoints can still produce IDOR or cross-tenant disclosure bugs when object-level "
                        "authorization is skipped."
                    ),
                    suggested_fix=(
                        "Add explicit read authorization checks such as `$this->authorize('view', $model)` or "
                        "route ability middleware (`can:view,model`). Add forbidden-path tests for other accounts "
                        "or tenants."
                    ),
                    tags=["laravel", "security", "authorization", "idor", "read-access"],
                    confidence=confidence,
                    evidence_signals=evidence,
                )
            )

        return findings

    def _looks_sensitive(self, method: MethodInfo, route_ctx: list, queries: list) -> bool:
        low_file = (method.file_path or "").lower().replace("\\", "/")
        low_name = (method.name or "").lower()

        if low_name in self._SENSITIVE_METHOD_NAMES:
            return True
        if any(marker in low_file for marker in self._SENSITIVE_MARKERS):
            return True

        for route in route_ctx:
            uri = str(getattr(route, "uri", "") or "").lower()
            if "{" in uri:
                return True
            if any(marker in uri for marker in self._SENSITIVE_MARKERS):
                return True

        if any(self._route_has_auth_middleware(r) for r in route_ctx):
            return True

        return any(any(marker in str(q.model or "").lower() for marker in self._SENSITIVE_MARKERS) for q in queries)

    def _method_has_authz_guard(self, method: MethodInfo) -> bool:
        joined = "\n".join(method.call_sites or [])
        return any(pat.search(joined) for pat in self._AUTH_PATTERNS)

    def _routes_have_ability_guard(self, routes: list) -> bool:
        if not routes:
            return False
        for route in routes:
            txt = " ".join([str(x).lower() for x in (getattr(route, "middleware", []) or [])])
            if any(tok in txt for tok in self._AUTHZ_MIDDLEWARE_TOKENS):
                return True
        return False

    def _route_has_auth_middleware(self, route) -> bool:
        txt = " ".join([str(x).lower() for x in (getattr(route, "middleware", []) or [])])
        return any(tok in txt for tok in self._AUTH_MIDDLEWARE_TOKENS)

    def _controller_ctor_ability_map(self, facts: Facts) -> dict[str, bool]:
        out: dict[str, bool] = {}
        controller_names = {c.name for c in facts.controllers}
        for method in facts.methods:
            if method.class_name not in controller_names:
                continue
            if method.name != "__construct":
                continue
            lc_calls = " ".join(method.call_sites or []).lower()
            if "authorizeresource(" in lc_calls:
                out[method.class_name] = True
                continue
            if "middleware(" not in lc_calls:
                continue
            if any(tok in lc_calls for tok in self._AUTHZ_MIDDLEWARE_TOKENS):
                out[method.class_name] = True
        return out

    def _is_read_query(self, chain: str) -> bool:
        tokens = [t.strip().lower() for t in (chain or "").split("->") if t.strip()]
        return any(t in self._READ_TOKENS for t in tokens)

    def _is_write_query(self, chain: str) -> bool:
        tokens = [t.strip().lower() for t in (chain or "").split("->") if t.strip()]
        return any(t in self._WRITE_TOKENS for t in tokens)

    def _routes_by_target(self, facts: Facts) -> dict[tuple[str, str], list]:
        out: dict[tuple[str, str], list] = {}
        for route in facts.routes or []:
            controller = self._normalize_controller_name(route.controller or "")
            action = str(route.action or "").strip().lower()
            if not controller or not action:
                continue
            out.setdefault((controller.lower(), action), []).append(route)
        return out

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATH_MARKERS)

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
