"""
Policy Coverage On Mutations Rule

Detects controller mutation actions that appear to be missing authorization checks.
"""

from __future__ import annotations

import re

from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class PolicyCoverageOnMutationsRule(Rule):
    id = "policy-coverage-on-mutations"
    name = "Policy Coverage On Mutations"
    description = "Detects mutation controller actions without policy/gate/auth protection"
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
        "bulkupdate",
        "bulkdelete",
        "restore",
        "forceDelete".lower(),
    }
    _WRITE_TOKENS = {
        "create",
        "update",
        "delete",
        "insert",
        "upsert",
        "save",
        "createMany".lower(),
        "deleteMany".lower(),
        "sync",
        "attach",
        "detach",
        "increment",
        "decrement",
    }
    _AUTH_MIDDLEWARE_TOKENS = ("auth", "sanctum", "passport", "can:", "permission:", "role:")
    _PUBLIC_ACTION_NAMES = {"login", "logout", "register", "forgotpassword", "resetpassword", "verify", "callback", "webhook"}
    _ALLOWLIST_PATH_MARKERS = ("/tests/", "/test/", "/vendor/", "/database/migrations/", "/database/factories/")
    _AUTH_PATTERNS = [
        re.compile(r"\bauthorize\s*\(", re.IGNORECASE),
        re.compile(r"\bGate::\s*(authorize|allows|denies|check|any|inspect)\s*\(", re.IGNORECASE),
        re.compile(r"->\s*(can|cannot)\s*\(", re.IGNORECASE),
        re.compile(r"\b(can|cannot)\s*\(", re.IGNORECASE),
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
        write_queries: dict[tuple[str, str], int] = {}
        for q in facts.queries:
            key = (q.file_path, q.method_name)
            queries_by_method.setdefault(key, []).append(q)
            chain = (q.method_chain or "").strip().lower()
            if not chain:
                continue
            if not self._is_write_chain(chain):
                continue
            write_queries[key] = write_queries.get(key, 0) + 1

        route_protected = self._route_protection_map(facts)
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

            key = (method.file_path, method.name)
            write_count = int(write_queries.get(key, 0))
            mutation_by_name = method.name.lower() in self._MUTATION_METHOD_NAMES
            has_model_query = any(q.model for q in queries_by_method.get(key, []))
            # Keep signal high: require direct query evidence.
            is_mutation = write_count > 0 or (mutation_by_name and has_model_query)
            if not is_mutation:
                continue

            if self._method_has_auth_guard(method):
                continue
            if controller_ctor_protected.get(method.class_name, False):
                continue
            if route_protected.get((method.class_name.lower(), method.name.lower()), False):
                continue

            confidence = 0.65
            if write_count > 0:
                confidence = min(0.95, 0.75 + (0.05 * min(write_count, 4)))

            evidence = [f"method={method.method_fqn}"]
            if mutation_by_name:
                evidence.append("mutation_method_name=true")
            if write_count > 0:
                evidence.append(f"write_queries={write_count}")
            if has_model_query:
                evidence.append("direct_model_query=true")
            if not self._method_has_auth_guard(method):
                evidence.append("authorize_guard_missing=true")
            if not route_protected.get((method.class_name.lower(), method.name.lower()), False):
                evidence.append("route_auth_or_can_middleware_missing=true")

            findings.append(
                self.create_finding(
                    title="Mutation action appears to be missing policy/authorization checks",
                    context=method.method_fqn,
                    file=method.file_path,
                    line_start=method.line_start,
                    line_end=method.line_end,
                    description=(
                        f"Controller method `{method.method_fqn}` looks like a state-changing action "
                        "but no explicit authorization guard was detected "
                        "(e.g. `authorize()`, Gate check, or auth/can route middleware)."
                    ),
                    why_it_matters=(
                        "Mutation endpoints without explicit authorization checks can allow unauthorized actions, "
                        "especially when route protection changes over time."
                    ),
                    suggested_fix=(
                        "1. Add explicit policy checks (`$this->authorize(...)`) in mutation actions\n"
                        "2. Protect routes with `auth` and ability middleware (`can:...`) where appropriate\n"
                        "3. Prefer policy methods for resource-level decisions (create/update/delete)\n"
                        "4. Add feature tests for forbidden access paths"
                    ),
                    tags=["laravel", "security", "authorization", "policy"],
                    confidence=confidence,
                    evidence_signals=evidence,
                )
            )

        return findings

    def _route_protection_map(self, facts: Facts) -> dict[tuple[str, str], bool]:
        out: dict[tuple[str, str], bool] = {}
        for route in facts.routes or []:
            controller = self._normalize_controller_name(route.controller or "")
            action = (route.action or "").strip().lower()
            if not controller or not action:
                continue
            has_guard = any(
                any(tok in str(mw).lower() for tok in self._AUTH_MIDDLEWARE_TOKENS)
                for mw in (route.middleware or [])
            )
            if has_guard:
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
            has_mw = "middleware(" in lc_calls
            has_auth = any(tok in lc_calls for tok in self._AUTH_MIDDLEWARE_TOKENS)
            if "authorizeresource(" in lc_calls:
                out[m.class_name] = True
                continue
            if has_mw and has_auth:
                out[m.class_name] = True
        return out

    def _method_has_auth_guard(self, method: MethodInfo) -> bool:
        joined = "\n".join(method.call_sites or [])
        for pat in self._AUTH_PATTERNS:
            if pat.search(joined):
                return True
        return False

    def _is_write_chain(self, chain: str) -> bool:
        tokens = [t.strip().lower() for t in chain.split("->") if t.strip()]
        return any(tok in self._WRITE_TOKENS for tok in tokens)

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(m in low for m in self._ALLOWLIST_PATH_MARKERS)

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
