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
from core.project_recommendations import (
    enabled_capabilities,
    enabled_team_standards,
    project_aware_guidance,
    recommendation_context_tags,
)


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
        min_write_queries = int(self.get_threshold("min_write_queries", 1) or 1)
        min_mutation_signals = int(self.get_threshold("min_mutation_signals", 2) or 2)
        strict_public_action_exemptions = bool(self.get_threshold("strict_public_action_exemptions", True))
        capabilities = enabled_capabilities(facts)
        team_standards = enabled_team_standards(facts)
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
        routes_by_target = self._routes_by_target(facts)
        controller_ctor_protected = self._controller_ctor_protection_map(facts)

        for method in facts.methods:
            if method.class_name not in controller_names:
                continue
            if method.name.startswith("__"):
                continue
            if self._is_allowlisted_path(method.file_path):
                continue
            if strict_public_action_exemptions and method.name.lower() in self._PUBLIC_ACTION_NAMES:
                continue

            key = (method.file_path, method.name)
            write_count = int(write_queries.get(key, 0))
            mutation_by_name = method.name.lower() in self._MUTATION_METHOD_NAMES
            has_model_query = any(q.model for q in queries_by_method.get(key, []))
            route_ctx = routes_by_target.get((method.class_name.lower(), method.name.lower()), [])
            mutation_signal_score = 0
            if mutation_by_name:
                mutation_signal_score += 1
            if write_count >= min_write_queries:
                mutation_signal_score += 1
            if route_ctx and any("{" in str(getattr(route, "uri", "") or "") for route in route_ctx):
                mutation_signal_score += 1
            if route_ctx and any(self._route_has_auth_middleware(route) for route in route_ctx):
                mutation_signal_score += 1

            # Keep signal high: require direct query evidence and context score.
            is_mutation = (write_count >= min_write_queries) or (mutation_by_name and has_model_query)
            if not is_mutation:
                continue
            if mutation_signal_score < min_mutation_signals:
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
            guidance = project_aware_guidance(facts, focus="orchestration_boundaries")

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
                    ) + (f"\n\nProject-aware guidance:\n{guidance}" if guidance else ""),
                    tags=["laravel", "security", "authorization", "policy", *recommendation_context_tags(facts)],
                    confidence=confidence,
                    evidence_signals=evidence,
                    metadata={
                        "decision_profile": {
                            "decision": "emit",
                            "project_business_context": str(getattr(getattr(facts, "project_context", None), "project_business_context", "unknown") or "unknown"),
                            "capabilities": sorted(capabilities),
                            "team_standards": sorted(team_standards),
                            "decision_summary": "Mutation flow matched authorization-risk signals without policy/gate protection.",
                            "decision_reasons": [
                                f"mutation_by_name={int(mutation_by_name)}",
                                f"write_queries={write_count}",
                                f"route_guard={int(route_protected.get((method.class_name.lower(), method.name.lower()), False))}",
                                f"mutation_signal_score={mutation_signal_score}",
                                f"min_mutation_signals={min_mutation_signals}",
                            ],
                        },
                        "overlap_group": "authorization-boundary",
                        "overlap_scope": method.method_fqn,
                        "overlap_rank": 210,
                        "overlap_role": "parent",
                    },
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

    def _routes_by_target(self, facts: Facts) -> dict[tuple[str, str], list]:
        out: dict[tuple[str, str], list] = {}
        for route in facts.routes or []:
            controller = self._normalize_controller_name(route.controller or "")
            action = (route.action or "").strip().lower()
            if not controller or not action:
                continue
            out.setdefault((controller.lower(), action), []).append(route)
        return out

    def _route_has_auth_middleware(self, route) -> bool:
        text = " ".join(str(mw).lower() for mw in (getattr(route, "middleware", []) or []))
        return any(token in text for token in self._AUTH_MIDDLEWARE_TOKENS)

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
