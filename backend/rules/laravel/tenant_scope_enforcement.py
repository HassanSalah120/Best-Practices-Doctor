"""
Tenant Scope Enforcement Rule

Detects query methods in multi-tenant code that do not show tenant/clinic scoping signals.
"""

from __future__ import annotations

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


class TenantScopeEnforcementRule(Rule):
    id = "tenant-scope-enforcement"
    name = "Tenant Scope Enforcement"
    description = "Detects tenant-sensitive queries that appear to be missing tenant scoping"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _TENANT_MARKERS = (
        "tenant",
        "tenant_id",
        "clinic",
        "clinic_id",
        "organization",
        "organization_id",
        "account",
        "account_id",
        "workspace",
        "workspace_id",
        "practice",
        "branch",
    )
    _STRONG_TENANT_MARKERS = (
        "tenant",
        "tenant_id",
        "clinic",
        "clinic_id",
        "workspace",
        "workspace_id",
        "organization",
        "organization_id",
        "tenant_access",
        "clinic_access",
    )
    _WEAK_TENANT_MARKERS = (
        "account",
        "account_id",
        "practice",
        "branch",
    )
    _PUBLIC_CONTEXT_MARKERS = ("auth/", "public/", "webhook", "health", "status")
    _ALLOWLIST_PATH_MARKERS = (
        "/tests/",
        "/test/",
        "/vendor/",
        "/node_modules/",
        "/storybook/",
        "/stories/",
        "/demo/",
        "/demos/",
        "/resources/lang/",
        "/lang/",
    )
    _GLOBAL_MODEL_ALLOWLIST = {
        "setting",
        "settings",
        "country",
        "countries",
        "currency",
        "currencies",
        "language",
        "languages",
        "permission",
        "permissions",
        "role",
        "roles",
        "featureflag",
        "featureflags",
        "timezone",
        "timezones",
        "locale",
        "locales",
        "countrycallingcode",
        "countrycallingcodes",
        "callingcode",
        "callingcodes",
    }
    _STATIC_DATA_SERVICE_MARKERS = (
        "countrycallingcode",
        "callingcode",
        "countrycode",
        "phonenumber",
        "timezone",
        "locale",
        "currency",
        "language",
        "staticdata",
        "referencedata",
        "lookupdata",
    )
    # Methods that are system-wide scheduled tasks (operate across all tenants)
    _SCHEDULED_TASK_PATTERNS = (
        "sendpostvisit",
        "senddaily",
        "sendweekly",
        "sendmonthly",
        "processqueue",
        "processscheduled",
        "cleanup",
        "prune",
        "expire",
        "archive",
        "syncall",
        "importall",
        "exportall",
        "generateall",
        "notifyall",
        "reminder",
        "alert",
        "broadcast",
    )
    _AUTH_MIDDLEWARE_TOKENS = ("auth", "sanctum", "passport", "verified")
    _READ_TOKENS = {"get", "first", "paginate", "all", "find", "findorfail", "pluck", "count", "exists"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_signals = int(self.get_threshold("min_project_signals", 5) or 5)
        min_method_queries = int(self.get_threshold("min_method_queries", 1) or 1)
        min_confidence = float(self.get_threshold("min_confidence", 0.65) or 0.65)
        require_multi_tenant_capability = bool(self.get_threshold("require_multi_tenant_capability", False))
        tenant_mode = str(getattr(getattr(facts, "project_context", None), "tenant_mode", "unknown") or "unknown").lower()
        capabilities = enabled_capabilities(facts)
        team_standards = enabled_team_standards(facts)
        if require_multi_tenant_capability and "multi_tenant" not in capabilities and tenant_mode != "tenant":
            return findings

        if tenant_mode == "non_tenant":
            return findings

        project_signal_score, project_strong_hits = self._project_tenant_signals(facts)
        if tenant_mode != "tenant" and (project_signal_score < min_signals or project_strong_hits == 0):
            return findings

        methods_by_key: dict[tuple[str, str], MethodInfo] = {
            (m.file_path, m.name): m for m in facts.methods if not m.name.startswith("__")
        }
        routes_by_target = self._routes_by_target(facts)

        grouped: dict[tuple[str, str], list] = {}
        for q in facts.queries:
            grouped.setdefault((q.file_path, q.method_name), []).append(q)

        for key, qs in grouped.items():
            method = methods_by_key.get(key)
            if not method:
                continue

            if not self._is_tenant_sensitive_path(method.file_path):
                continue
            if self._is_allowlisted_path(method.file_path):
                continue
            if self._is_public_context_path(method.file_path):
                continue
            if self._looks_auth_or_public_method(method):
                continue
            if self._is_static_data_service(method):
                continue
            if self._is_scheduled_task(method):
                continue

            unsafe: list = []
            for q in qs:
                if not self._is_read_query(q.method_chain or ""):
                    continue
                if self._is_global_model_allowlisted(q.model):
                    continue
                if self._has_tenant_scope_signal(q.method_chain or "", method):
                    continue
                if q.model and self._is_tenant_root_model(q.model):
                    # Querying Tenant/Clinic model itself is often bootstrap/admin workflow.
                    continue
                unsafe.append(q)

            if len(unsafe) < min_method_queries:
                continue

            route_ctx = routes_by_target.get((method.class_name.lower(), method.name.lower()), [])
            if not self._has_method_tenant_context(method, route_ctx):
                continue
            if route_ctx and self._all_routes_look_public(route_ctx):
                continue

            models = sorted({q.model for q in unsafe if q.model})[:4]
            model_text = ", ".join(models) if models else "tenant-sensitive models"
            confidence = 0.58 + (0.07 * min(len(unsafe), 4))
            if route_ctx and any(self._route_has_auth_middleware(r) for r in route_ctx):
                confidence += 0.08
            low_path = method.file_path.lower().replace("\\", "/")
            if "/clinic/" in low_path or "/tenant/" in low_path:
                confidence += 0.05
            confidence = min(0.92, confidence)
            if confidence < min_confidence:
                continue
            guidance = project_aware_guidance(facts, focus="orchestration_boundaries")

            evidence = [
                f"method={method.method_fqn}",
                f"unscoped_read_queries={len(unsafe)}",
            ]
            if models:
                evidence.append(f"models={','.join(models)}")
            if route_ctx:
                evidence.append(f"route_bindings={len(route_ctx)}")
                if any(self._route_has_auth_middleware(r) for r in route_ctx):
                    evidence.append("route_auth_context=true")

            findings.append(
                self.create_finding(
                    title="Query appears missing tenant/clinic scope",
                    context=method.method_fqn,
                    file=method.file_path,
                    line_start=method.line_start,
                    line_end=method.line_end,
                    description=(
                        f"Method `{method.method_fqn}` executes query operations for {model_text} "
                        "without an obvious tenant/clinic scope signal."
                    ),
                    why_it_matters=(
                        "In multi-tenant SaaS, missing tenant scope checks can cause cross-tenant data exposure."
                    ),
                    suggested_fix=(
                        "Apply explicit tenant scoping in repository/service queries "
                        "(e.g., `where('clinic_id', $clinicId)` or a shared tenant scope helper).\n"
                        "Add integration tests to ensure users cannot access other tenants' data."
                    ) + (f"\n\nProject-aware guidance:\n{guidance}" if guidance else ""),
                    tags=["laravel", "security", "multi-tenant", "data-isolation", *recommendation_context_tags(facts)],
                    confidence=confidence,
                    evidence_signals=evidence,
                    metadata={
                        "decision_profile": {
                            "decision": "emit",
                            "project_business_context": str(getattr(getattr(facts, "project_context", None), "project_business_context", "unknown") or "unknown"),
                            "capabilities": sorted(capabilities),
                            "team_standards": sorted(team_standards),
                            "decision_summary": "Potential unscoped tenant read detected in tenant-sensitive method context.",
                            "decision_reasons": [
                                f"tenant_mode={tenant_mode}",
                                f"project_signal_score={project_signal_score}",
                                f"unsafe_queries={len(unsafe)}",
                                f"min_confidence={min_confidence:.2f}",
                            ],
                        }
                    },
                )
            )

        return findings

    def _project_tenant_signals(self, facts: Facts) -> tuple[int, int]:
        score = 0
        strong_hits = 0
        for f in facts.files or []:
            low = f.lower().replace("\\", "/")
            item_score, item_strong = self._tenant_marker_score(low)
            score += item_score
            strong_hits += item_strong
        for c in facts.classes or []:
            name = (c.name or "").lower()
            fqcn = (c.fqcn or "").lower()
            item_score, item_strong = self._tenant_marker_score(f"{name} {fqcn}")
            score += item_score
            strong_hits += item_strong
        for route in facts.routes or []:
            route_text = " ".join(
                [
                    str(getattr(route, "uri", "") or ""),
                    " ".join(str(x or "") for x in (getattr(route, "middleware", []) or [])),
                ]
            ).lower()
            item_score, item_strong = self._tenant_marker_score(route_text)
            score += item_score
            strong_hits += item_strong
        return score, strong_hits

    def _is_tenant_sensitive_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return low.startswith("app/") and any(p in low for p in ["/controllers/", "/services/"])

    def _has_method_tenant_context(self, method: MethodInfo, route_ctx: list) -> bool:
        method_text = " ".join(
            [
                str(method.file_path or ""),
                str(method.class_name or ""),
                str(method.class_fqcn or ""),
            ]
        ).lower().replace("\\", "/")
        _, strong_hits = self._tenant_marker_score(method_text)
        if strong_hits:
            return True

        for route in route_ctx or []:
            route_text = " ".join(
                [
                    str(getattr(route, "uri", "") or ""),
                    " ".join(str(x or "") for x in (getattr(route, "middleware", []) or [])),
                ]
            ).lower()
            _, route_strong_hits = self._tenant_marker_score(route_text)
            if route_strong_hits:
                return True
        return False

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATH_MARKERS)

    def _is_public_context_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._PUBLIC_CONTEXT_MARKERS)

    def _looks_auth_or_public_method(self, method: MethodInfo) -> bool:
        low_file = (method.file_path or "").lower().replace("\\", "/")
        if any(tok in low_file for tok in ["/auth/", "login", "register", "password", "reset"]):
            return True
        low_name = (method.name or "").lower()
        return low_name in {"login", "logout", "register", "forgotpassword", "resetpassword", "webhook"}

    def _is_tenant_root_model(self, model: str) -> bool:
        low = (model or "").lower()
        return any(m in low for m in ["tenant", "clinic", "organization", "workspace", "account"])

    def _is_static_data_service(self, method: MethodInfo) -> bool:
        """Check if this service returns static reference data (no DB queries, no tenant scope needed)."""
        # Check class name for static data markers
        class_name = (method.class_name or "").lower().replace("_", "").replace("-", "")
        if any(m in class_name for m in self._STATIC_DATA_SERVICE_MARKERS):
            return True
        
        # Check file path for static data patterns
        file_path = (method.file_path or "").lower().replace("\\", "/")
        if any(m in file_path for m in ["countrycallingcode", "callingcode", "staticdata", "referencedata"]):
            return True
        
        # Check if method returns from a Data object (not database)
        call_sites = " ".join(method.call_sites or []).lower()
        if "data->get" in call_sites or "data->all" in call_sites:
            return True
        
        return False

    def _is_scheduled_task(self, method: MethodInfo) -> bool:
        """Check if this is a system-wide scheduled task that operates across all tenants."""
        method_name = (method.name or "").lower().replace("_", "")
        if any(pattern in method_name for pattern in self._SCHEDULED_TASK_PATTERNS):
            return True
        
        # Check for Console/Command context
        file_path = (method.file_path or "").lower().replace("\\", "/")
        if "/console/" in file_path or "/commands/" in file_path:
            return True
        
        # Check docblock for scheduled task indicators
        doc_comment = str(getattr(method, "doc_comment", "") or "").lower()
        if any(kw in doc_comment for kw in ["scheduled", "cron", "console", "command", "system-wide", "background"]):
            return True
        
        return False

    def _is_global_model_allowlisted(self, model: str | None) -> bool:
        m = (model or "").strip().lower().replace("_", "").replace("\\", "")
        return bool(m and m in self._GLOBAL_MODEL_ALLOWLIST)

    def _is_read_query(self, chain: str) -> bool:
        tokens = [t.strip().lower() for t in (chain or "").split("->") if t.strip()]
        return any(t in self._READ_TOKENS for t in tokens)

    def _has_tenant_scope_signal(self, chain: str, method: MethodInfo) -> bool:
        chain_low = (chain or "").lower()
        if any(m in chain_low for m in self._TENANT_MARKERS):
            return True

        joined_calls = " ".join(method.call_sites or []).lower()
        if any(m in joined_calls for m in self._TENANT_MARKERS):
            return True
        if any(k in joined_calls for k in ("currenttenant", "currentclinic", "forclinic", "fortenant", "scopebytenant")):
            return True
        return False

    def _tenant_marker_score(self, text: str) -> tuple[int, int]:
        low = (text or "").lower()
        strong = sum(1 for marker in self._STRONG_TENANT_MARKERS if marker in low)
        weak = sum(1 for marker in self._WEAK_TENANT_MARKERS if marker in low)
        return (strong * 2) + weak, strong

    def _routes_by_target(self, facts: Facts) -> dict[tuple[str, str], list]:
        out: dict[tuple[str, str], list] = {}
        for route in facts.routes or []:
            controller = self._normalize_controller_name(route.controller or "")
            action = str(route.action or "").strip().lower()
            if not controller or not action:
                continue
            out.setdefault((controller.lower(), action), []).append(route)
        return out

    def _all_routes_look_public(self, routes: list) -> bool:
        if not routes:
            return False
        for r in routes:
            uri = str(getattr(r, "uri", "") or "").lower().strip("/")
            if any(x in uri for x in ["login", "register", "password", "reset", "webhook", "health", "status", "ping"]):
                continue
            return False
        return True

    def _route_has_auth_middleware(self, route) -> bool:
        txt = " ".join([str(x).lower() for x in (getattr(route, "middleware", []) or [])])
        return any(tok in txt for tok in self._AUTH_MIDDLEWARE_TOKENS)

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
