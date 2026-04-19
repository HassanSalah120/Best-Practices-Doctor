"""
Missing Cache for Reference Data Rule

Detects reference data queries that could benefit from caching.
"""

from __future__ import annotations

from pathlib import Path

from schemas.facts import Facts, QueryUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingCacheForReferenceDataRule(Rule):
    id = "missing-cache-for-reference-data"
    name = "Missing Cache for Reference Data"
    description = "Detects reference data queries that could benefit from caching"
    category = Category.PERFORMANCE
    default_severity = Severity.LOW
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    # Models that are typically reference data (rarely change)
    _REFERENCE_DATA_MODELS = {
        "country",
        "countries",
        "currency",
        "currencies",
        "language",
        "languages",
        "timezone",
        "timezones",
        "setting",
        "settings",
        "config",
        "configs",
        "permission",
        "permissions",
        "role",
        "roles",
        "status",
        "statuses",
        "type",
        "types",
        "category",
        "categories",
        "countrycallingcode",
        "callingcode",
        "locale",
        "locales",
        "featureflag",
        "featureflags",
    }

    # Method names that suggest getter/fetcher patterns
    _GETTER_METHOD_PATTERNS = (
        "get",
        "fetch",
        "list",
        "all",
        "load",
        "find",
    )

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/vendor/",
        "/database/",
    )
    _CACHE_CALL_PATTERNS = (
        "cache::remember",
        "cache::rememberforever",
        "cache::flexible",
        "cache()->remember",
        "cache()->rememberforever",
        "cache()->flexible",
        "->remember(",
        "->rememberforever(",
        "->flexible(",
    )
    _CONFIG_LOOKUP_PATTERNS = (
        "config::get(",
        "config(",
    )
    _SIMPLE_CONTEXT_PROJECT_TYPES = {
        "internal_admin_system",
        "public_website_with_dashboard",
        "api_backend",
        "unknown",
    }
    _HEAVY_CAPABILITIES = {"billing", "notifications_heavy", "external_integrations_heavy", "saas", "multi_role_portal"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)
        require_repeated_reference_access = bool(self.get_threshold("require_repeated_reference_access", False))
        min_reference_query_count = int(self.get_threshold("min_reference_query_count", 1) or 1)
        require_project_cache_usage = bool(self.get_threshold("require_project_cache_usage", True))
        require_service_or_repository_context = bool(self.get_threshold("require_service_or_repository_context", False))

        has_cache_usage = self._check_cache_usage(facts)
        if require_project_cache_usage and not has_cache_usage:
            return findings

        reference_queries: list[QueryUsage] = []
        model_occurrences: dict[str, int] = {}
        model_files: dict[str, set[str]] = {}
        for q in facts.queries:
            if q.query_type != "select":
                continue
            norm_path = (q.file_path or "").replace("\\", "/").lower()
            if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
                continue

            model_lower = self._model_key(q.model or "")
            if not model_lower:
                continue
            is_reference_data = any(ref in model_lower for ref in self._REFERENCE_DATA_MODELS)
            if not is_reference_data:
                continue
            if self._is_config_lookup(facts, q, model_lower):
                continue

            reference_queries.append(q)
            model_occurrences[model_lower] = model_occurrences.get(model_lower, 0) + 1
            model_files.setdefault(model_lower, set()).add(norm_path)

        if not reference_queries:
            return findings

        simple_context = self._is_simple_context(facts)
        for q in reference_queries:
            model_lower = self._model_key(q.model or "")
            norm_path = (q.file_path or "").replace("\\", "/").lower()
            repeated_count = model_occurrences.get(model_lower, 0)
            spread_files = len(model_files.get(model_lower, set()))

            if require_repeated_reference_access and repeated_count < min_reference_query_count:
                continue

            is_service_or_repository = self._is_service_or_repository_context(norm_path)
            if require_service_or_repository_context and not is_service_or_repository:
                continue

            if self._is_query_already_cached(facts, q):
                continue

            method_lower = (q.method_name or "").lower()
            is_getter = any(pattern in method_lower for pattern in self._GETTER_METHOD_PATTERNS)

            # Extra conservatism for simple/non-SaaS contexts: prefer underfiring over noisy hints.
            if simple_context and repeated_count < max(2, min_reference_query_count):
                continue
            if simple_context and not (is_service_or_repository or is_getter):
                continue

            confidence = 0.52
            if repeated_count >= min_reference_query_count:
                confidence += 0.2
            if spread_files >= 2:
                confidence += 0.08
            if is_service_or_repository:
                confidence += 0.12
            if is_getter:
                confidence += 0.08
            if any(token in model_lower for token in ("setting", "role", "permission", "country", "locale", "status")):
                confidence += 0.06
            confidence = min(0.95, confidence)
            if confidence + 1e-9 < min_confidence:
                continue

            evidence = [
                f"model={q.model or 'unknown'}",
                f"reference_query_count={repeated_count}",
                f"spread_files={spread_files}",
                f"service_or_repository_context={'true' if is_service_or_repository else 'false'}",
                f"getter_like_method={'true' if is_getter else 'false'}",
                f"simple_context={'true' if simple_context else 'false'}",
            ]
            if require_project_cache_usage:
                evidence.append(f"project_cache_usage={'true' if has_cache_usage else 'false'}")

            findings.append(
                self.create_finding(
                    title="Consider caching for reference data query",
                    context=f"{q.model}:{q.method_chain}",
                    file=q.file_path,
                    line_start=q.line_number,
                    description=(
                        f"Query on `{q.model or 'Model'}` appears to be reference data. "
                        "Consider caching the results to reduce database load."
                    ),
                    why_it_matters=(
                        "Reference data (countries, currencies, settings, etc.) rarely changes:\n"
                        "- Reduces unnecessary database queries\n"
                        "- Improves response times for frequently accessed data\n"
                        "- Decreases database server load\n"
                        "- Reference data is often used in dropdowns, lookups, and validation"
                    ),
                    suggested_fix=(
                        "1. Use Laravel's Cache facade:\n"
                        "   $countries = Cache::remember('countries', 3600, fn() =>\n"
                        "       Country::all()\n"
                        "   );\n\n"
                        "2. Choose appropriate TTL:\n"
                        "   - Static data (countries): 24 hours or more\n"
                        "   - Settings: 1-4 hours\n"
                        "   - Permissions: 5-15 minutes\n\n"
                        "3. Clear cache when data changes:\n"
                        "   Cache::forget('countries');\n\n"
                        "4. Use cache tags for grouped invalidation:\n"
                        "   Cache::tags(['settings'])->flush();"
                    ),
                    code_example=(
                        "// Before (queries every request)\n"
                        "public function getCountries()\n"
                        "{\n"
                        "    return Country::all();\n"
                        "}\n\n"
                        "// After (cached for 24 hours)\n"
                        "public function getCountries()\n"
                        "{\n"
                        "    return Cache::remember('countries.all', 86400, fn() =>\n"
                        "        Country::select(['id', 'name', 'code'])->get()\n"
                        "    );\n"
                        "}"
                    ),
                    confidence=confidence,
                    tags=["performance", "caching", "reference-data", "optimization"],
                    evidence_signals=evidence,
                )
            )

        return findings

    def _check_cache_usage(self, facts: Facts) -> bool:
        """Check if the project uses Cache facade anywhere."""
        for m in facts.methods:
            for call in m.call_sites or []:
                call_lower = call.lower()
                if "cache::" in call_lower or "cache()->" in call_lower:
                    return True
        return False

    def _is_query_already_cached(self, facts: Facts, query: QueryUsage) -> bool:
        window = self._source_window(facts, query).lower()
        if not window:
            return False

        if not any(token in window for token in self._CACHE_CALL_PATTERNS):
            return False

        if "cache::" in window or "cache()->" in window:
            return True
        return "->remember(" in window or "->rememberforever(" in window or "->flexible(" in window

    def _is_config_lookup(self, facts: Facts, query: QueryUsage, model_lower: str) -> bool:
        if model_lower not in {"config", "configs"}:
            return False

        source_window = self._source_window(facts, query)
        if not source_window:
            return True

        source_window = source_window.lower()
        return any(pattern in source_window for pattern in self._CONFIG_LOOKUP_PATTERNS)

    def _source_window(self, facts: Facts, query: QueryUsage, before: int = 20, after: int = 3) -> str:
        file_path = (query.file_path or "").replace("\\", "/").strip()
        if not file_path:
            return ""

        source_path = Path(getattr(facts, "project_path", "") or ".") / file_path
        if not source_path.exists():
            return ""

        try:
            lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return ""

        line_index = max((query.line_number or 1) - 1, 0)
        start = max(0, line_index - before)
        end = min(len(lines), line_index + after)
        return "\n".join(lines[start:end])

    def _model_key(self, raw_model: str) -> str:
        return (raw_model or "").lower().replace("\\", "").replace("_", "")

    def _is_service_or_repository_context(self, norm_path: str) -> bool:
        return "/services/" in norm_path or "/repositories/" in norm_path

    def _is_simple_context(self, facts: Facts) -> bool:
        project_type = str(getattr(facts.project_context, "project_business_context", "") or "unknown").lower()
        if project_type not in self._SIMPLE_CONTEXT_PROJECT_TYPES:
            return False

        capabilities = getattr(facts.project_context, "backend_capabilities", {}) or {}
        for capability in self._HEAVY_CAPABILITIES:
            payload = capabilities.get(capability)
            if isinstance(payload, dict) and bool(payload.get("enabled", False)):
                return False
        return True
