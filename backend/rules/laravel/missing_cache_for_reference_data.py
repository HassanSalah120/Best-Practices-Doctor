"""
Missing Cache for Reference Data Rule

Detects reference data queries that could benefit from caching.
"""

from __future__ import annotations

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

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Check if project uses Cache at all
        has_cache_usage = self._check_cache_usage(facts)
        if not has_cache_usage:
            # Don't suggest caching if project doesn't use it
            return findings

        for q in facts.queries:
            # Skip non-SELECT queries
            if q.query_type != "select":
                continue

            # Skip allowlisted paths
            norm_path = (q.file_path or "").replace("\\", "/").lower()
            if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
                continue

            # Check if model is reference data
            model_lower = (q.model or "").lower().replace("\\", "").replace("_", "")
            is_reference_data = any(ref in model_lower for ref in self._REFERENCE_DATA_MODELS)

            if not is_reference_data:
                continue

            # Check if method name suggests getter pattern
            method_lower = (q.method_name or "").lower()
            is_getter = any(pattern in method_lower for pattern in self._GETTER_METHOD_PATTERNS)

            # Check if query is in a service (more likely to benefit from caching)
            is_service = "/services/" in norm_path

            # Adjust confidence
            confidence = 0.70
            if is_getter:
                confidence += 0.10
            if is_service:
                confidence += 0.10

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
