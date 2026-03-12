"""
Missing Pagination Rule

Detects API endpoints returning all records without pagination or limit.
"""

from __future__ import annotations

from schemas.facts import Facts, QueryUsage, RouteInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingPaginationRule(Rule):
    id = "missing-pagination"
    name = "Missing Pagination"
    description = "Detects API endpoints returning all records without pagination or limit"
    category = Category.PERFORMANCE
    default_severity = Severity.MEDIUM
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    # Models that typically have many records
    _LARGE_TABLE_MODELS = {
        "appointment",
        "appointments",
        "patient",
        "patients",
        "user",
        "users",
        "order",
        "orders",
        "transaction",
        "transactions",
        "invoice",
        "invoices",
        "claim",
        "claims",
        "encounter",
        "encounters",
        "prescription",
        "prescriptions",
        "log",
        "logs",
        "audit",
        "audits",
        "event",
        "events",
        "message",
        "messages",
        "notification",
        "notifications",
        "activity",
        "activities",
        "record",
        "records",
        "item",
        "items",
        "product",
        "products",
        "customer",
        "customers",
    }

    # Terminal methods that return multiple records
    _MULTI_RECORD_TERMINALS = {"get", "all"}

    # Methods that indicate pagination/limit is used
    _PAGINATION_METHODS = {"paginate", "simplepaginate", "cursorpaginate", "limit", "take", "skip", "offset"}

    _ALLOWLIST_PATHS = (
        "tests/",
        "/tests/",
        "test/",
        "/test/",
        "vendor/",
        "/vendor/",
        "database/",
        "/database/",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Build route -> method mapping
        route_methods: dict[str, list[str]] = {}
        for route in facts.routes:
            if route.action and "@" in route.action:
                controller, method = route.action.split("@", 1)
                route_methods[f"{controller}::{method}"] = route.uri or ""

        for q in facts.queries:
            # Skip non-SELECT queries
            if q.query_type != "select":
                continue

            # Skip allowlisted paths
            norm_path = (q.file_path or "").replace("\\", "/").lower()
            if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
                continue

            # Check if query is in a controller (API endpoint)
            is_controller = (
                "controllers/" in norm_path or 
                "/controllers/" in norm_path or
                "controller" in norm_path.lower()
            )
            if not is_controller:
                continue

            # Parse method chain
            chain_lower = (q.method_chain or "").lower()

            # Check terminal method
            chain_parts = [p.strip() for p in chain_lower.split("->") if p.strip()]
            if not chain_parts:
                continue

            terminal = chain_parts[-1] if chain_parts else ""
            
            # Extract method name (remove parentheses and arguments)
            terminal_name = terminal.split("(")[0].strip() if "(" in terminal else terminal

            # Only flag multi-record queries
            if terminal_name not in self._MULTI_RECORD_TERMINALS:
                continue

            # Check if pagination/limit is used
            has_pagination = any(method in chain_lower for method in self._PAGINATION_METHODS)
            if has_pagination:
                continue

            # Check if model is known to be large
            model_lower = (q.model or "").lower().replace("\\", "").replace("_", "")
            is_large_model = any(large in model_lower for large in self._LARGE_TABLE_MODELS)

            # Adjust confidence based on model
            confidence = 0.75 if is_large_model else 0.55

            findings.append(
                self.create_finding(
                    title="API endpoint missing pagination",
                    context=f"{q.model}:{q.method_chain}",
                    file=q.file_path,
                    line_start=q.line_number,
                    description=(
                        f"Query on `{q.model or 'Model'}` returns all records using `->{terminal}()` "
                        "without pagination or limit. This can cause performance issues and memory exhaustion "
                        "for large datasets."
                    ),
                    why_it_matters=(
                        "Returning all records without pagination:\n"
                        "- Can exhaust PHP memory on large tables\n"
                        "- Increases response time significantly\n"
                        "- Transfers unnecessary data over network\n"
                        "- May cause timeout errors\n"
                        "- Poor user experience on slow connections\n"
                        "- Can crash the application on large datasets"
                    ),
                    suggested_fix=(
                        "1. Use Laravel's built-in pagination:\n"
                        "   Model::paginate(15);\n\n"
                        "2. Use simple pagination for better performance:\n"
                        "   Model::simplePaginate(15);\n\n"
                        "3. Use cursor pagination for large datasets:\n"
                        "   Model::cursorPaginate(15);\n\n"
                        "4. If you need all records, use chunking:\n"
                        "   Model::chunk(100, function($records) { ... });\n\n"
                        "5. For APIs, return pagination metadata:\n"
                        "   return UserResource::collection(User::paginate(15));"
                    ),
                    code_example=(
                        "// Before (returns all records - dangerous)\n"
                        "public function index()\n"
                        "{\n"
                        "    return Patient::all(); // Could be thousands of records!\n"
                        "}\n\n"
                        "// After (paginated - safe)\n"
                        "public function index()\n"
                        "{\n"
                        "    return PatientResource::collection(\n"
                        "        Patient::paginate(15)\n"
                        "    );\n"
                        "}\n\n"
                        "// Response includes pagination metadata:\n"
                        "{\n"
                        '    "data": [...],\n'
                        '    "meta": {\n'
                        '        "current_page": 1,\n'
                        '        "total": 1000,\n'
                        '        "per_page": 15\n'
                        '    }\n'
                        "}"
                    ),
                    confidence=confidence,
                    tags=["performance", "api", "pagination", "memory", "laravel"],
                )
            )

        return findings
