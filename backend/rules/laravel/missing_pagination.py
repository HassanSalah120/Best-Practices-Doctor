"""
Missing Pagination Rule

Detects API endpoints returning all records without pagination or limit.
"""

from __future__ import annotations

from pathlib import Path

from schemas.facts import Facts
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
    _API_ROUTE_FILES = {"routes/api.php"}
    _EXPORT_METHOD_HINTS = ("export", "download", "csv", "xlsx", "report", "print")
    _INDEX_METHOD_HINTS = {"index", "list", "search", "browse"}

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

        require_api_context = bool(self.get_threshold("require_api_context", True))
        min_api_context_signals = int(self.get_threshold("min_api_context_signals", 1) or 1)
        min_multi_record_signals = int(self.get_threshold("min_multi_record_signals", 2) or 2)
        large_model_only = bool(self.get_threshold("large_model_only", False))
        suppress_export_flows = bool(self.get_threshold("suppress_export_flows", True))
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        api_route_actions = self._collect_api_route_actions(facts)

        for q in facts.queries:
            # Skip non-SELECT queries
            if q.query_type != "select":
                continue

            # Skip allowlisted paths
            norm_path = (q.file_path or "").replace("\\", "/").lower()
            if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
                continue

            # Check if query is in a controller (API endpoint)
            is_controller = self._is_controller_query(norm_path)
            if not is_controller:
                continue

            method_name = (q.method_name or "").strip().lower()
            if suppress_export_flows and self._is_export_flow(norm_path, method_name):
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
            if large_model_only and not is_large_model:
                continue

            api_context, api_evidence = self._detect_api_context(q.file_path or "", method_name, api_route_actions)
            if require_api_context and not api_context:
                continue
            if require_api_context and len(api_evidence) < min_api_context_signals:
                continue

            method_hint = method_name in self._INDEX_METHOD_HINTS
            multi_record_signals = 1  # terminal get/all on controller query
            if api_context:
                multi_record_signals += 1
            if is_large_model:
                multi_record_signals += 1
            if method_hint:
                multi_record_signals += 1
            if multi_record_signals < min_multi_record_signals:
                continue

            # Adjust confidence based on model
            confidence = 0.56
            if terminal_name == "all":
                confidence += 0.08
            else:
                confidence += 0.05
            if api_context:
                confidence += 0.16
            if is_large_model:
                confidence += 0.14
            if method_hint:
                confidence += 0.06
            confidence = min(0.95, confidence)
            if confidence + 1e-9 < min_confidence:
                continue

            evidence = list(api_evidence)
            evidence.extend(
                [
                    f"model={q.model or 'unknown'}",
                    f"terminal={terminal_name}",
                    f"multi_record_signals={multi_record_signals}",
                ]
            )
            if is_large_model:
                evidence.append("large_model=true")
            if method_hint:
                evidence.append("index_like_method=true")

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
                    evidence_signals=evidence,
                )
            )

        return findings

    def _is_controller_query(self, norm_path: str) -> bool:
        return "controllers/" in norm_path or "/controllers/" in norm_path or "controller" in norm_path

    def _is_api_route_file(self, file_path: str) -> bool:
        fp = (file_path or "").replace("\\", "/").lower()
        return fp in self._API_ROUTE_FILES or fp.endswith("/routes/api.php")

    def _collect_api_route_actions(self, facts: Facts) -> set[str]:
        actions: set[str] = set()
        for route in facts.routes or []:
            action = (route.action or "").strip()
            if "@" not in action:
                continue
            if self._is_api_route_file(route.file_path or "") or str(route.uri or "").startswith("api/"):
                actions.add(action.lower())
        return actions

    def _detect_api_context(self, file_path: str, method_name: str, api_route_actions: set[str]) -> tuple[bool, list[str]]:
        evidence: list[str] = []
        norm_path = (file_path or "").replace("\\", "/").lower()
        if "/http/controllers/api/" in norm_path:
            evidence.append("api_context=controller_path")

        class_name = Path(norm_path).stem
        if class_name and method_name:
            probe = f"{class_name}@{method_name}".lower()
            if any(action.endswith(probe) for action in api_route_actions):
                evidence.append("api_context=api_route_controller_match")

        return bool(evidence), evidence

    def _is_export_flow(self, norm_path: str, method_name: str) -> bool:
        payload = f"{norm_path}::{method_name}".lower()
        return any(token in payload for token in self._EXPORT_METHOD_HINTS)
