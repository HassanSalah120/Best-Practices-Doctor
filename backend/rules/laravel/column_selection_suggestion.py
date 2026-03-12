"""
Column Selection Suggestion Rule

Suggests using explicit column selection instead of SELECT * for performance optimization.
"""

from __future__ import annotations

from schemas.facts import Facts, QueryUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class ColumnSelectionSuggestionRule(Rule):
    id = "column-selection-suggestion"
    name = "Column Selection Suggestion"
    description = "Suggests explicit column selection for better query performance"
    category = Category.PERFORMANCE
    default_severity = Severity.LOW
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    # Models that typically have many columns (benefit most from column selection)
    _LARGE_MODELS = {
        "appointment",
        "patient",
        "user",
        "invoice",
        "claim",
        "order",
        "product",
        "customer",
        "transaction",
        "encounter",
        "medical_record",
        "prescription",
    }

    # Terminal methods that return multiple records
    _MULTI_RECORD_TERMINALS = {"get", "paginate", "chunk", "each", "cursor"}

    # Methods that imply column selection is already done
    _COLUMN_SELECTION_METHODS = {"select", "addselect", "selectraw", "value", "pluck"}

    # Methods that fetch single record (column selection less important)
    _SINGLE_RECORD_TERMINALS = {"first", "find", "findorfail", "firstorfail", "sole"}

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/vendor/",
        "/database/migrations/",
        "/database/factories/",
        "/database/seeders/",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for q in facts.queries:
            # Skip non-SELECT queries
            if q.query_type != "select":
                continue

            # Skip allowlisted paths
            norm_path = (q.file_path or "").replace("\\", "/").lower()
            if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
                continue

            # Check if query already has column selection
            chain_lower = (q.method_chain or "").lower()
            if any(method in chain_lower for method in self._COLUMN_SELECTION_METHODS):
                continue

            # Check if query has eager loading (already optimized for relations)
            if q.has_eager_loading:
                continue

            # Parse chain to check terminal method
            chain_parts = [p.strip() for p in chain_lower.split("->") if p.strip()]
            if not chain_parts:
                continue

            terminal = chain_parts[-1] if chain_parts else ""

            # Skip single-record queries (less benefit from column selection)
            if terminal in self._SINGLE_RECORD_TERMINALS:
                continue

            # Only suggest for multi-record queries
            if terminal not in self._MULTI_RECORD_TERMINALS:
                continue

            # Check if model is known to be large
            model_lower = (q.model or "").lower().replace("\\", "")
            is_large_model = any(large in model_lower for large in self._LARGE_MODELS)

            # Adjust confidence based on model size
            confidence = 0.75 if is_large_model else 0.55

            findings.append(
                self.create_finding(
                    title="Consider explicit column selection",
                    context=f"{q.model}:{q.method_chain}",
                    file=q.file_path,
                    line_start=q.line_number,
                    description=(
                        f"Query on `{q.model or 'Model'}` fetches all columns (`SELECT *`). "
                        "Consider specifying only the columns you need for better performance."
                    ),
                    why_it_matters=(
                        "Fetching all columns when you only need a few:\n"
                        "- Increases memory usage in PHP and database\n"
                        "- Increases network transfer time\n"
                        "- May expose sensitive columns unintentionally\n"
                        "- Slows down queries on large tables with many columns"
                    ),
                    suggested_fix=(
                        "1. Specify columns in the query:\n"
                        "   Model::select(['id', 'name', 'email'])->get();\n\n"
                        "2. Specify columns in eager loading:\n"
                        "   Model::with(['relation:id,name'])->get();\n\n"
                        "3. Use value() for single column:\n"
                        "   Model::where('id', 1)->value('name');\n\n"
                        "4. Use pluck() for key-value pairs:\n"
                        "   Model::pluck('name', 'id');"
                    ),
                    code_example=(
                        "// Before (fetches all columns)\n"
                        "$patients = Patient::where('clinic_id', $id)->get();\n\n"
                        "// After (fetches only needed columns)\n"
                        "$patients = Patient::select(['id', 'first_name', 'last_name'])\n"
                        "    ->where('clinic_id', $id)\n"
                        "    ->get();\n\n"
                        "// With eager loading column selection\n"
                        "$patients = Patient::with(['doctor:id,name'])\n"
                        "    ->select(['id', 'first_name', 'doctor_id'])\n"
                        "    ->get();"
                    ),
                    confidence=confidence,
                    tags=["performance", "database", "eloquent", "optimization"],
                )
            )

        return findings
