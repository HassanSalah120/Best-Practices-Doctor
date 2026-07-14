"""
Composite Index On Tenant Models Rule

Detects multi-tenant project models that appear to have a tenant/clinic column
but lack a composite index on (tenant_id/clinic_id, created_at) or similar
common query patterns.

In multi-tenant SaaS, most queries filter by tenant + timestamp. Without a
composite index, the database scans all tenant rows before applying the
timestamp filter.

ADVISORY — LOW confidence. Some projects intentionally partition data differently.
"""

from __future__ import annotations

import re
from collections import defaultdict

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class CompositeIndexOnTenantModelsRule(Rule):
    id = "composite-index-on-tenant-models"
    name = "Composite Index On Tenant Models"
    description = "Detects tenant-scoped models missing composite (tenant_id, created_at) indexes"
    category = Category.DATA_INTEGRITY
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    severity_weight = 2
    confidence = "low"
    fix_suggestion = (
        "Add a composite index for common tenant-scoped queries:\n"
        "```php\n"
        "Schema::table('patients', function (Blueprint $table) {\n"
        "    $table->index(['clinic_id', 'created_at']);\n"
        "});\n"
        "```\n"
        "For high-volume tables, consider also `['clinic_id', 'updated_at']` "
        "if updated-at queries are common."
    )
    examples = {}
    priority = 3
    group = "Performance"
    applies_to = ["migration", "model"]
    references = ["Laravel docs: Migration Indexes", "MySQL: Composite Indexes"]
    related_rules = ["missing-index-on-lookup-columns", "tenant-scope-enforcement"]
    false_positive_notes = (
        "Projects with low table volume, dedicated tenant databases, or that "
        "partition by tenant at the database level may not need composite indexes. "
        "Review query patterns before adding indexes."
    )
    detection_type = "ast"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "performance", "concern": "composite-index"}

    _TENANT_COLUMNS = ("clinic_id", "tenant_id", "workspace_id", "organization_id", "account_id")
    _TIMESTAMP_COLUMNS = ("created_at", "updated_at")

    _EXCLUDED_TABLES = {
        "migrations", "failed_jobs", "password_reset_tokens",
        "personal_access_tokens", "sessions", "cache", "cache_locks",
        "job_batches", "telescope_entries", "telescope_monitoring",
    }

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        project_context = getattr(facts, "project_context", None)
        tenant_mode = str(getattr(project_context, "tenant_mode", "unknown") or "unknown").lower()
        if tenant_mode == "non_tenant":
            return []

        changes = getattr(facts, "migration_table_changes", []) or []
        indexes = getattr(facts, "migration_indexes", []) or []

        if not changes and not indexes:
            return []

        tenant_tables: set[str] = set()
        for change in changes:
            if self._has_tenant_column(change):
                tenant_tables.add(change.table_name.lower())

        if not tenant_tables:
            return []

        indexed_tenant_timestamp: set[str] = set()
        for idx in indexes:
            table = (idx.table_name or "").lower()
            if table not in tenant_tables:
                continue
            columns = [c.lower() for c in (idx.columns or [])]
            if any(tc in columns for tc in self._TENANT_COLUMNS) and any(ts in columns for ts in self._TIMESTAMP_COLUMNS):
                indexed_tenant_timestamp.add(table)

        missing = tenant_tables - indexed_tenant_timestamp - self._EXCLUDED_TABLES
        if not missing:
            return []

        sorted_missing = sorted(missing)[:8]
        tables_str = ", ".join(sorted_missing)

        return [
            self.create_finding(
                title="Tenant-scoped tables missing composite index",
                context=f"tables: {tables_str}",
                file=changes[0].file_path if changes else "",
                line_start=1,
                description=(
                    f"{len(missing)} tenant-scoped table(s) have a `clinic_id`/`tenant_id` column "
                    f"but no composite index including a timestamp column "
                    f"(`(tenant_id, created_at)` or similar). "
                    f"Tables: {tables_str}."
                ),
                why_it_matters=(
                    "Tenant-scoped queries typically filter by tenant AND order by timestamp. "
                    "Without a composite index, the database scans all rows for the tenant "
                    "before sorting, causing slow queries as data grows."
                ),
                suggested_fix=self.fix_suggestion,
                confidence=0.55,
                tags=["laravel", "database", "performance", "indexing", "multi-tenant"],
                evidence_signals=[
                    f"tenant_tables_without_composite_index={len(missing)}",
                    f"tables={tables_str}",
                    "composite_index_missing=true",
                ],
            ),
        ]

    def _has_tenant_column(self, change) -> bool:
        col = str(getattr(change, "column_name", "") or "").lower()
        return any(tc in col for tc in self._TENANT_COLUMNS)
