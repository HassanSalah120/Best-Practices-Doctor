"""
Missing Foreign Key In Migration Rule

Detects Laravel migration columns that look like foreign-key references but
do not define a foreign key in the same migration.
"""

from __future__ import annotations

from collections import defaultdict

from schemas.facts import Facts, MigrationTableChange
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class MissingForeignKeyInMigrationRule(Rule):
    id = "missing-foreign-key-in-migration"
    name = "Missing Foreign Key In Migration"
    description = "Detects migration reference columns that are added without a foreign key definition"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _FOREIGNISH_TYPES = {
        "foreignid",
        "foreignuuid",
        "foreignulid",
        "foreignidfor",
        "unsignedbiginteger",
        "unsignedinteger",
        "unsignedsmallinteger",
        "unsignedtinyinteger",
        "uuid",
        "ulid",
    }
    _IGNORE_PREFIXES = ("external_", "provider_", "legacy_", "source_", "remote_")
    _IGNORE_COLUMNS = {"id"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        changes = getattr(facts, "migration_table_changes", []) or []
        foreign_keys = getattr(facts, "migration_foreign_keys", []) or []
        if not changes:
            return []

        foreign_key_columns: dict[tuple[str, str], set[str]] = defaultdict(set)
        columns_by_table: dict[tuple[str, str], set[str]] = defaultdict(set)

        for foreign_key in foreign_keys:
            key = (str(foreign_key.file_path), str(foreign_key.table_name).lower())
            for column in foreign_key.columns or []:
                foreign_key_columns[key].add(str(column).lower())

        for change in changes:
            if change.column_name:
                key = (str(change.file_path), str(change.table_name).lower())
                columns_by_table[key].add(str(change.column_name).lower())

        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for change in changes:
            if str(change.operation or "").lower() != "add_column":
                continue
            column_name = str(change.column_name or "").lower()
            column_type = str(change.column_type or "").lower()
            if not self._is_candidate(column_name, column_type):
                continue

            key = (str(change.file_path), str(change.table_name).lower())
            if column_name in foreign_key_columns.get(key, set()):
                continue
            if self._is_polymorphic_pair(column_name, columns_by_table.get(key, set())):
                continue

            confidence = 0.9 if column_type in {"foreignid", "foreignuuid", "foreignulid", "foreignidfor"} else 0.8
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="Migration adds reference column without foreign key",
                    file=change.file_path,
                    line_start=int(change.line_number or 1),
                    context=f"migration:{change.table_name}.{change.column_name}",
                    description=(
                        f"Migration adds `{change.column_name}` on `{change.table_name}` but does not define a matching foreign key."
                    ),
                    why_it_matters=(
                        "Foreign keys protect referential integrity and make accidental orphaned records less likely."
                    ),
                    suggested_fix=(
                        "Use `foreignId(...)->constrained()` or add an explicit `$table->foreign(...)->references(...)->on(...)` definition."
                    ),
                    confidence=confidence,
                    tags=["laravel", "migration", "database", "foreign-key"],
                    evidence_signals=[
                        "migration_reference_column=true",
                        "foreign_key_missing=true",
                        f"column_type={column_type or 'unknown'}",
                    ],
                )
            )

        return findings

    def _is_candidate(self, column_name: str, column_type: str) -> bool:
        if not column_name or column_name in self._IGNORE_COLUMNS:
            return False
        if any(column_name.startswith(prefix) for prefix in self._IGNORE_PREFIXES):
            return False
        if column_type in {"uuid", "ulid"} and not column_name.endswith("_id"):
            return False
        return column_name.endswith("_id") and column_type in self._FOREIGNISH_TYPES

    def _is_polymorphic_pair(self, column_name: str, table_columns: set[str]) -> bool:
        if not column_name.endswith("_id"):
            return False
        prefix = column_name[:-3]
        return f"{prefix}_type" in table_columns
