"""
Missing Index On Lookup Columns Rule

Detects migration lookup/reference columns that do not appear indexed.
"""

from __future__ import annotations

from collections import defaultdict
import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class MissingIndexOnLookupColumnsRule(Rule):
    id = "missing-index-on-lookup-columns"
    name = "Missing Index On Lookup Columns"
    description = "Detects migration lookup columns that are added without an index or unique constraint"
    category = Category.PERFORMANCE
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

    _LOOKUP_NAME_RE = re.compile(r"(?:_id|^email$|^slug$|^uuid$|^ulid$)", re.IGNORECASE)
    _LOOKUP_TYPES = {"foreignid", "foreignuuid", "foreignulid", "foreignidfor", "uuid", "ulid", "string", "unsignedbiginteger", "unsignedinteger"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        changes = getattr(facts, "migration_table_changes", []) or []
        if not changes:
            return []

        indexed_columns: dict[tuple[str, str], set[str]] = defaultdict(set)
        for definition in (getattr(facts, "migration_indexes", []) or []):
            key = (str(definition.file_path), str(definition.table_name).lower())
            for column in definition.columns or []:
                indexed_columns[key].add(str(column).lower())
        for foreign_key in (getattr(facts, "migration_foreign_keys", []) or []):
            key = (str(foreign_key.file_path), str(foreign_key.table_name).lower())
            for column in foreign_key.columns or []:
                indexed_columns[key].add(str(column).lower())

        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for change in changes:
            if str(change.operation or "").lower() != "add_column":
                continue
            column_name = str(change.column_name or "").lower()
            column_type = str(change.column_type or "").lower()
            if not self._is_lookup_candidate(column_name, column_type):
                continue

            key = (str(change.file_path), str(change.table_name).lower())
            if column_name in indexed_columns.get(key, set()):
                continue

            confidence = 0.82 if column_name.endswith("_id") else 0.74
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="Lookup column added without index",
                    file=change.file_path,
                    line_start=int(change.line_number or 1),
                    context=f"migration:{change.table_name}.{change.column_name}",
                    description=(
                        f"Migration adds lookup column `{change.column_name}` on `{change.table_name}` without an obvious index or unique constraint."
                    ),
                    why_it_matters=(
                        "Lookup columns are frequently used in joins and filters. Missing indexes can degrade query performance as data grows."
                    ),
                    suggested_fix="Add `->index()`, `->unique()`, or another appropriate index for the lookup column.",
                    confidence=confidence,
                    tags=["laravel", "migration", "database", "indexing", "performance"],
                    evidence_signals=[
                        "lookup_column=true",
                        "lookup_index_missing=true",
                        f"column_type={column_type or 'unknown'}",
                    ],
                )
            )

        return findings

    def _is_lookup_candidate(self, column_name: str, column_type: str) -> bool:
        if not column_name or column_name == "id":
            return False
        return bool(self._LOOKUP_NAME_RE.search(column_name)) and column_type in self._LOOKUP_TYPES
