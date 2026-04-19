"""
Destructive Migration Without Safety Guard Rule

Detects destructive migration operations in the up() path that do not show
basic schema guards.
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class DestructiveMigrationWithoutSafetyGuardRule(Rule):
    id = "destructive-migration-without-safety-guard"
    name = "Destructive Migration Without Safety Guard"
    description = "Detects destructive migration operations without schema/table existence checks"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _DESTRUCTIVE_OPS = {"drop_column", "rename_column", "drop_table", "rename_table"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.0) or 0.0)

        for change in (getattr(facts, "migration_table_changes", []) or []):
            operation = str(change.operation or "").lower()
            if operation not in self._DESTRUCTIVE_OPS:
                continue
            if list(change.guard_signals or []):
                continue

            confidence = 0.9 if operation in {"drop_table", "drop_column"} else 0.84
            if confidence + 1e-9 < min_confidence:
                continue

            findings.append(
                self.create_finding(
                    title="Destructive migration runs without safety guard",
                    file=change.file_path,
                    line_start=int(change.line_number or 1),
                    context=f"migration:{change.table_name}:{operation}",
                    description=(
                        f"Migration performs `{operation}` on `{change.table_name}` without a visible schema/table existence guard in the forward migration path."
                    ),
                    why_it_matters=(
                        "Destructive schema changes are harder to roll out safely across environments when the migration assumes the target already exists."
                    ),
                    suggested_fix=(
                        "Wrap destructive operations in `Schema::hasTable(...)` / `Schema::hasColumn(...)` checks or another explicit safety guard before mutating the schema."
                    ),
                    confidence=confidence,
                    tags=["laravel", "migration", "database", "schema-safety"],
                    evidence_signals=[
                        "destructive_migration=true",
                        "migration_safety_guard_missing=true",
                        f"operation={operation}",
                    ],
                )
            )

        return findings
