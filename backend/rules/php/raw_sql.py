"""
Raw SQL Rule

Detects raw SQL usage via DB::select/statement/raw (risk: SQL injection, portability, and readability).
Uses QueryUsage facts extracted from AST (Tree-sitter primary).
"""
from schemas.facts import Facts, QueryUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class RawSqlRule(Rule):
    id = "raw-sql"
    name = "Raw SQL Usage"
    description = "Detects DB::select/statement/raw usage (prefer query builder with bindings)"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types: list[str] = []  # all

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for q in facts.queries:
            chain = (q.method_chain or "").lower()
            is_db = q.model is None and chain.split("->", 1)[0] in {"table", "select", "statement", "raw"}
            if not is_db and not q.is_raw:
                continue

            # Only flag truly raw-ish DB calls; query builder `DB::table()` alone isn't raw SQL.
            if chain.startswith("table") and not q.is_raw:
                continue

            ctx = f"{q.method_name}:{q.model or 'DB'}:{q.method_chain or ''}"
            findings.append(
                self.create_finding(
                    title="Avoid raw SQL; prefer query builder with bindings",
                    context=ctx,
                    file=q.file_path,
                    line_start=q.line_number,
                    description=(
                        f"Detected raw SQL usage: `{q.model or 'DB'}::{q.method_chain}`. "
                        "Raw SQL increases injection risk and reduces portability."
                    ),
                    why_it_matters=(
                        "Raw SQL can introduce SQL injection vulnerabilities if values are interpolated. "
                        "The query builder/ORM encourages parameter binding, composability, and clearer intent."
                    ),
                    suggested_fix=(
                        "1. Use Eloquent/query builder (`Model::query()->where(...)->get()`)\n"
                        "2. If raw SQL is necessary, use parameter binding (`DB::select($sql, [$bindings])`)\n"
                        "3. Centralize raw SQL in a repository/query object and add tests"
                    ),
                    tags=["security", "sql", "injection", "database"],
                )
            )

        return findings

