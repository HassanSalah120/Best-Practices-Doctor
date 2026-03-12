"""
Transaction Required For Multi Write Rule

Detects methods that perform multiple write queries without a transaction boundary.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class TransactionRequiredForMultiWriteRule(Rule):
    id = "transaction-required-for-multi-write"
    name = "Transaction Required For Multi Write"
    description = "Detects methods with multiple writes that are not wrapped in a DB transaction"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _WRITE_TOKENS = {
        "create",
        "upsert",
        "insert",
        "update",
        "delete",
        "save",
        "createmany",
        "createquietly",
        "sync",
        "attach",
        "detach",
        "increment",
        "decrement",
    }
    _TX_PATTERNS = [
        re.compile(r"\bDB::transaction\s*\(", re.IGNORECASE),
        re.compile(r"->\s*transaction\s*\(", re.IGNORECASE),
        re.compile(r"\bbeginTransaction\s*\(", re.IGNORECASE),
        re.compile(r"\bcommit\s*\(", re.IGNORECASE),
        re.compile(r"\brollBack\s*\(", re.IGNORECASE),
    ]

    # File paths that define routes/config, not actual DB-writing logic.
    _IGNORED_PATH_FRAGMENTS = [
        "RouteRegistrars/",
        "RouteRegistrar",
        "app/Providers/",
        "routes/",
        "database/seeders/",
        "database/factories/",
    ]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_writes = int(self.get_threshold("min_write_calls", 2) or 2)

        queries_by_method: dict[tuple[str, str], list] = {}
        for q in facts.queries:
            queries_by_method.setdefault((q.file_path, q.method_name), []).append(q)

        for method in facts.methods:
            if method.name.startswith("__"):
                continue

            # Skip files that define routes/config — they don't write to DB.
            fp = (method.file_path or "").replace("\\", "/")
            if any(frag in fp for frag in self._IGNORED_PATH_FRAGMENTS):
                continue


            qs = queries_by_method.get((method.file_path, method.name), [])
            if not qs:
                continue

            write_qs = [q for q in qs if self._is_write_chain(q.method_chain or "")]
            if len(write_qs) < min_writes:
                continue

            if self._is_transactional(method.call_sites or []):
                continue

            sample = ", ".join(sorted({q.method_chain for q in write_qs if q.method_chain})[:3])
            if len(write_qs) > 3:
                sample += f", +{len(write_qs) - 3} more"

            confidence = min(0.95, 0.6 + (0.08 * min(len(write_qs), 4)))

            findings.append(
                self.create_finding(
                    title="Multiple writes without explicit DB transaction",
                    context=method.method_fqn,
                    file=method.file_path,
                    line_start=method.line_start,
                    line_end=method.line_end,
                    description=(
                        f"Method `{method.method_fqn}` appears to execute {len(write_qs)} write operations "
                        "without a detected transaction boundary. "
                        f"Examples: {sample or 'write queries'}."
                    ),
                    why_it_matters=(
                        "Without a transaction, partial writes can persist when an exception happens mid-flow, "
                        "causing inconsistent state and data integrity issues."
                    ),
                    suggested_fix=(
                        "Wrap related writes in `DB::transaction(...)`.\n"
                        "For long workflows, isolate transaction-critical writes from side effects "
                        "(events, notifications, external API calls)."
                    ),
                    tags=["laravel", "transactions", "consistency", "architecture"],
                    confidence=confidence,
                )
            )

        return findings

    def _is_write_chain(self, chain: str) -> bool:
        tokens = [t.strip().lower() for t in (chain or "").split("->") if t.strip()]
        return any(t in self._WRITE_TOKENS for t in tokens)

    def _is_transactional(self, call_sites: list[str]) -> bool:
        body = "\n".join(call_sites or [])
        return any(p.search(body) for p in self._TX_PATTERNS)
