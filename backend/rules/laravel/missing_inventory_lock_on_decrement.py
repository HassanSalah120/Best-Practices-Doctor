"""Missing inventory lock on decrement rule."""

from __future__ import annotations

from analysis.dataflow import AnalysisContext, DataflowSink
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class MissingInventoryLockOnDecrementRule(Rule):
    id = "missing-inventory-lock-on-decrement"
    name = "Missing Inventory Lock On Decrement"
    description = "Detects inventory decrements without pessimistic locking"
    category = Category.DATA_INTEGRITY
    default_severity = Severity.HIGH
    type = "ast"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    regex_file_extensions = [".php"]

    severity_weight = 8
    confidence = "medium"
    fix_suggestion = (
        "Use lockForUpdate() before reading and decrementing inventory. "
        "Example: Product::lockForUpdate()->find($id)->decrement('stock', $qty). "
        "A DB::transaction() alone does NOT prevent concurrent read races; only "
        "pessimistic locking (SELECT FOR UPDATE) prevents two requests from "
        "reading the same stock value simultaneously."
    )
    examples = {
        "bad": (
            "DB::transaction(function () {\n"
            "    $product = Product::find($id);\n"
            "    $product->decrement('stock', $qty);\n"
            "});"
        ),
        "good": (
            "DB::transaction(function () {\n"
            "    Product::lockForUpdate()->find($id)->decrement('stock', $qty);\n"
            "});"
        ),
    }
    priority = 2
    group = "Architecture Integrity"
    applies_to = ["controller", "service", "job"]
    references = []
    related_rules = ["negative-stock-not-guarded", "transaction-required-for-multi-write"]
    false_positive_notes = (
        "May fire on methods protected by database constraints, advisory locks, or "
        "external reservation systems not visible in code."
    )
    detection_type = "ast"
    analysis_contract = "semantic"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "inventory-lock"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for context in self.iter_analysis_contexts(facts):
            if self._skip_context(context) or context.has_lock:
                continue
            for sink in context.domain_sinks("inventory"):
                findings.append(self._finding_for_sink(context, sink))
        return findings

    def _skip_context(self, context: AnalysisContext) -> bool:
        return (
            not context.is_scan_target
            or context.is_skip_file
            or context.is_skip_class
            or context.is_non_inventory_only
            or not context.has_inventory_sink
        )

    def _finding_for_sink(self, context: AnalysisContext, sink: DataflowSink) -> Finding:
        trace_ids = [sink.trace_id] if sink.trace_id else []
        return self.create_finding(
            title="Inventory decrement without pessimistic lock",
            context=f"{sink.pattern_type}:{sink.field_name}",
            file=context.file_path,
            line_start=sink.line,
            description=(
                f"Inventory field '{sink.field_name}' is decremented without "
                "pessimistic locking (lockForUpdate/SELECT FOR UPDATE). Two "
                "concurrent requests can read the same stock value, both pass "
                "validation, and both decrement, causing overselling or negative stock."
            ),
            why_it_matters=(
                "Without row-level locking:\n"
                "- Race condition: concurrent requests read identical stock values\n"
                "- Both requests pass stock >= qty checks\n"
                "- Both decrement, resulting in negative stock\n"
                "- Overselling: more items sold than available\n"
                "- DB::transaction() alone does NOT prevent this; it only ensures "
                "atomicity, not isolation of reads\n"
                "- Only lockForUpdate() or SELECT FOR UPDATE prevents concurrent reads "
                "of the same row"
            ),
            suggested_fix=self.fix_suggestion,
            confidence=0.75,
            tags=["laravel", "inventory", "concurrency", "race-condition", "dataflow"],
            evidence_signals=[
                f"trace={sink.trace_id}",
                f"sink_field={sink.field_name}",
                f"sink_pattern={sink.pattern_type}",
                f"has_lock={str(context.has_lock).lower()}",
                f"has_transaction={str(context.has_transaction).lower()}",
            ],
            metadata={
                "analysis_contract": "semantic",
                "trace_quality": "trace-backed" if trace_ids else "pattern-only",
                "evidence_trace_ids": trace_ids,
                "analysis_context_file": context.file_path,
                "rule_decision": {
                    "has_inventory_sink": context.has_inventory_sink,
                    "has_lock": context.has_lock,
                    "sink_trace_id": sink.trace_id,
                },
            },
        )
