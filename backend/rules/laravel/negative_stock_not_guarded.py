"""Negative stock not guarded rule."""

from __future__ import annotations

from analysis.dataflow import AnalysisContext, DataflowSink
from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics


class NegativeStockNotGuardedRule(Rule):
    id = "negative-stock-not-guarded"
    name = "Negative Stock Not Guarded"
    description = "Detects inventory decrements without floor validation"
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
        "Add floor validation before decrementing inventory. Example: "
        "if ($product->stock >= $qty) { $product->decrement('stock', $qty); } "
        "or use atomic decrement: Product::where('id', $id)->where('stock', '>=', $qty)"
        "->decrement('stock', $qty). Alternatively, enforce a database CHECK "
        "constraint or model mutator."
    )
    examples = {
        "bad": "$product->decrement('stock', $qty);",
        "good": "if ($product->stock >= $qty) {\n    $product->decrement('stock', $qty);\n}",
    }
    priority = 2
    group = "Architecture Integrity"
    applies_to = ["controller", "service", "job"]
    references = []
    related_rules = ["missing-inventory-lock-on-decrement", "transaction-required-for-multi-write"]
    false_positive_notes = (
        "May fire when floor validation is enforced upstream or by database constraints "
        "not visible in code. QueryException catches and max(0) mutators are suppressed."
    )
    detection_type = "ast"
    analysis_contract = "semantic"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "negative-stock"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for context in self.iter_analysis_contexts(facts):
            if self._skip_context(context):
                continue
            if context.has_query_exception_guard or context.has_floor_validation:
                continue
            for sink in context.domain_sinks("inventory"):
                if sink.field_name.lower() in context.mutator_protected_fields:
                    continue
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
        insufficient = context.has_insufficient_floor_guard
        trace_ids = [sink.trace_id] if sink.trace_id else []
        title = (
            "Inventory decrement with insufficient floor guard"
            if insufficient
            else "Inventory decrement without floor validation"
        )
        description = (
            f"Inventory field '{sink.field_name}' is decremented with only a > 0 "
            "check, but the decrement amount may exceed available stock."
            if insufficient
            else f"Inventory field '{sink.field_name}' is decremented without floor "
            "validation. The stock could go negative if the decrement amount exceeds "
            "available stock."
        )
        why = (
            "Insufficient floor validation:\n"
            "- stock > 0 passes even when stock=1 and qty=10\n"
            "- Results in negative stock\n"
            "- Must check stock >= qty, not stock > 0"
            if insufficient
            else "Without floor validation:\n"
            "- Stock can go negative\n"
            "- Overselling without detection\n"
            "- Corrupted inventory state\n"
            "- Must validate stock >= qty before decrementing"
        )
        return self.create_finding(
            title=title,
            context=f"{sink.pattern_type}:{sink.field_name}",
            file=context.file_path,
            line_start=sink.line,
            description=description,
            why_it_matters=why,
            suggested_fix=self.fix_suggestion,
            confidence=0.70 if insufficient else 0.75,
            tags=["laravel", "inventory", "validation", "negative-stock", "dataflow"],
            evidence_signals=[
                f"trace={sink.trace_id}",
                f"sink_field={sink.field_name}",
                f"sink_pattern={sink.pattern_type}",
                f"has_floor_validation={str(context.has_floor_validation).lower()}",
                f"has_query_exception_guard={str(context.has_query_exception_guard).lower()}",
            ],
            metadata={
                "analysis_contract": "semantic",
                "trace_quality": "trace-backed" if trace_ids else "pattern-only",
                "evidence_trace_ids": trace_ids,
                "analysis_context_file": context.file_path,
                "rule_decision": {
                    "has_inventory_sink": context.has_inventory_sink,
                    "has_floor_validation": context.has_floor_validation,
                    "has_query_exception_guard": context.has_query_exception_guard,
                    "sink_trace_id": sink.trace_id,
                },
            },
        )
