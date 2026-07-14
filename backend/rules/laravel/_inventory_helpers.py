"""Compatibility imports for inventory dataflow helpers.

Inventory semantics live in analysis.dataflow. Keep this module as a thin
bridge for older imports while rules move to the global analysis layer.
"""

from analysis.dataflow import (
    DEFAULT_INVENTORY_FIELD_NAMES,
    INVENTORY_SKIP_FIELDS,
    AnalysisContext,
    DataflowSink,
    DataflowSource,
    EvidenceTrace,
    FrameworkSignal,
    GlobalDataflowAnalyzer,
    GuardCondition,
    InventorySink,
    VariableDefinition,
    find_decrement_candidates,
    has_floor_guard,
    has_lock_protection,
    has_mutator_protection,
    has_query_exception_guard,
    has_transaction_protection,
    is_inventory_field,
    is_non_inventory_model,
    is_scan_target,
    is_skip_class,
    is_skip_file,
    iter_analysis_contexts,
)

__all__ = [
    "DEFAULT_INVENTORY_FIELD_NAMES",
    "INVENTORY_SKIP_FIELDS",
    "AnalysisContext",
    "DataflowSink",
    "DataflowSource",
    "EvidenceTrace",
    "FrameworkSignal",
    "GlobalDataflowAnalyzer",
    "GuardCondition",
    "InventorySink",
    "VariableDefinition",
    "find_decrement_candidates",
    "has_floor_guard",
    "has_lock_protection",
    "has_mutator_protection",
    "has_query_exception_guard",
    "has_transaction_protection",
    "is_inventory_field",
    "is_non_inventory_model",
    "is_scan_target",
    "is_skip_class",
    "is_skip_file",
    "iter_analysis_contexts",
]
