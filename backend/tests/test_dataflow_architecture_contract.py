from __future__ import annotations

from pathlib import Path


INVENTORY_RULE_FILES = [
    Path("rules/laravel/missing_inventory_lock_on_decrement.py"),
    Path("rules/laravel/negative_stock_not_guarded.py"),
]

FORBIDDEN_RULE_PATTERNS = [
    "import re",
    "from re import",
    "analyze_regex",
    "read_text(",
    "open(",
    "inventory_sinks",
    "find_decrement_candidates(",
    "has_lock_protection(",
    "has_floor_guard(",
    "has_query_exception_guard(",
    "has_mutator_protection(",
]


def test_inventory_business_rules_consume_generic_analysis_context():
    root = Path(__file__).resolve().parents[1]

    for rel_path in INVENTORY_RULE_FILES:
        text = (root / rel_path).read_text(encoding="utf-8")

        assert "iter_analysis_contexts" in text
        assert 'domain_sinks("inventory")' in text
        for pattern in FORBIDDEN_RULE_PATTERNS:
            assert pattern not in text, f"{rel_path} must not use rule-local analysis: {pattern}"


def test_analysis_context_exposes_domain_neutral_ir_surface():
    root = Path(__file__).resolve().parents[1]
    text = (root / "analysis/dataflow.py").read_text(encoding="utf-8")

    assert "class DataflowSource" in text
    assert "class DataflowSink" in text
    assert "class FrameworkSignal" in text
    assert "class CallEdge" in text
    assert "sources:" in text
    assert "sinks:" in text
    assert "framework_signals:" in text
    assert "call_edges:" in text
