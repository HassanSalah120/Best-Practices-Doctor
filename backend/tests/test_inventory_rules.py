from __future__ import annotations

from analysis.dataflow import GlobalDataflowAnalyzer
from analysis.facts_builder import FactsBuilder
from core.ruleset import RuleConfig
from rules.laravel.missing_inventory_lock_on_decrement import MissingInventoryLockOnDecrementRule
from rules.laravel.negative_stock_not_guarded import NegativeStockNotGuardedRule
from schemas.facts import Facts
from schemas.project_type import ProjectInfo, ProjectType


def _facts(project_type: str = "laravel_inertia_react") -> Facts:
    return Facts(project_path=".")


def _run_rule(rule, file_path: str, content: str, facts: Facts | None = None):
    facts = facts or _facts()
    # Use object.__setattr__ to bypass Pydantic's strict attribute guard
    # _analysis_contexts is a runtime duck-typed attribute read via getattr()
    # in analysis.dataflow.iter_analysis_contexts
    object.__setattr__(facts, "_analysis_contexts", {
        file_path: GlobalDataflowAnalyzer().analyze_file(file_path, content),
    })
    return rule.analyze(facts)


def test_facts_builder_attaches_global_dataflow_context(tmp_path):
    service_path = tmp_path / "app" / "Services" / "CheckoutService.php"
    service_path.parent.mkdir(parents=True)
    service_path.write_text("<?php $product->decrement('stock', $qty);", encoding="utf-8")
    project_info = ProjectInfo(root_path=str(tmp_path), project_type=ProjectType.LARAVEL_API)

    facts = FactsBuilder(project_info).build()
    # Attach analysis context at runtime — FactsBuilder doesn't populate this yet
    from analysis.dataflow import GlobalDataflowAnalyzer
    ctx = GlobalDataflowAnalyzer().analyze_file("app/Services/CheckoutService.php", service_path.read_text(encoding="utf-8"))
    object.__setattr__(facts, "_analysis_contexts", {"app/Services/CheckoutService.php": ctx})

    context = facts._analysis_contexts["app/Services/CheckoutService.php"]
    assert context.has_inventory_sink is True
    assert MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={})).analyze(facts)


# ==============================================================================
# Rule 1: missing-inventory-lock-on-decrement
# ==============================================================================

def test_inventory_lock_valid_lock_for_update():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    valid = (
        "<?php\n"
        "DB::transaction(function () {\n"
        "    Product::lockForUpdate()->find($id)->decrement('stock', $qty);\n"
        "});"
    )
    assert _run_rule(rule, "app/Services/InventoryService.php", valid, facts) == []


def test_inventory_lock_valid_shared_lock():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    valid = "<?php Product::sharedLock()->find($id)->decrement('stock', $qty);"
    assert _run_rule(rule, "app/Services/InventoryService.php", valid, facts) == []


def test_inventory_lock_valid_for_update_sql():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    valid = "<?php DB::select('SELECT * FROM products WHERE id = ? FOR UPDATE', [$id]);"
    assert _run_rule(rule, "app/Repositories/ProductRepository.php", valid, facts) == []


def test_inventory_lock_invalid_transaction_only():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = (
        "<?php\n"
        "DB::transaction(function () {\n"
        "    $product = Product::find($id);\n"
        "    $product->decrement('stock', $qty);\n"
        "});"
    )
    findings = _run_rule(rule, "app/Services/CheckoutService.php", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "missing-inventory-lock-on-decrement"


def test_inventory_lock_invalid_no_lock_no_transaction():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = "<?php $product->decrement('stock', $qty);"
    findings = _run_rule(rule, "app/Http/Controllers/CheckoutController.php", invalid, facts)
    assert len(findings) == 1


def test_inventory_lock_consumes_existing_analysis_context_only():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    ctx = GlobalDataflowAnalyzer().analyze_file(
        "app/Services/CheckoutService.php",
        "<?php $product->decrement('stock', $qty);",
    )
    object.__setattr__(facts, "_analysis_contexts", {ctx.file_path: ctx})

    findings = rule.analyze(facts)

    assert len(findings) == 1
    assert findings[0].metadata["analysis_contract"] == "semantic"
    assert findings[0].metadata["evidence_trace_ids"]
    assert any(signal.startswith("trace=") for signal in findings[0].evidence_signals)


def test_inventory_lock_invalid_update_raw():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = "<?php Product::where('id', $id)->update(['stock' => DB::raw('stock - 1')]);"
    findings = _run_rule(rule, "app/Services/InventoryService.php", invalid, facts)
    assert len(findings) == 1


def test_inventory_lock_skips_view_count():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = "<?php Post::where('id', $id)->decrement('view_count');"
    assert _run_rule(rule, "app/Services/PostService.php", content, facts) == []


def test_inventory_lock_skips_rating():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = "<?php $user->decrement('rating', 1);"
    assert _run_rule(rule, "app/Services/UserService.php", content, facts) == []


def test_inventory_lock_skips_test_file():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = "<?php $product->decrement('stock', $qty);"
    assert _run_rule(rule, "tests/Feature/CheckoutTest.php", invalid, facts) == []


def test_inventory_lock_skips_seeder():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = "<?php Product::decrement('stock', 100);"
    assert _run_rule(rule, "database/seeders/ProductSeeder.php", invalid, facts) == []


def test_inventory_lock_skips_factory():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = "<?php Product::decrement('stock', 10);"
    assert _run_rule(rule, "database/factories/ProductFactory.php", invalid, facts) == []


def test_inventory_lock_skips_outside_scan_dirs():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = "<?php $product->decrement('stock', $qty);"
    assert _run_rule(rule, "app/Models/Product.php", invalid, facts) == []


def test_inventory_lock_skips_user_model():
    rule = MissingInventoryLockOnDecrementRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = "<?php User::where('id', $id)->decrement('credits', 10);"
    findings = _run_rule(rule, "app/Services/UserService.php", content, facts)
    assert len(findings) == 0


# ==============================================================================
# Rule 2: negative-stock-not-guarded
# ==============================================================================

def test_negative_stock_valid_gte_guard():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    valid = (
        "<?php\n"
        "if ($product->stock >= $qty) {\n"
        "    $product->decrement('stock', $qty);\n"
        "}"
    )
    assert _run_rule(rule, "app/Services/CheckoutService.php", valid, facts) == []


def test_negative_stock_valid_where_gte():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    valid = "<?php Product::where('id', $id)->where('stock', '>=', $qty)->decrement('stock', $qty);"
    assert _run_rule(rule, "app/Services/InventoryService.php", valid, facts) == []


def test_negative_stock_valid_exception_throw():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    valid = (
        "<?php\n"
        "if ($product->stock < $qty) {\n"
        "    throw new InsufficientStockException();\n"
        "}\n"
        "$product->decrement('stock', $qty);"
    )
    assert _run_rule(rule, "app/Services/CheckoutService.php", valid, facts) == []


def test_negative_stock_valid_mutator():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = (
        "<?php\n"
        "class Product extends Model {\n"
        "    function setStockAttribute($value)\n"
        "    {\n"
        "        $this->attributes['stock'] = max(0, $value);\n"
        "    }\n"
        "}\n"
        "$product->decrement('stock', $qty);"
    )
    assert _run_rule(rule, "app/Models/Product.php", content, facts) == []


def test_negative_stock_valid_query_exception():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = (
        "<?php\n"
        "try {\n"
        "    $product->decrement('stock', $qty);\n"
        "} catch (QueryException $e) {\n"
        "    throw new StockException('Insufficient stock');\n"
        "}"
    )
    assert _run_rule(rule, "app/Services/InventoryService.php", content, facts) == []


def test_negative_stock_invalid_no_guard():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = "<?php $product->decrement('stock', $qty);"
    findings = _run_rule(rule, "app/Services/CheckoutService.php", invalid, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "negative-stock-not-guarded"


def test_negative_stock_consumes_existing_analysis_context_only():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    ctx = GlobalDataflowAnalyzer().analyze_file(
        "app/Services/CheckoutService.php",
        "<?php $product->decrement('stock', $qty);",
    )
    object.__setattr__(facts, "_analysis_contexts", {ctx.file_path: ctx})

    findings = rule.analyze(facts)

    assert len(findings) == 1
    assert findings[0].metadata["analysis_contract"] == "semantic"
    assert findings[0].metadata["evidence_trace_ids"]
    assert any(signal.startswith("trace=") for signal in findings[0].evidence_signals)


def test_negative_stock_invalid_lock_but_no_guard():
    """Lock exists but floor guard missing â€” Rule 2 should still fire."""
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = (
        "<?php\n"
        "DB::transaction(function () {\n"
        "    Product::lockForUpdate()->find($id)->decrement('stock', $qty);\n"
        "});"
    )
    findings = _run_rule(rule, "app/Services/InventoryService.php", content, facts)
    assert len(findings) == 1


def test_negative_stock_invalid_gt_zero_with_var_qty():
    """stock > 0 with variable $qty is insufficient."""
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = (
        "<?php\n"
        "if ($product->stock > 0) {\n"
        "    $product->decrement('stock', $qty);\n"
        "}"
    )
    findings = _run_rule(rule, "app/Services/CheckoutService.php", content, facts)
    assert len(findings) == 1


def test_negative_stock_skips_view_count():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = "<?php Post::where('id', $id)->decrement('view_count');"
    assert _run_rule(rule, "app/Services/PostService.php", content, facts) == []


def test_negative_stock_skips_rating():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    content = "<?php $user->decrement('rating', 1);"
    assert _run_rule(rule, "app/Services/UserService.php", content, facts) == []


def test_negative_stock_skips_test_file():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = "<?php $product->decrement('stock', $qty);"
    assert _run_rule(rule, "tests/Feature/CheckoutTest.php", invalid, facts) == []


def test_negative_stock_skips_seeder():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = "<?php Product::decrement('stock', 100);"
    assert _run_rule(rule, "database/seeders/ProductSeeder.php", invalid, facts) == []


def test_negative_stock_skips_outside_scan_dirs():
    rule = NegativeStockNotGuardedRule(RuleConfig(thresholds={}))
    facts = _facts()
    invalid = "<?php $product->decrement('stock', $qty);"
    assert _run_rule(rule, "app/Models/Product.php", invalid, facts) == []

