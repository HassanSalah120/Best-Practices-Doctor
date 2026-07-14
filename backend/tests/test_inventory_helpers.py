from __future__ import annotations

from analysis.dataflow import (
    GlobalDataflowAnalyzer,
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
)


class TestIsInventoryField:
    def test_stock(self):
        assert is_inventory_field("stock") is True

    def test_quantity(self):
        assert is_inventory_field("quantity") is True

    def test_products_stock(self):
        assert is_inventory_field("products.stock") is True

    def test_view_count_not_inventory(self):
        assert is_inventory_field("view_count") is False

    def test_rating_not_inventory(self):
        assert is_inventory_field("rating") is False

    def test_case_insensitive(self):
        assert is_inventory_field("STOCK") is True
        assert is_inventory_field("Quantity") is True

    def test_backticks_stripped(self):
        assert is_inventory_field("`stock`") is True

    def test_quotes_stripped(self):
        assert is_inventory_field("'quantity'") is True
        assert is_inventory_field('"qty"') is True

    def test_skip_fields(self):
        assert is_inventory_field("score") is False
        assert is_inventory_field("points") is False
        assert is_inventory_field("reputation") is False
        assert is_inventory_field("views") is False
        assert is_inventory_field("version") is False
        assert is_inventory_field("engagement_rate") is False
        assert is_inventory_field("karma") is False
        assert is_inventory_field("xp") is False
        assert is_inventory_field("follower_count") is False
        assert is_inventory_field("revenue") is False
        assert is_inventory_field("product_rating") is False
        assert is_inventory_field("cache_hits") is False
        assert is_inventory_field("sort_index") is False

    def test_expanded_inventory_fields(self):
        assert is_inventory_field("stock_available") is True
        assert is_inventory_field("stock_remaining") is True
        assert is_inventory_field("stock_left") is True
        assert is_inventory_field("reserved_qty") is True
        assert is_inventory_field("sold_qty") is True
        assert is_inventory_field("allocated_qty") is True
        assert is_inventory_field("warehouse_stock") is True
        assert is_inventory_field("bin_quantity") is True
        assert is_inventory_field("reservation_count") is True
        assert is_inventory_field("hold_quantity") is True
        assert is_inventory_field("booked_seats") is True
        assert is_inventory_field("quota") is True
        assert is_inventory_field("quota_remaining") is True
        assert is_inventory_field("api_credits") is True
        assert is_inventory_field("daily_quota") is True
        assert is_inventory_field("energy") is True
        assert is_inventory_field("stamina") is True
        assert is_inventory_field("gems") is True
        assert is_inventory_field("lives") is True

    def test_extension_fields(self):
        ext = frozenset(["warehouse_stock", "api_credits"])
        assert is_inventory_field("warehouse_stock", extensions=ext) is True
        assert is_inventory_field("api_credits", extensions=ext) is True
        assert is_inventory_field("unknown_field", extensions=ext) is False

    def test_skip_fields_override_extensions(self):
        ext = frozenset(["rating", "score"])
        assert is_inventory_field("rating", extensions=ext) is False
        assert is_inventory_field("score", extensions=ext) is False


class TestHasLockProtection:
    def test_lock_for_update(self):
        assert has_lock_protection("->lockForUpdate()->find(1)") is True

    def test_shared_lock(self):
        assert has_lock_protection("->sharedLock()->get()") is True

    def test_for_update_sql(self):
        assert has_lock_protection("DB::select('SELECT * FROM products FOR UPDATE')") is True

    def test_no_lock(self):
        assert has_lock_protection("->find(1)->decrement('stock')") is False

    def test_lock_for_update_syntax(self):
        assert has_lock_protection("->lock_for_update()->get()") is True


class TestHasTransactionProtection:
    def test_db_transaction(self):
        assert has_transaction_protection("DB::transaction(function () { })") is True

    def test_begin_transaction(self):
        assert has_transaction_protection("DB::beginTransaction();") is True

    def test_no_transaction(self):
        assert has_transaction_protection("->decrement('stock')") is False


class TestIsSkipFile:
    def test_tests_dir(self):
        assert is_skip_file("tests/Feature/CheckoutTest.php") is True

    def test_seeders(self):
        assert is_skip_file("database/seeders/ProductSeeder.php") is True

    def test_factories(self):
        assert is_skip_file("database/factories/ProductFactory.php") is True

    def test_migrations(self):
        assert is_skip_file("database/migrations/2024_01_01_create_products.php") is True

    def test_controller(self):
        assert is_skip_file("app/Http/Controllers/CheckoutController.php") is False

    def test_service(self):
        assert is_skip_file("app/Services/InventoryService.php") is False


class TestIsScanTarget:
    def test_controller(self):
        assert is_scan_target("app/Http/Controllers/CheckoutController.php") is True

    def test_service(self):
        assert is_scan_target("app/Services/InventoryService.php") is True

    def test_job(self):
        assert is_scan_target("app/Jobs/ProcessOrder.php") is True

    def test_repository(self):
        assert is_scan_target("app/Repositories/ProductRepository.php") is True

    def test_model(self):
        assert is_scan_target("app/Models/Product.php") is False

    def test_routes(self):
        assert is_scan_target("routes/web.php") is False


class TestIsSkipClass:
    def test_test_class(self):
        assert is_skip_class("ProductTest") is True

    def test_seeder_class(self):
        assert is_skip_class("ProductSeeder") is True

    def test_factory_class(self):
        assert is_skip_class("ProductFactory") is True

    def test_normal_class(self):
        assert is_skip_class("CheckoutService") is False


class TestIsNonInventoryModel:
    def test_user(self):
        assert is_non_inventory_model("User") is True

    def test_admin(self):
        assert is_non_inventory_model("Admin") is True

    def test_product(self):
        assert is_non_inventory_model("Product") is False

    def test_order(self):
        assert is_non_inventory_model("Order") is False


class TestFindDecrementCandidates:
    def test_decrement_call(self):
        results = find_decrement_candidates("->decrement('stock', $qty)")
        assert len(results) == 1
        assert results[0][0] == "stock"

    def test_update_raw(self):
        results = find_decrement_candidates("->update(['stock' => DB::raw('stock - 1')])")
        assert any(r[0] == "stock" for r in results)

    def test_assignment_decrement(self):
        results = find_decrement_candidates("$model->stock -= 1")
        assert any(r[0] == "stock" for r in results)

    def test_non_inventory_field(self):
        results = find_decrement_candidates("->decrement('view_count')")
        assert len(results) == 1
        assert results[0][0] == "view_count"


class TestHasFloorGuard:
    def test_gte_validation(self):
        assert has_floor_guard("if ($product->stock >= $qty)") is True

    def test_where_gte(self):
        assert has_floor_guard("->where('stock', '>=', $qty)->decrement('stock', $qty)") is True

    def test_exception_throw(self):
        assert has_floor_guard("throw new InsufficientStockException()") is True

    def test_no_guard(self):
        assert has_floor_guard("$product->decrement('stock', $qty)") is False

    def test_gt_zero_with_variable_qty(self):
        """stock > 0 with $qty is NOT a valid guard for variable qty."""
        assert has_floor_guard("if ($product->stock > 0) { $product->decrement('stock', $qty); }") is False


class TestHasMutatorProtection:
    def test_max_zero_mutator(self):
        content = """
        function setStockAttribute($value)
        {
            $this->attributes['stock'] = max(0, $value);
        }
        """
        assert has_mutator_protection(content, "stock") is True

    def test_no_mutator(self):
        assert has_mutator_protection("$product->decrement('stock')", "stock") is False


class TestHasQueryExceptionGuard:
    def test_query_exception(self):
        assert has_query_exception_guard("catch (QueryException $e)") is True

    def test_no_exception(self):
        assert has_query_exception_guard("catch (Exception $e)") is False


class TestGlobalDataflowAnalyzer:
    def test_propagates_request_taint_to_derived_quantity(self):
        content = """
        <?php
        $qty = $request->input('qty');
        $finalQty = $qty + 1;
        $product->decrement('stock', $finalQty);
        """

        ctx = GlobalDataflowAnalyzer().analyze_file("app/Services/CheckoutService.php", content)

        assert ctx.variables["qty"].taint == "tainted"
        assert ctx.variables["finalQty"].taint == "tainted"
        assert ctx.inventory_sinks[0].amount_variable == "finalQty"

    def test_records_evidence_traces_for_variable_flow_and_sink(self):
        content = """
        <?php
        $qty = $request->input('qty');
        $finalQty = $qty + 1;
        $product->decrement('stock', $finalQty);
        """

        ctx = GlobalDataflowAnalyzer().analyze_file("app/Services/CheckoutService.php", content)
        trace_kinds = {trace.kind for trace in ctx.traces}

        assert "variable_taint" in trace_kinds
        assert "inventory_sink" in trace_kinds
        assert ctx.domain_sinks("inventory")[0].target == "stock"
        assert ctx.inventory_sinks[0].trace_id
        assert any(trace.id == ctx.inventory_sinks[0].trace_id for trace in ctx.traces)

    def test_builds_generic_context_for_frontend_sources_and_sinks(self):
        content = """
        const saved = localStorage.getItem('session');
        localStorage.setItem('session', saved);
        console.warn(saved);
        fetch('/api/profile');
        """

        ctx = GlobalDataflowAnalyzer().analyze_file("frontend/src/Profile.tsx", content)

        assert ctx.language == "typescript"
        assert any(source.domain == "browser_storage" for source in ctx.sources)
        assert any(sink.domain == "browser_storage" and sink.target == "session" for sink in ctx.sinks)
        assert any(sink.domain == "logging" for sink in ctx.sinks)
        assert any(sink.domain == "network" for sink in ctx.sinks)

    def test_builds_global_context_for_blade_and_devops_files(self):
        blade = GlobalDataflowAnalyzer().analyze_file("resources/views/welcome.blade.php", "{!! $name !!}")
        composer = GlobalDataflowAnalyzer().analyze_file("composer.json", '{"require":{"laravel/framework":"^11.0"}}')
        env_example = GlobalDataflowAnalyzer().analyze_file(".env.example", "APP_ENV=production\n")
        gitignore = GlobalDataflowAnalyzer().analyze_file(".gitignore", ".env\n")
        workflow = GlobalDataflowAnalyzer().analyze_file(".github/workflows/ci.yml", "name: CI\n")

        assert blade.language == "blade"
        assert any(sink.domain == "blade" and sink.operation == "raw_echo" for sink in blade.sinks)
        assert composer.language == "config"
        assert any(signal.domain == "devops" and signal.kind == "dependency_manifest" for signal in composer.framework_signals)
        assert any(signal.domain == "devops" and signal.kind == "environment_file" for signal in env_example.framework_signals)
        assert any(signal.domain == "devops" and signal.kind == "gitignore_file" for signal in gitignore.framework_signals)
        assert any(signal.domain == "devops" and signal.kind == "ci_workflow" for signal in workflow.framework_signals)

    def test_records_same_class_and_service_call_edges(self):
        content = """
        <?php
        class CheckoutController {
            public function store() {
                $this->authorizeOrder();
                $this->checkoutService->reserveStock();
                Product::where('id', 1)->first();
            }
        }
        """

        ctx = GlobalDataflowAnalyzer().analyze_file("app/Http/Controllers/CheckoutController.php", content)

        assert any(edge.kind == "same_class_call" and edge.callee == "authorizeOrder" for edge in ctx.call_edges)
        assert any(edge.kind == "service_or_static_call" and edge.callee == "reserveStock" for edge in ctx.call_edges)
        assert any(trace.kind == "call_edge" for trace in ctx.traces)

    def test_tracks_transaction_and_lock_separately(self):
        content = """
        <?php
        DB::transaction(function () use ($product, $qty) {
            $product->decrement('stock', $qty);
        });
        """

        ctx = GlobalDataflowAnalyzer().analyze_file("app/Services/CheckoutService.php", content)

        assert ctx.has_transaction is True
        assert ctx.has_lock is False
        assert ctx.has_inventory_sink is True

    def test_detects_lock_and_floor_validation_once(self):
        content = """
        <?php
        DB::transaction(function () use ($id, $qty) {
            Product::where('stock', '>=', $qty)->lockForUpdate()->find($id)->decrement('stock', $qty);
        });
        """

        ctx = GlobalDataflowAnalyzer().analyze_file("app/Services/CheckoutService.php", content)

        assert ctx.has_lock is True
        assert ctx.has_floor_validation is True
        assert ctx.inventory_sink_fields == {"stock"}

    def test_debug_export_is_serializable_and_includes_core_signals(self):
        content = """
        <?php
        DB::transaction(function () use ($id, $qty) {
            Product::where('stock', '>=', $qty)->lockForUpdate()->find($id)->decrement('stock', $qty);
        });
        """

        ctx = GlobalDataflowAnalyzer().analyze_file("app/Services/CheckoutService.php", content)
        exported = ctx.to_debug_dict()

        assert exported["file_path"] == "app/Services/CheckoutService.php"
        assert exported["has_lock"] is True
        assert exported["has_transaction"] is True
        assert exported["has_floor_validation"] is True
        assert exported["sinks"][0]["domain"] == "inventory"
        assert exported["inventory_sinks"][0]["field_name"] == "stock"
        assert exported["traces"]
