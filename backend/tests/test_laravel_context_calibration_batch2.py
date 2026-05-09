from __future__ import annotations

from core.ruleset import RuleConfig
from rules.laravel.authorization_missing_on_sensitive_reads import AuthorizationMissingOnSensitiveReadsRule
from rules.laravel.controller_business_logic import ControllerBusinessLogicRule
from rules.laravel.missing_form_request import MissingFormRequestRule
from rules.laravel.policy_coverage_on_mutations import PolicyCoverageOnMutationsRule
from rules.laravel.repository_suggestion import RepositorySuggestionRule
from rules.laravel.service_extraction import ServiceExtractionRule
from rules.laravel.tenant_access_middleware_missing import TenantAccessMiddlewareMissingRule
from rules.laravel.tenant_scope_enforcement import TenantScopeEnforcementRule
from schemas.facts import ClassInfo, Facts, MethodInfo, QueryUsage, RouteInfo, ValidationUsage
from schemas.metrics import MethodMetrics


def _controller(name: str, path: str) -> ClassInfo:
    return ClassInfo(
        name=name,
        fqcn=f"App\\Http\\Controllers\\{name}",
        file_path=path,
        file_hash="fixture",
        line_start=1,
        line_end=220,
    )


def _method(
    class_name: str,
    name: str,
    path: str,
    *,
    loc: int = 60,
    call_sites: list[str] | None = None,
    parameters: list[str] | None = None,
) -> MethodInfo:
    return MethodInfo(
        name=name,
        class_name=class_name,
        class_fqcn=f"App\\Http\\Controllers\\{class_name}",
        file_path=path,
        file_hash="fixture",
        line_start=10,
        line_end=10 + max(loc, 1),
        loc=loc,
        call_sites=call_sites or [],
        parameters=parameters or [],
    )


def _enable_capability(facts: Facts, capability: str) -> None:
    facts.project_context.backend_capabilities[capability] = {"enabled": True, "confidence": 0.9, "source": "test"}


def test_controller_business_logic_batch2_valid_near_invalid():
    rule = ControllerBusinessLogicRule(RuleConfig())
    controller = _controller("OrdersController", "app/Http/Controllers/OrdersController.php")

    valid = Facts(project_path=".")
    valid.project_context.backend_architecture_profile = "layered"
    method_valid = _method(
        "OrdersController",
        "store",
        controller.file_path,
        loc=52,
        call_sites=["$dto = new CreateOrderDTO($request->validated())", "$this->createOrder->execute($dto)", "return back()->with('ok', true)"],
    )
    valid.controllers.append(controller)
    valid.methods.append(method_valid)
    valid_metrics = {
        method_valid.method_fqn: MethodMetrics(
            method_fqn=method_valid.method_fqn,
            file_path=method_valid.file_path,
            cyclomatic_complexity=5,
            conditional_count=2,
            query_count=1,
            validation_count=1,
            loop_count=0,
            has_business_logic=True,
            business_logic_confidence=0.78,
        )
    }
    assert rule.analyze(valid, valid_metrics) == []

    near_miss = Facts(project_path=".")
    near_miss.project_context.backend_architecture_profile = "layered"
    method_near = _method(
        "OrdersController",
        "update",
        controller.file_path,
        loc=66,
        call_sites=["$order = Order::query()->first()", "$order->update($request->validated())", "return back()->with('ok', true)"],
    )
    near_miss.controllers.append(controller)
    near_miss.methods.append(method_near)
    near_metrics = {
        method_near.method_fqn: MethodMetrics(
            method_fqn=method_near.method_fqn,
            file_path=method_near.file_path,
            cyclomatic_complexity=8,
            conditional_count=4,
            query_count=2,
            validation_count=1,
            loop_count=1,
            has_business_logic=True,
            business_logic_confidence=0.84,
        )
    }
    assert len(rule.analyze(near_miss, near_metrics)) == 1

    invalid = Facts(project_path=".")
    invalid.project_context.backend_architecture_profile = "layered"
    method_invalid = _method(
        "OrdersController",
        "approveAll",
        controller.file_path,
        loc=92,
        call_sites=["$rows = Order::query()->get()", "$this->calculateTotals($rows)", "$this->reconcileAccounts($rows)", "return response()->json(['ok' => true])"],
    )
    invalid.controllers.append(controller)
    invalid.methods.append(method_invalid)
    invalid_metrics = {
        method_invalid.method_fqn: MethodMetrics(
            method_fqn=method_invalid.method_fqn,
            file_path=method_invalid.file_path,
            cyclomatic_complexity=11,
            conditional_count=6,
            query_count=2,
            validation_count=0,
            loop_count=2,
            has_business_logic=True,
            business_logic_confidence=0.9,
        )
    }
    assert len(rule.analyze(invalid, invalid_metrics)) == 1


def test_service_extraction_batch2_valid_near_invalid():
    rule = ServiceExtractionRule(
        RuleConfig(
            thresholds={
                "min_business_loc": 18,
                "min_business_confidence": 0.6,
                "loc_only_min_loc": 42,
                "loc_only_min_call_sites": 5,
            }
        )
    )
    controller = _controller("BillingController", "app/Http/Controllers/BillingController.php")

    valid = Facts(project_path=".")
    valid.project_context.backend_architecture_profile = "layered"
    constructor = _method(
        "BillingController",
        "__construct",
        controller.file_path,
        loc=8,
        parameters=["CreateInvoiceAction $createInvoice", "BillingRepository $billingRepository"],
    )
    method_valid = _method(
        "BillingController",
        "store",
        controller.file_path,
        loc=48,
        call_sites=["$dto = new CreateInvoiceDTO($request->validated())", "$this->createInvoice->execute($dto)", "return back()->with('ok', true)"],
        parameters=["Request $request", "CreateInvoiceAction $createInvoice"],
    )
    valid.controllers.append(controller)
    valid.methods.extend([constructor, method_valid])
    valid_metrics = {
        method_valid.method_fqn: MethodMetrics(
            method_fqn=method_valid.method_fqn,
            file_path=method_valid.file_path,
            cyclomatic_complexity=6,
            conditional_count=2,
            has_business_logic=True,
            business_logic_confidence=0.75,
        )
    }
    assert rule.analyze(valid, valid_metrics) == []

    near_miss = Facts(project_path=".")
    near_miss.project_context.backend_architecture_profile = "mvc"
    near_miss.controllers.append(controller)
    method_near = _method(
        "BillingController",
        "touch",
        controller.file_path,
        loc=38,
        call_sites=["$items = Invoice::query()->get()", "$logger->info('ok')", "return back()->with('ok', true)"],
    )
    near_miss.methods.append(method_near)
    near_metrics = {
        method_near.method_fqn: MethodMetrics(
            method_fqn=method_near.method_fqn,
            file_path=method_near.file_path,
            cyclomatic_complexity=5,
            conditional_count=2,
            has_business_logic=False,
            business_logic_confidence=0.0,
        )
    }
    assert rule.analyze(near_miss, near_metrics) == []

    invalid = Facts(project_path=".")
    invalid.project_context.backend_architecture_profile = "layered"
    invalid.controllers.append(controller)
    method_invalid = _method(
        "BillingController",
        "refund",
        controller.file_path,
        loc=72,
        call_sites=[
            "$payment = Payment::query()->first()",
            "$this->calculatePenalty($payment)",
            "$this->processRefund($payment)",
            "$this->notifyUsers($payment)",
            "$this->appendAuditLog($payment)",
            "return back()->with('ok', true)",
        ],
    )
    invalid.methods.append(method_invalid)
    invalid_metrics = {
        method_invalid.method_fqn: MethodMetrics(
            method_fqn=method_invalid.method_fqn,
            file_path=method_invalid.file_path,
            cyclomatic_complexity=9,
            conditional_count=4,
            has_business_logic=True,
            business_logic_confidence=0.86,
        )
    }
    assert len(rule.analyze(invalid, invalid_metrics)) == 1


def test_repository_suggestion_batch2_valid_near_invalid():
    rule = RepositorySuggestionRule(
        RuleConfig(
            thresholds={
                "min_query_count": 2,
                "min_complexity": 2,
                "min_write_queries": 1,
                "read_only_blocked_max_queries": 1,
            }
        )
    )
    controller = _controller("ReportsController", "app/Http/Controllers/ReportsController.php")

    valid = Facts(project_path=".")
    valid.project_context.backend_architecture_profile = "layered"
    valid.controllers.append(controller)
    valid_method = _method(
        "ReportsController",
        "index",
        controller.file_path,
        loc=34,
        call_sites=["$rows = $this->reportService->execute($request)", "return Inertia::render('Reports/Index', ['rows' => $rows])"],
    )
    valid.methods.append(valid_method)
    valid.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=18,
            method_name="index",
            model="Report",
            method_chain="query->get",
            query_type="select",
        )
    )
    valid_metrics = {
        valid_method.method_fqn: MethodMetrics(
            method_fqn=valid_method.method_fqn,
            file_path=valid_method.file_path,
            cyclomatic_complexity=3,
            query_count=1,
        )
    }
    assert rule.analyze(valid, valid_metrics) == []

    near_miss = Facts(project_path=".")
    near_miss.project_context.backend_architecture_profile = "layered"
    near_miss.controllers.append(controller)
    near_method = _method("ReportsController", "store", controller.file_path, loc=52)
    near_miss.methods.append(near_method)
    near_miss.queries.extend(
        [
            QueryUsage(file_path=controller.file_path, line_number=24, method_name="store", model="Report", method_chain="query->first", query_type="select"),
            QueryUsage(file_path=controller.file_path, line_number=35, method_name="store", model="Report", method_chain="query->update", query_type="update"),
        ]
    )
    near_metrics = {
        near_method.method_fqn: MethodMetrics(
            method_fqn=near_method.method_fqn,
            file_path=near_method.file_path,
            cyclomatic_complexity=3,
            query_count=2,
        )
    }
    assert len(rule.analyze(near_miss, near_metrics)) == 1

    invalid = Facts(project_path=".")
    invalid.project_context.backend_architecture_profile = "layered"
    invalid.controllers.append(controller)
    invalid_method = _method("ReportsController", "bulkUpdate", controller.file_path, loc=64)
    invalid.methods.append(invalid_method)
    invalid.queries.extend(
        [
            QueryUsage(file_path=controller.file_path, line_number=31, method_name="bulkUpdate", model="Report", method_chain="query->get", query_type="select"),
            QueryUsage(file_path=controller.file_path, line_number=44, method_name="bulkUpdate", model="Report", method_chain="query->update", query_type="update"),
            QueryUsage(file_path=controller.file_path, line_number=48, method_name="bulkUpdate", model="AuditLog", method_chain="query->insert", query_type="insert"),
        ]
    )
    invalid_metrics = {
        invalid_method.method_fqn: MethodMetrics(
            method_fqn=invalid_method.method_fqn,
            file_path=invalid_method.file_path,
            cyclomatic_complexity=5,
            query_count=3,
        )
    }
    assert len(rule.analyze(invalid, invalid_metrics)) == 1


def test_missing_form_request_batch2_valid_near_invalid():
    rule = MissingFormRequestRule(RuleConfig(thresholds={"min_rules": 2, "auth_flow_max_rules_without_form_request": 3}))

    valid = Facts(project_path=".")
    auth_controller = _controller("LoginController", "app/Http/Controllers/Auth/LoginController.php")
    valid.controllers.append(auth_controller)
    valid.methods.append(_method("LoginController", "store", auth_controller.file_path, loc=20))
    valid.validations.append(
        ValidationUsage(
            file_path=auth_controller.file_path,
            line_number=15,
            method_name="store",
            validation_type="inline",
            rules={"email": ["required", "email"], "password": ["required"]},
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.controllers.append(auth_controller)
    near_miss.methods.append(_method("LoginController", "store", auth_controller.file_path, loc=26))
    near_miss.validations.append(
        ValidationUsage(
            file_path=auth_controller.file_path,
            line_number=19,
            method_name="store",
            validation_type="inline",
            rules={
                "email": ["required", "email"],
                "password": ["required", "string", "min:8"],
                "otp": ["required", "string", "size:6"],
            },
        )
    )
    assert len(rule.analyze(near_miss)) == 1

    invalid = Facts(project_path=".")
    patient_controller = _controller("PatientController", "app/Http/Controllers/PatientController.php")
    invalid.controllers.append(patient_controller)
    invalid.methods.append(_method("PatientController", "update", patient_controller.file_path, loc=44))
    invalid.validations.append(
        ValidationUsage(
            file_path=patient_controller.file_path,
            line_number=31,
            method_name="update",
            validation_type="inline",
            rules={
                "name": ["required", "string", "max:255"],
                "email": ["required", "email", "unique:users,email"],
                "status": ["required", "in:active,inactive,pending"],
            },
        )
    )
    assert len(rule.analyze(invalid)) == 1


def test_tenant_scope_enforcement_batch2_valid_near_invalid():
    rule = TenantScopeEnforcementRule(
        RuleConfig(
            thresholds={
                "min_project_signals": 5,
                "min_method_queries": 1,
                "min_confidence": 0.7,
                "require_multi_tenant_capability": True,
            }
        )
    )

    valid = Facts(project_path=".")
    valid.project_context.tenant_mode = "unknown"
    valid.controllers.append(_controller("DashboardController", "app/Http/Controllers/DashboardController.php"))
    valid.methods.append(_method("DashboardController", "index", "app/Http/Controllers/DashboardController.php", loc=30))
    valid.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/DashboardController.php",
            line_number=18,
            method_name="index",
            model="Clinic",
            method_chain="query->get",
            query_type="select",
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.project_context.tenant_mode = "tenant"
    _enable_capability(near_miss, "multi_tenant")
    near_miss.methods.append(
        MethodInfo(
            name="index",
            class_name="ClinicReportsService",
            class_fqcn="App\\Services\\ClinicReportsService",
            file_path="app/Services/Clinic/ClinicReportsService.php",
            file_hash="svc",
            line_start=10,
            line_end=48,
            loc=39,
            call_sites=["$clinicId = auth()->user()->clinic_id", "return Report::query()->where('clinic_id', $clinicId)->get()"],
        )
    )
    near_miss.queries.append(
        QueryUsage(
            file_path="app/Services/Clinic/ClinicReportsService.php",
            line_number=24,
            method_name="index",
            model="Report",
            method_chain="query->where('clinic_id', $clinicId)->get",
            query_type="select",
        )
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.project_context.tenant_mode = "tenant"
    _enable_capability(invalid, "multi_tenant")
    invalid.methods.append(
        MethodInfo(
            name="index",
            class_name="ClinicReportsService",
            class_fqcn="App\\Services\\ClinicReportsService",
            file_path="app/Services/Clinic/ClinicReportsService.php",
            file_hash="svc",
            line_start=10,
            line_end=52,
            loc=43,
            call_sites=["return Report::query()->get()"],
        )
    )
    invalid.queries.append(
        QueryUsage(
            file_path="app/Services/Clinic/ClinicReportsService.php",
            line_number=26,
            method_name="index",
            model="Report",
            method_chain="query->get",
            query_type="select",
        )
    )
    assert len(rule.analyze(invalid)) == 1


def test_tenant_access_middleware_missing_batch2_valid_near_invalid():
    rule = TenantAccessMiddlewareMissingRule(
        RuleConfig(
            thresholds={
                "min_project_signals": 5,
                "min_confidence": 0.7,
                "require_multi_tenant_capability": True,
            }
        )
    )

    valid = Facts(project_path=".")
    valid.project_context.tenant_mode = "unknown"
    valid.routes.append(
        RouteInfo(
            method="GET",
            uri="/clinic/reports",
            controller="Clinic\\ReportsController",
            action="index",
            middleware=["auth", "clinic_access"],
            file_path="routes/web.php",
            line_number=22,
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.project_context.tenant_mode = "tenant"
    _enable_capability(near_miss, "multi_tenant")
    near_miss.routes.append(
        RouteInfo(
            method="GET",
            uri="/clinic/reports/{clinic}",
            controller="Clinic\\ReportsController",
            action="show",
            middleware=["auth", "can:view,clinic"],
            file_path="routes/web.php",
            line_number=30,
        )
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.project_context.tenant_mode = "tenant"
    _enable_capability(invalid, "multi_tenant")
    invalid.routes.append(
        RouteInfo(
            method="GET",
            uri="/clinic/reports/{clinic}",
            controller="Clinic\\ReportsController",
            action="show",
            middleware=["auth", "verified"],
            file_path="routes/web.php",
            line_number=37,
        )
    )
    assert len(rule.analyze(invalid)) == 1


def test_policy_coverage_on_mutations_batch2_valid_near_invalid():
    rule = PolicyCoverageOnMutationsRule(RuleConfig(thresholds={"min_write_queries": 1, "min_mutation_signals": 2}))
    controller = _controller("InvoicesController", "app/Http/Controllers/InvoicesController.php")

    valid = Facts(project_path=".")
    valid.controllers.append(controller)
    valid_method = _method(
        "InvoicesController",
        "update",
        controller.file_path,
        loc=42,
        call_sites=["$this->authorize('update', $invoice)", "$invoice->update($request->validated())"],
    )
    valid.methods.append(valid_method)
    valid.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=24,
            method_name="update",
            model="Invoice",
            method_chain="query->update",
            query_type="update",
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.controllers.append(controller)
    near_method = _method("InvoicesController", "touch", controller.file_path, loc=30, call_sites=["$invoice->update(['seen_at' => now()])"])
    near_miss.methods.append(near_method)
    near_miss.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=19,
            method_name="touch",
            model="Invoice",
            method_chain="query->update",
            query_type="update",
        )
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.controllers.append(controller)
    invalid_method = _method("InvoicesController", "destroy", controller.file_path, loc=39, call_sites=["$invoice->delete()", "return back()"])
    invalid.methods.append(invalid_method)
    invalid.routes.append(
        RouteInfo(
            method="DELETE",
            uri="/invoices/{invoice}",
            controller="InvoicesController",
            action="destroy",
            middleware=["web"],
            file_path="routes/web.php",
            line_number=40,
        )
    )
    invalid.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=20,
            method_name="destroy",
            model="Invoice",
            method_chain="query->delete",
            query_type="delete",
        )
    )
    assert len(rule.analyze(invalid)) == 1


def test_authorization_missing_on_sensitive_reads_batch2_valid_near_invalid():
    rule = AuthorizationMissingOnSensitiveReadsRule(RuleConfig(thresholds={"min_read_queries": 1, "min_sensitive_score": 3}))
    controller = _controller("PatientFinancialController", "app/Http/Controllers/PatientFinancialController.php")

    valid = Facts(project_path=".")
    valid.controllers.append(controller)
    valid_method = _method(
        "PatientFinancialController",
        "show",
        controller.file_path,
        loc=32,
        call_sites=["$this->authorize('view', $invoice)", "$invoice = Invoice::query()->firstOrFail()"],
    )
    valid.methods.append(valid_method)
    valid.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=18,
            method_name="show",
            model="Invoice",
            method_chain="query->firstOrFail",
            query_type="select",
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.controllers.append(controller)
    near_method = _method("PatientFinancialController", "index", controller.file_path, loc=26, call_sites=["$rows = Invoice::query()->paginate()"])
    near_miss.methods.append(near_method)
    near_miss.routes.append(
        RouteInfo(
            method="GET",
            uri="/overview",
            controller="PatientFinancialController",
            action="index",
            middleware=["auth"],
            file_path="routes/web.php",
            line_number=22,
        )
    )
    near_miss.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=14,
            method_name="index",
            model="Log",
            method_chain="query->paginate",
            query_type="select",
        )
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.controllers.append(controller)
    invalid_method = _method(
        "PatientFinancialController",
        "show",
        controller.file_path,
        loc=34,
        call_sites=["$invoice = Invoice::query()->firstOrFail()", "return response()->json($invoice)"],
    )
    invalid.methods.append(invalid_method)
    invalid.routes.append(
        RouteInfo(
            method="GET",
            uri="/patients/{patient}/invoices/{invoice}",
            controller="PatientFinancialController",
            action="show",
            middleware=["auth", "verified"],
            file_path="routes/web.php",
            line_number=31,
        )
    )
    invalid.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=20,
            method_name="show",
            model="Invoice",
            method_chain="query->firstOrFail",
            query_type="select",
        )
    )
    assert len(rule.analyze(invalid)) == 1
