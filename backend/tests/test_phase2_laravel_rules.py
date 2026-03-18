from core.ruleset import RuleConfig
from rules.laravel.policy_coverage_on_mutations import PolicyCoverageOnMutationsRule
from rules.laravel.authorization_bypass_risk import AuthorizationBypassRiskRule
from rules.laravel.transaction_required_for_multi_write import TransactionRequiredForMultiWriteRule
from rules.laravel.tenant_scope_enforcement import TenantScopeEnforcementRule
from rules.laravel.controller_business_logic import ControllerBusinessLogicRule
from rules.laravel.controller_query_direct import ControllerQueryDirectRule
from rules.laravel.controller_validation_inline import ControllerInlineValidationRule
from rules.laravel.custom_exception_suggestion import CustomExceptionSuggestionRule
from rules.laravel.action_class_suggestion import ActionClassSuggestionRule
from rules.laravel.massive_model import MassiveModelRule
from rules.php.too_many_dependencies import TooManyDependenciesRule
from schemas.facts import Facts, ClassInfo, MethodInfo, QueryUsage, RouteInfo, ValidationUsage
from schemas.metrics import MethodMetrics


def _controller(name: str, file_path: str) -> ClassInfo:
    return ClassInfo(
        name=name,
        fqcn=f"App\\Http\\Controllers\\{name}",
        file_path=file_path,
        file_hash="deadbeef",
        line_start=1,
        line_end=200,
    )


def _method(
    class_name: str,
    method_name: str,
    file_path: str,
    call_sites: list[str] | None = None,
) -> MethodInfo:
    return MethodInfo(
        name=method_name,
        class_name=class_name,
        class_fqcn=f"App\\Http\\Controllers\\{class_name}",
        file_path=file_path,
        file_hash="deadbeef",
        line_start=10,
        line_end=80,
        loc=71,
        call_sites=call_sites or [],
    )


def test_policy_coverage_on_mutations_flags_unprotected_mutation():
    facts = Facts(project_path=".")
    facts.controllers.append(_controller("PatientController", "app/Http/Controllers/PatientController.php"))
    facts.methods.append(_method("PatientController", "store", "app/Http/Controllers/PatientController.php"))
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/PatientController.php",
            line_number=20,
            method_name="store",
            model="Patient",
            method_chain="create",
        )
    )

    findings = PolicyCoverageOnMutationsRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert len(findings) == 1
    assert findings[0].rule_id == "policy-coverage-on-mutations"


def test_policy_coverage_on_mutations_ignores_authorized_mutation():
    facts = Facts(project_path=".")
    facts.controllers.append(_controller("PatientController", "app/Http/Controllers/PatientController.php"))
    facts.methods.append(
        _method(
            "PatientController",
            "store",
            "app/Http/Controllers/PatientController.php",
            call_sites=["$this->authorize('create', Patient::class)"],
        )
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/PatientController.php",
            line_number=20,
            method_name="store",
            model="Patient",
            method_chain="create",
        )
    )

    findings = PolicyCoverageOnMutationsRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_policy_coverage_on_mutations_ignores_route_guarded_mutation():
    facts = Facts(project_path=".")
    facts.controllers.append(_controller("PatientController", "app/Http/Controllers/PatientController.php"))
    facts.methods.append(_method("PatientController", "store", "app/Http/Controllers/PatientController.php"))
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/PatientController.php",
            line_number=20,
            method_name="store",
            model="Patient",
            method_chain="create",
        )
    )
    facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/patients",
            controller="PatientController",
            action="store",
            middleware=["auth:sanctum"],
            file_path="routes/api.php",
            line_number=10,
        )
    )

    findings = PolicyCoverageOnMutationsRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_authorization_bypass_risk_flags_model_access_without_auth():
    facts = Facts(project_path=".")
    facts.controllers.append(_controller("OrderController", "app/Http/Controllers/OrderController.php"))
    facts.methods.append(_method("OrderController", "update", "app/Http/Controllers/OrderController.php"))
    facts.queries.extend(
        [
            QueryUsage(
                file_path="app/Http/Controllers/OrderController.php",
                line_number=22,
                method_name="update",
                model="Order",
                method_chain="findOrFail",
            ),
            QueryUsage(
                file_path="app/Http/Controllers/OrderController.php",
                line_number=27,
                method_name="update",
                model="Order",
                method_chain="update",
            ),
        ]
    )

    findings = AuthorizationBypassRiskRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert len(findings) == 1
    assert findings[0].rule_id == "authorization-bypass-risk"


def test_authorization_bypass_risk_ignores_gate_protected_method():
    facts = Facts(project_path=".")
    facts.controllers.append(_controller("OrderController", "app/Http/Controllers/OrderController.php"))
    facts.methods.append(
        _method(
            "OrderController",
            "update",
            "app/Http/Controllers/OrderController.php",
            call_sites=["Gate::authorize('update', $order)"],
        )
    )
    facts.queries.extend(
        [
            QueryUsage(
                file_path="app/Http/Controllers/OrderController.php",
                line_number=22,
                method_name="update",
                model="Order",
                method_chain="findOrFail",
            ),
            QueryUsage(
                file_path="app/Http/Controllers/OrderController.php",
                line_number=27,
                method_name="update",
                model="Order",
                method_chain="update",
            ),
        ]
    )

    findings = AuthorizationBypassRiskRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_transaction_required_for_multi_write_flags_unwrapped_multi_write():
    facts = Facts(project_path=".")
    facts.methods.append(
        MethodInfo(
            name="finalize",
            class_name="InvoiceService",
            class_fqcn="App\\Services\\InvoiceService",
            file_path="app/Services/InvoiceService.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=80,
            loc=71,
            call_sites=[],
        )
    )
    facts.queries.extend(
        [
            QueryUsage(
                file_path="app/Services/InvoiceService.php",
                line_number=20,
                method_name="finalize",
                model="Invoice",
                method_chain="create",
            ),
            QueryUsage(
                file_path="app/Services/InvoiceService.php",
                line_number=25,
                method_name="finalize",
                model="Payment",
                method_chain="create",
            ),
        ]
    )

    findings = TransactionRequiredForMultiWriteRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert len(findings) == 1
    assert findings[0].rule_id == "transaction-required-for-multi-write"


def test_transaction_required_for_multi_write_ignores_transactional_method():
    facts = Facts(project_path=".")
    facts.methods.append(
        MethodInfo(
            name="finalize",
            class_name="InvoiceService",
            class_fqcn="App\\Services\\InvoiceService",
            file_path="app/Services/InvoiceService.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=80,
            loc=71,
            call_sites=["DB::transaction(function () { /* ... */ })"],
        )
    )
    facts.queries.extend(
        [
            QueryUsage(
                file_path="app/Services/InvoiceService.php",
                line_number=20,
                method_name="finalize",
                model="Invoice",
                method_chain="create",
            ),
            QueryUsage(
                file_path="app/Services/InvoiceService.php",
                line_number=25,
                method_name="finalize",
                model="Payment",
                method_chain="create",
            ),
        ]
    )

    findings = TransactionRequiredForMultiWriteRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_tenant_scope_enforcement_flags_unscoped_tenant_query():
    facts = Facts(project_path=".")
    facts.files = [
        "app/Http/Controllers/Clinic/PatientController.php",
        "app/Services/ClinicBillingService.php",
        "app/Repositories/ClinicPatientRepository.php",
        "app/Models/Clinic.php",
        "app/Models/Patient.php",
    ]
    facts.classes.append(
        ClassInfo(
            name="ClinicPatientRepository",
            fqcn="App\\Repositories\\ClinicPatientRepository",
            file_path="app/Repositories/ClinicPatientRepository.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=120,
        )
    )
    facts.methods.append(
        MethodInfo(
            name="index",
            class_name="PatientController",
            class_fqcn="App\\Http\\Controllers\\Clinic\\PatientController",
            file_path="app/Http/Controllers/Clinic/PatientController.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=70,
            loc=61,
            call_sites=["Patient::query()->paginate(20)"],
        )
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Clinic/PatientController.php",
            line_number=20,
            method_name="index",
            model="Patient",
            method_chain="query->paginate",
        )
    )

    findings = TenantScopeEnforcementRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert len(findings) == 1
    assert findings[0].rule_id == "tenant-scope-enforcement"


def test_tenant_scope_enforcement_ignores_scoped_query():
    facts = Facts(project_path=".")
    facts.files = [
        "app/Http/Controllers/Clinic/PatientController.php",
        "app/Services/ClinicBillingService.php",
        "app/Repositories/ClinicPatientRepository.php",
        "app/Models/Clinic.php",
        "app/Models/Patient.php",
    ]
    facts.methods.append(
        MethodInfo(
            name="index",
            class_name="PatientController",
            class_fqcn="App\\Http\\Controllers\\Clinic\\PatientController",
            file_path="app/Http/Controllers/Clinic/PatientController.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=70,
            loc=61,
            call_sites=["Patient::where('clinic_id', $clinicId)->paginate(20)"],
        )
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Clinic/PatientController.php",
            line_number=20,
            method_name="index",
            model="Patient",
            method_chain="where->paginate",
        )
    )

    findings = TenantScopeEnforcementRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_policy_coverage_on_mutations_ignores_public_auth_action():
    facts = Facts(project_path=".")
    facts.controllers.append(_controller("AuthController", "app/Http/Controllers/AuthController.php"))
    facts.methods.append(_method("AuthController", "login", "app/Http/Controllers/AuthController.php"))
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/AuthController.php",
            line_number=22,
            method_name="login",
            model="User",
            method_chain="create",
        )
    )

    findings = PolicyCoverageOnMutationsRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_authorization_bypass_risk_ignores_route_can_middleware_protection():
    facts = Facts(project_path=".")
    facts.controllers.append(_controller("OrderController", "app/Http/Controllers/OrderController.php"))
    facts.methods.append(_method("OrderController", "update", "app/Http/Controllers/OrderController.php"))
    facts.routes.append(
        RouteInfo(
            method="PUT",
            uri="/orders/{order}",
            controller="OrderController",
            action="update",
            middleware=["auth:sanctum", "can:update,order"],
            file_path="routes/api.php",
            line_number=18,
        )
    )
    facts.queries.extend(
        [
            QueryUsage(
                file_path="app/Http/Controllers/OrderController.php",
                line_number=22,
                method_name="update",
                model="Order",
                method_chain="findOrFail",
            ),
            QueryUsage(
                file_path="app/Http/Controllers/OrderController.php",
                line_number=27,
                method_name="update",
                model="Order",
                method_chain="update",
            ),
        ]
    )

    findings = AuthorizationBypassRiskRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_tenant_scope_enforcement_ignores_global_model_queries():
    facts = Facts(project_path=".")
    facts.files = [
        "app/Http/Controllers/Clinic/SystemSettingsController.php",
        "app/Services/ClinicBillingService.php",
        "app/Models/Clinic.php",
    ]
    facts.methods.append(
        MethodInfo(
            name="index",
            class_name="SystemSettingsController",
            class_fqcn="App\\Http\\Controllers\\Clinic\\SystemSettingsController",
            file_path="app/Http/Controllers/Clinic/SystemSettingsController.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=70,
            loc=61,
            call_sites=["Setting::query()->get()"],
        )
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Clinic/SystemSettingsController.php",
            line_number=20,
            method_name="index",
            model="Setting",
            method_chain="query->get",
        )
    )

    findings = TenantScopeEnforcementRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_tenant_scope_enforcement_skips_non_tenant_projects_with_account_language():
    facts = Facts(project_path=".")
    facts.files = [
        "app/Http/Controllers/Account/OrdersController.php",
        "app/Services/AccountReportingService.php",
        "app/Models/Order.php",
        "app/Models/Account.php",
    ]
    facts.methods.append(
        MethodInfo(
            name="index",
            class_name="OrdersController",
            class_fqcn="App\\Http\\Controllers\\Account\\OrdersController",
            file_path="app/Http/Controllers/Account/OrdersController.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=70,
            loc=61,
            call_sites=["Order::query()->paginate(20)"],
        )
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Account/OrdersController.php",
            line_number=20,
            method_name="index",
            model="Order",
            method_chain="query->paginate",
        )
    )

    findings = TenantScopeEnforcementRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_controller_query_direct_skips_single_simple_rest_read():
    facts = Facts(project_path=".")
    controller = _controller("PatientController", "app/Http/Controllers/PatientController.php")
    facts.controllers.append(controller)
    facts.methods.append(_method("PatientController", "index", controller.file_path))
    facts.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=18,
            method_name="index",
            model="Patient",
            method_chain="query->paginate",
            query_type="select",
        )
    )

    findings = ControllerQueryDirectRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_controller_query_direct_flags_multiple_controller_queries():
    facts = Facts(project_path=".")
    controller = _controller("PatientController", "app/Http/Controllers/PatientController.php")
    facts.controllers.append(controller)
    facts.methods.append(_method("PatientController", "index", controller.file_path))
    facts.queries.extend(
        [
            QueryUsage(
                file_path=controller.file_path,
                line_number=18,
                method_name="index",
                model="Patient",
                method_chain="query->paginate",
                query_type="select",
            ),
            QueryUsage(
                file_path=controller.file_path,
                line_number=28,
                method_name="index",
                model="Clinic",
                method_chain="query->get",
                query_type="select",
            ),
        ]
    )

    findings = ControllerQueryDirectRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert len(findings) == 1
    assert findings[0].rule_id == "controller-query-direct"


def test_controller_business_logic_skips_large_rest_read_without_business_signal():
    facts = Facts(project_path=".")
    controller = _controller("ReportsController", "app/Http/Controllers/ReportsController.php")
    method = _method("ReportsController", "index", controller.file_path)
    method.loc = 95
    facts.controllers.append(controller)
    facts.methods.append(method)
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=9,
            conditional_count=2,
            query_count=1,
            validation_count=1,
            loop_count=0,
            has_business_logic=False,
        )
    }

    findings = ControllerBusinessLogicRule(RuleConfig()).analyze(facts, metrics)
    assert findings == []


def test_controller_business_logic_flags_confident_business_logic():
    facts = Facts(project_path=".")
    controller = _controller("CheckoutController", "app/Http/Controllers/CheckoutController.php")
    method = _method("CheckoutController", "store", controller.file_path)
    method.loc = 90
    facts.controllers.append(controller)
    facts.methods.append(method)
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=10,
            conditional_count=5,
            query_count=2,
            validation_count=1,
            loop_count=1,
            has_business_logic=True,
            business_logic_confidence=0.85,
        )
    }

    findings = ControllerBusinessLogicRule(RuleConfig()).analyze(facts, metrics)
    assert len(findings) == 1
    assert findings[0].rule_id == "controller-business-logic"


def test_controller_business_logic_skips_tiny_service_delegation():
    facts = Facts(project_path=".")
    controller = _controller("NewingController", "app/Http/Controllers/NewingController.php")
    method = _method("NewingController", "store", controller.file_path)
    method.loc = 6
    facts.controllers.append(controller)
    facts.methods.append(method)
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=1,
            conditional_count=0,
            query_count=0,
            validation_count=0,
            loop_count=0,
            has_business_logic=True,
            business_logic_confidence=0.65,
        )
    }

    findings = ControllerBusinessLogicRule(RuleConfig()).analyze(facts, metrics)
    assert findings == []


def test_controller_business_logic_skips_auth_flow_action_orchestration():
    facts = Facts(project_path=".")
    controller_path = "app/Http/Controllers/Auth/EmailVerificationNotificationController.php"
    controller = _controller("EmailVerificationNotificationController", controller_path)
    method = _method(
        "EmailVerificationNotificationController",
        "store",
        controller.file_path,
        call_sites=["$this->sendVerification->execute($request->user())", "redirect()->intended(route('dashboard'))"],
    )
    method.loc = 24
    facts.controllers.append(controller)
    facts.methods.append(method)
    facts.project_context.auth_flow_paths = [controller_path, method.method_fqn]
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=3,
            conditional_count=2,
            query_count=0,
            validation_count=0,
            loop_count=0,
            has_business_logic=True,
            business_logic_confidence=0.8,
        )
    }

    findings = ControllerBusinessLogicRule(RuleConfig()).analyze(facts, metrics)
    assert findings == []


def test_controller_business_logic_skips_booking_action_orchestration_with_response_formatting():
    facts = Facts(project_path=".")
    controller_path = "app/Http/Controllers/BookingController.php"
    controller = _controller("BookingController", controller_path)
    method = _method(
        "BookingController",
        "storeWhatsApp",
        controller.file_path,
        call_sites=[
            "$clinic = $this->bookingService->resolveClinicForBooking('whatsapp')",
            "$result = $this->processWhatsApp->execute($clinic, $request->validated(), $request)",
            "$redirectUrl = $this->redirector->sanitize($result['redirectUrl'] ?? null, $request)",
            "return redirect()->away($redirectUrl)",
        ],
    )
    method.loc = 52
    facts.controllers.append(controller)
    facts.methods.append(method)
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=4,
            conditional_count=3,
            query_count=0,
            validation_count=1,
            loop_count=0,
            has_business_logic=True,
            business_logic_confidence=0.76,
        )
    }

    findings = ControllerBusinessLogicRule(RuleConfig()).analyze(facts, metrics)
    assert findings == []


def test_too_many_dependencies_skips_controller_facade_orchestrator_pattern():
    facts = Facts(project_path=".")
    ctor = MethodInfo(
        name="__construct",
        class_name="CommunicationController",
        class_fqcn="App\\Http\\Controllers\\Clinic\\CommunicationController",
        file_path="app/Http/Controllers/Clinic/CommunicationController.php",
        file_hash="deadbeef",
        line_start=10,
        line_end=18,
        loc=9,
        parameters=[
            "CommunicationServiceInterface $communication",
            "ClinicMailServiceInterface $clinicMail",
            "PatientServiceInterface $patients",
            "SendManualMessageAction $sendMessage",
            "GetConnectionStatusAction $getConnectionStatus",
            "SendTestMessageAction $sendTestMessage",
            "SendTestEmailAction $sendTestEmail",
        ],
    )
    facts.methods.append(ctor)

    findings = TooManyDependenciesRule(RuleConfig()).analyze(facts)
    assert findings == []


def test_massive_model_skips_slightly_large_structure_without_mixed_responsibilities():
    facts = Facts(project_path=".")
    model = ClassInfo(
        name="Patient",
        fqcn="App\\Models\\Patient",
        file_path="app/Models/Patient.php",
        file_hash="deadbeef",
        line_start=1,
        line_end=220,
    )
    facts.models.append(model)
    for index in range(16):
        facts.methods.append(
            MethodInfo(
                name=f"relation{index}",
                class_name="Patient",
                class_fqcn=model.fqcn,
                file_path=model.file_path,
                file_hash="deadbeef",
                line_start=10 + index,
                line_end=11 + index,
                loc=2,
            )
        )

    findings = MassiveModelRule(RuleConfig()).analyze(facts, metrics={})
    assert findings == []


def test_massive_model_flags_large_model_with_mixed_responsibilities():
    facts = Facts(project_path=".")
    model = ClassInfo(
        name="Patient",
        fqcn="App\\Models\\Patient",
        file_path="app/Models/Patient.php",
        file_hash="deadbeef",
        line_start=1,
        line_end=220,
    )
    facts.models.append(model)
    metrics: dict[str, MethodMetrics] = {}
    for index in range(16):
        method = MethodInfo(
            name=f"method{index}",
            class_name="Patient",
            class_fqcn=model.fqcn,
            file_path=model.file_path,
            file_hash="deadbeef",
            line_start=10 + index,
            line_end=12 + index,
            loc=3,
        )
        facts.methods.append(method)
        metrics[method.method_fqn] = MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            has_query=index == 0,
            has_business_logic=index == 1,
            business_logic_confidence=0.8 if index == 1 else 0.0,
        )

    findings = MassiveModelRule(RuleConfig()).analyze(facts, metrics=metrics)
    assert len(findings) == 1
    assert findings[0].rule_id == "massive-model"


def test_controller_inline_validation_skips_small_auth_flow():
    facts = Facts(project_path=".")
    controller = ClassInfo(
        name="LoginController",
        fqcn="App\\Http\\Controllers\\Auth\\LoginController",
        file_path="app/Http/Controllers/Auth/LoginController.php",
        file_hash="deadbeef",
        line_start=1,
        line_end=120,
    )
    facts.controllers.append(controller)
    facts.validations.append(
        ValidationUsage(
            file_path=controller.file_path,
            line_number=18,
            method_name="store",
            validation_type="inline",
            rules={"email": ["required", "email"], "password": ["required"]},
        )
    )

    findings = ControllerInlineValidationRule(RuleConfig()).analyze(facts)
    assert findings == []


def test_controller_inline_validation_flags_substantial_validation():
    facts = Facts(project_path=".")
    controller = _controller("PatientController", "app/Http/Controllers/PatientController.php")
    facts.controllers.append(controller)
    facts.form_requests.append(
        ClassInfo(
            name="PatientRequest",
            fqcn="App\\Http\\Requests\\PatientRequest",
            file_path="app/Http/Requests/PatientRequest.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=40,
        )
    )
    facts.validations.append(
        ValidationUsage(
            file_path=controller.file_path,
            line_number=18,
            method_name="store",
            validation_type="inline",
            rules={
                "email": ["required", "email", "unique:users"],
                "name": ["required", "string", "max:255"],
            },
        )
    )

    findings = ControllerInlineValidationRule(RuleConfig()).analyze(facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "controller-inline-validation"
    assert findings[0].confidence >= 0.8


def test_custom_exception_suggestion_flags_generic_service_exception_when_project_has_custom_exceptions():
    facts = Facts(project_path=".")
    facts.exceptions.append(
        ClassInfo(
            name="PaymentFailedException",
            fqcn="App\\Exceptions\\PaymentFailedException",
            file_path="app/Exceptions/PaymentFailedException.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=20,
        )
    )
    facts.methods.append(
        MethodInfo(
            name="charge",
            class_name="BillingService",
            class_fqcn="App\\Services\\BillingService",
            file_path="app/Services/BillingService.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=30,
            loc=21,
            call_sites=["$gateway->charge()", "$logger->error()"],
            throws=["Exception"],
        )
    )

    findings = CustomExceptionSuggestionRule(RuleConfig()).analyze(facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "custom-exception-suggestion"
    assert findings[0].confidence >= 0.8


def test_custom_exception_suggestion_skips_console_command_exceptions():
    facts = Facts(project_path=".")
    facts.exceptions.append(
        ClassInfo(
            name="DomainException",
            fqcn="App\\Exceptions\\DomainException",
            file_path="app/Exceptions/DomainException.php",
            file_hash="deadbeef",
            line_start=1,
            line_end=20,
        )
    )
    facts.methods.append(
        MethodInfo(
            name="handle",
            class_name="SyncDataCommand",
            class_fqcn="App\\Console\\Commands\\SyncDataCommand",
            file_path="app/Console/Commands/SyncDataCommand.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=22,
            loc=13,
            throws=["Exception"],
        )
    )

    findings = CustomExceptionSuggestionRule(RuleConfig()).analyze(facts)
    assert findings == []


def test_action_class_suggestion_skips_single_method_service_in_action_architecture():
    facts = Facts(project_path=".")
    facts.files = [
        "app/Domains/Admin/Actions/RecordAdminChangeAction.php",
        "app/Domains/Auth/Actions/RegisterUserAction.php",
        "app/Services/MatchLifecycleService.php",
    ]
    facts.classes.extend(
        [
            ClassInfo(
                name="RecordAdminChangeAction",
                fqcn="App\\Domains\\Admin\\Actions\\RecordAdminChangeAction",
                file_path="app/Domains/Admin/Actions/RecordAdminChangeAction.php",
                file_hash="a1",
                line_start=1,
                line_end=20,
            ),
            ClassInfo(
                name="RegisterUserAction",
                fqcn="App\\Domains\\Auth\\Actions\\RegisterUserAction",
                file_path="app/Domains/Auth/Actions/RegisterUserAction.php",
                file_hash="a2",
                line_start=1,
                line_end=20,
            ),
            ClassInfo(
                name="MatchLifecycleService",
                fqcn="App\\Services\\MatchLifecycleService",
                file_path="app/Services/MatchLifecycleService.php",
                file_hash="svc",
                line_start=1,
                line_end=60,
            ),
        ]
    )
    facts.methods.append(
        MethodInfo(
            name="execute",
            class_name="MatchLifecycleService",
            class_fqcn="App\\Services\\MatchLifecycleService",
            file_path="app/Services/MatchLifecycleService.php",
            file_hash="svc",
            line_start=10,
            line_end=30,
            loc=21,
            visibility="public",
        )
    )

    findings = ActionClassSuggestionRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_transaction_required_for_multi_write_skips_action_delegating_orchestrator():
    facts = Facts(project_path=".")
    facts.methods.append(
        MethodInfo(
            name="createRoom",
            class_name="RoomController",
            class_fqcn="App\\Http\\Controllers\\RoomController",
            file_path="app/Http/Controllers/RoomController.php",
            file_hash="deadbeef",
            line_start=10,
            line_end=40,
            loc=31,
            call_sites=[
                "$room = $this->createRoomWithMatchAction->execute($dto);",
                "$this->auditTrail->record($room);",
            ],
        )
    )
    facts.queries.extend(
        [
            QueryUsage(
                file_path="app/Http/Controllers/RoomController.php",
                line_number=20,
                method_name="createRoom",
                model="Room",
                method_chain="create",
            ),
            QueryUsage(
                file_path="app/Http/Controllers/RoomController.php",
                line_number=21,
                method_name="createRoom",
                model="Match",
                method_chain="create",
            ),
        ]
    )

    findings = TransactionRequiredForMultiWriteRule(RuleConfig()).run(facts, project_type="laravel_api").findings
    assert findings == []


def test_too_many_dependencies_skips_service_coordinator_facade():
    facts = Facts(project_path=".")
    facts.methods.append(
        MethodInfo(
            name="__construct",
            class_name="GameServer",
            class_fqcn="App\\Services\\Game\\GameServer",
            file_path="app/Services/Game/GameServer.php",
            file_hash="deadbeef",
            line_start=23,
            line_end=31,
            loc=9,
            parameters=[
                "GameServerQueueServiceInterface $queue",
                "GameServerRedisCircuitBreaker $redisCircuitBreaker",
                "GameSocketTokenServiceInterface $tokenService",
                "GameSocketCommandServiceInterface $commandService",
                "SessionVisibilityServiceInterface $sessionVisibility",
                "GameServerEventHandler $eventHandler",
                "GameServerConnectionManager $connectionManager",
            ],
        )
    )

    findings = TooManyDependenciesRule(RuleConfig(thresholds={"max_dependencies": 5})).run(
        facts, project_type="laravel_api"
    ).findings
    assert findings == []
