from core.ruleset import RuleConfig
from rules.laravel.policy_coverage_on_mutations import PolicyCoverageOnMutationsRule
from rules.laravel.authorization_bypass_risk import AuthorizationBypassRiskRule
from rules.laravel.transaction_required_for_multi_write import TransactionRequiredForMultiWriteRule
from rules.laravel.tenant_scope_enforcement import TenantScopeEnforcementRule
from schemas.facts import Facts, ClassInfo, MethodInfo, QueryUsage, RouteInfo


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
