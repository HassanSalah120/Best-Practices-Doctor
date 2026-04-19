from __future__ import annotations

from pathlib import Path

from core.ruleset import RuleConfig
from rules.laravel.controller_query_direct import ControllerQueryDirectRule
from rules.laravel.controller_validation_inline import ControllerInlineValidationRule
from rules.laravel.enum_suggestion import EnumSuggestionRule
from rules.laravel.fat_controller import FatControllerRule
from rules.laravel.missing_csrf_token_verification import MissingCsrfTokenVerificationRule
from rules.laravel.signed_routes_missing_signature_middleware import SignedRoutesMissingSignatureMiddlewareRule
from rules.laravel.unsafe_external_redirect import UnsafeExternalRedirectRule
from rules.laravel.unused_service_class import UnusedServiceClassRule
from schemas.facts import (
    ClassConstAccess,
    ClassInfo,
    Facts,
    FqcnReference,
    MethodInfo,
    QueryUsage,
    RouteInfo,
    StringLiteral,
    ValidationUsage,
)
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


def _method(class_name: str, name: str, path: str, *, loc: int = 60, call_sites: list[str] | None = None) -> MethodInfo:
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
    )


def test_unsafe_external_redirect_regression_valid_near_invalid():
    rule = UnsafeExternalRedirectRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
<?php
class BookingRequestService {
    private function redirectToWhatsApp(string $redirectUrl) {
        return redirect()->away($redirectUrl);
    }

    public function build(array $result) {
        $redirectUrl = $this->bookingService->validateAndSanitizeRedirectUrl($result['redirectUrl'] ?? null, ['wa.me']);
        return $this->redirectToWhatsApp($redirectUrl);
    }
}
"""
    near_miss = """
<?php
class CampaignController {
    public function redirect(Request $request) {
        abort_unless($request->hasValidSignature(), 403);
        $targetUrl = (string) $request->get('url');
        return redirect()->away($targetUrl);
    }
}
"""
    invalid = """
<?php
class CampaignController {
    public function redirect() {
        return redirect()->away($targetUrl);
    }
}
"""

    assert rule.analyze_regex("app/Services/BookingRequestService.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Http/Controllers/CampaignController.php", near_miss, facts)) == 1
    assert len(rule.analyze_regex("app/Http/Controllers/CampaignController.php", invalid, facts)) == 1


def test_missing_csrf_token_verification_regression_valid_near_invalid():
    fixture_root = Path(__file__).resolve().parent / "fixtures" / "laravel-context-calibration-csrf-mini"
    rule = MissingCsrfTokenVerificationRule(RuleConfig())

    valid_facts = Facts(project_path=str(fixture_root))
    valid_facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/forgot-password",
            action="PasswordResetLinkController@store",
            file_path="routes/auth-guest.php",
            line_number=16,
            middleware=["guest"],
        )
    )
    assert rule.analyze(valid_facts) == []

    near_miss_facts = Facts(project_path=str(fixture_root))
    near_miss_facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/custom-auth-action",
            action="AuthController@custom",
            file_path="routes/auth-guest.php",
            line_number=22,
            middleware=["guest"],
        )
    )
    assert rule.analyze(near_miss_facts) == []

    invalid_facts = Facts(project_path=".")
    invalid_facts.routes.append(
        RouteInfo(
            method="POST",
            uri="/profile/update",
            action="ProfileController@update",
            file_path="routes/web.php",
            line_number=12,
            middleware=["auth"],
        )
    )
    assert len(rule.analyze(invalid_facts)) == 1


def test_unused_service_class_regression_valid_near_invalid():
    rule = UnusedServiceClassRule(RuleConfig())

    valid = Facts(project_path=".")
    valid.classes.append(
        ClassInfo(
            name="RoleAssignmentService",
            fqcn="App\\Services\\Game\\RoleAssignmentService",
            file_path="app/Services/Game/RoleAssignmentService.php",
            file_hash="svc",
            line_start=1,
            line_end=30,
            implements=["App\\Services\\Game\\Contracts\\RoleAssignmentServiceInterface"],
        )
    )
    valid.fqcn_references.append(
        FqcnReference(
            file_path="app/Actions/Game/StartRoundAction.php",
            line_number=8,
            fqcn="App\\Services\\Game\\Contracts\\RoleAssignmentServiceInterface",
            kind="type",
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.classes.append(
        ClassInfo(
            name="StateBroadcastService",
            fqcn="App\\Services\\Game\\StateBroadcastService",
            file_path="app/Services/Game/StateBroadcastService.php",
            file_hash="svc",
            line_start=1,
            line_end=40,
        )
    )
    near_miss.class_const_accesses.append(
        ClassConstAccess(
            file_path="app/Providers/AppServiceProvider.php",
            line_number=21,
            expression="StateBroadcastContract::class, StateBroadcastService::class",
        )
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.classes.append(
        ClassInfo(
            name="UnusedService",
            fqcn="App\\Services\\UnusedService",
            file_path="app/Services/UnusedService.php",
            file_hash="svc",
            line_start=1,
            line_end=20,
        )
    )
    assert len(rule.analyze(invalid)) == 1


def test_enum_suggestion_regression_valid_near_invalid():
    rule = EnumSuggestionRule(RuleConfig())

    valid = Facts(project_path=".")
    valid.string_literals.extend(
        [
            StringLiteral(value="first_name", occurrences=[("app/Repositories/UserRepository.php", 10, "column")]),
            StringLiteral(value="last_name", occurrences=[("app/Repositories/UserRepository.php", 11, "column")]),
            StringLiteral(value="email", occurrences=[("app/Repositories/UserRepository.php", 12, "column")]),
        ]
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.string_literals.extend(
        [
            StringLiteral(
                value="Compact",
                occurrences=[("resources/js/pages/Admin.tsx", 10, "labels"), ("resources/js/pages/Users.tsx", 24, "labels")],
            ),
            StringLiteral(
                value="Expanded",
                occurrences=[("resources/js/pages/Admin.tsx", 11, "labels"), ("resources/js/pages/Users.tsx", 25, "labels")],
            ),
            StringLiteral(
                value="Detailed",
                occurrences=[("resources/js/pages/Admin.tsx", 12, "labels"), ("resources/js/pages/Users.tsx", 26, "labels")],
            ),
        ]
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.string_literals.extend(
        [
            StringLiteral(
                value="pending",
                occurrences=[("app/Services/BillingService.php", 10, "status"), ("app/Actions/InvoiceAction.php", 12, "status")],
            ),
            StringLiteral(
                value="approved",
                occurrences=[("app/Services/BillingService.php", 18, "status"), ("app/Actions/InvoiceAction.php", 21, "status")],
            ),
            StringLiteral(
                value="rejected",
                occurrences=[("app/Services/BillingService.php", 25, "status"), ("app/Actions/InvoiceAction.php", 29, "status")],
            ),
        ]
    )
    assert len(rule.analyze(invalid)) >= 1


def test_controller_query_direct_regression_valid_near_invalid():
    rule = ControllerQueryDirectRule(RuleConfig())
    controller = _controller("ReportsController", "app/Http/Controllers/ReportsController.php")

    valid = Facts(project_path=".")
    valid.controllers.append(controller)
    valid.methods.append(
        _method(
            "ReportsController",
            "index",
            controller.file_path,
            loc=24,
            call_sites=["$result = $this->reportService->execute($request)"],
        )
    )
    valid.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=18,
            method_name="index",
            model="Report",
            method_chain="query->paginate",
            query_type="select",
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.controllers.append(controller)
    near_miss.methods.append(_method("ReportsController", "export", controller.file_path, loc=42))
    near_miss.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=28,
            method_name="export",
            model="Report",
            method_chain="query->get",
            query_type="select",
        )
    )
    assert len(rule.analyze(near_miss)) == 1

    invalid = Facts(project_path=".")
    invalid.controllers.append(controller)
    invalid.methods.append(_method("ReportsController", "store", controller.file_path, loc=58))
    invalid.queries.extend(
        [
            QueryUsage(
                file_path=controller.file_path,
                line_number=22,
                method_name="store",
                model="Report",
                method_chain="query->first",
                query_type="select",
            ),
            QueryUsage(
                file_path=controller.file_path,
                line_number=34,
                method_name="store",
                model="User",
                method_chain="query->get",
                query_type="select",
            ),
        ]
    )
    assert len(rule.analyze(invalid)) == 1


def test_fat_controller_regression_valid_near_invalid():
    rule = FatControllerRule(RuleConfig())
    controller = _controller("BillingController", "app/Http/Controllers/BillingController.php")

    valid = Facts(project_path=".")
    method_valid = _method(
        "BillingController",
        "store",
        controller.file_path,
        loc=48,
        call_sites=["$validated = $request->validate(['email' => ['required', 'email']])", "$this->billingAction->execute($validated)"],
    )
    valid.controllers.append(controller)
    valid.methods.append(method_valid)
    valid.validations.append(
        ValidationUsage(
            file_path=controller.file_path,
            line_number=18,
            method_name="store",
            validation_type="inline",
            rules={"email": ["required", "email"]},
        )
    )
    valid.queries.append(
        QueryUsage(
            file_path=controller.file_path,
            line_number=20,
            method_name="store",
            model="Invoice",
            method_chain="find",
            query_type="select",
        )
    )
    valid_metrics = {
        method_valid.method_fqn: MethodMetrics(
            method_fqn=method_valid.method_fqn,
            file_path=method_valid.file_path,
            cyclomatic_complexity=3,
            conditional_count=1,
            query_count=1,
            validation_count=1,
            loop_count=0,
            has_business_logic=False,
        )
    }
    assert rule.analyze(valid, valid_metrics) == []

    near_miss = Facts(project_path=".")
    method_near = _method(
        "BillingController",
        "store",
        controller.file_path,
        loc=70,
        call_sites=["$request->validate(['a' => 'required'])", "$this->billingAction->execute($payload)"],
    )
    near_miss.controllers.append(controller)
    near_miss.methods.append(method_near)
    near_miss.validations.append(
        ValidationUsage(
            file_path=controller.file_path,
            line_number=19,
            method_name="store",
            validation_type="inline",
            rules={"email": ["required", "email"]},
        )
    )
    near_miss.queries.extend(
        [
            QueryUsage(
                file_path=controller.file_path,
                line_number=20,
                method_name="store",
                model="Invoice",
                method_chain="query->get",
                query_type="select",
            ),
            QueryUsage(
                file_path=controller.file_path,
                line_number=24,
                method_name="store",
                model="Payment",
                method_chain="query->get",
                query_type="select",
            ),
        ]
    )
    assert len(rule.analyze(near_miss, {})) == 1

    invalid = Facts(project_path=".")
    method_invalid = _method(
        "BillingController",
        "refund",
        controller.file_path,
        loc=88,
        call_sites=["$request->validate(['reason' => 'required'])", "$payment = Payment::query()->first()"],
    )
    invalid.controllers.append(controller)
    invalid.methods.append(method_invalid)
    invalid.validations.append(
        ValidationUsage(
            file_path=controller.file_path,
            line_number=30,
            method_name="refund",
            validation_type="inline",
            rules={"reason": ["required"], "amount": ["required", "numeric"]},
        )
    )
    invalid.queries.extend(
        [
            QueryUsage(
                file_path=controller.file_path,
                line_number=33,
                method_name="refund",
                model="Payment",
                method_chain="query->first",
                query_type="select",
            ),
            QueryUsage(
                file_path=controller.file_path,
                line_number=40,
                method_name="refund",
                model="Invoice",
                method_chain="query->update",
                query_type="update",
            ),
        ]
    )
    invalid_metrics = {
        method_invalid.method_fqn: MethodMetrics(
            method_fqn=method_invalid.method_fqn,
            file_path=method_invalid.file_path,
            cyclomatic_complexity=9,
            conditional_count=5,
            query_count=2,
            validation_count=1,
            loop_count=1,
            has_business_logic=True,
            business_logic_confidence=0.86,
        )
    }
    assert len(rule.analyze(invalid, invalid_metrics)) == 1


def test_controller_inline_validation_regression_valid_near_invalid():
    rule = ControllerInlineValidationRule(RuleConfig())

    valid = Facts(project_path=".")
    auth_controller = _controller("LoginController", "app/Http/Controllers/Auth/LoginController.php")
    valid.controllers.append(auth_controller)
    valid.methods.append(_method("LoginController", "store", auth_controller.file_path, loc=20))
    valid.validations.append(
        ValidationUsage(
            file_path=auth_controller.file_path,
            line_number=14,
            method_name="store",
            validation_type="inline",
            rules={"email": ["required", "email"], "password": ["required"]},
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    patient_controller = _controller("PatientController", "app/Http/Controllers/PatientController.php")
    near_miss.controllers.append(patient_controller)
    near_method = _method(
        "PatientController",
        "store",
        patient_controller.file_path,
        loc=58,
        call_sites=["$this->patientAction->execute($payload)"],
    )
    near_miss.methods.append(near_method)
    near_miss.validations.append(
        ValidationUsage(
            file_path=patient_controller.file_path,
            line_number=22,
            method_name="store",
            validation_type="inline",
            rules={
                "email": ["required", "email"],
                "name": ["required"],
                "phone": ["required"],
            },
        )
    )
    assert len(rule.analyze(near_miss)) == 1

    invalid = Facts(project_path=".")
    invalid.controllers.append(patient_controller)
    invalid.methods.append(_method("PatientController", "update", patient_controller.file_path, loc=72))
    invalid.validations.append(
        ValidationUsage(
            file_path=patient_controller.file_path,
            line_number=35,
            method_name="update",
            validation_type="inline",
            rules={
                "email": ["required", "email", "unique:users,email"],
                "name": ["required", "string", "max:255"],
                "status": ["required", "in:active,inactive,pending"],
            },
        )
    )
    assert len(rule.analyze(invalid)) == 1


def test_signed_routes_missing_signature_middleware_regression_valid_near_invalid():
    rule = SignedRoutesMissingSignatureMiddlewareRule(RuleConfig())

    valid = Facts(project_path=".")
    valid.routes.append(
        RouteInfo(
            method="GET",
            uri="/email/verify",
            controller="Auth\\EmailVerificationController",
            action="show",
            middleware=["web", "auth", "verified"],
            file_path="routes/web.php",
            line_number=16,
        )
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.routes.append(
        RouteInfo(
            method="GET",
            uri="/campaigns/redirect/{slug}",
            controller="CampaignController",
            action="redirect",
            middleware=["web"],
            file_path="routes/web.php",
            line_number=22,
        )
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.routes.append(
        RouteInfo(
            method="GET",
            uri="/campaigns/track/{token}",
            controller="CampaignController",
            action="track",
            middleware=["web"],
            file_path="routes/web.php",
            line_number=32,
        )
    )
    assert len(rule.analyze(invalid)) == 1
