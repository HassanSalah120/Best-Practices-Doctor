from core.ruleset import RuleConfig
from rules.laravel.user_model_missing_must_verify_email import UserModelMissingMustVerifyEmailRule
from rules.laravel.registration_missing_registered_event import RegistrationMissingRegisteredEventRule
from rules.laravel.sensitive_routes_missing_verified_middleware import SensitiveRoutesMissingVerifiedMiddlewareRule
from rules.laravel.tenant_access_middleware_missing import TenantAccessMiddlewareMissingRule
from rules.laravel.signed_routes_missing_signature_middleware import SignedRoutesMissingSignatureMiddlewareRule
from rules.laravel.unsafe_external_redirect import UnsafeExternalRedirectRule
from schemas.facts import Facts, RouteInfo


def test_user_model_missing_must_verify_email_flags_plain_authenticatable_user():
    rule = UserModelMissingMustVerifyEmailRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
namespace App\\Models;
use Illuminate\\Foundation\\Auth\\User as Authenticatable;
class User extends Authenticatable
{
}
"""

    findings = rule.analyze_regex("app/Models/User.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "user-model-missing-must-verify-email"


def test_user_model_missing_must_verify_email_skips_verified_user_model():
    rule = UserModelMissingMustVerifyEmailRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
namespace App\\Models;
use Illuminate\\Contracts\\Auth\\MustVerifyEmail;
use Illuminate\\Foundation\\Auth\\User as Authenticatable;
class User extends Authenticatable implements MustVerifyEmail
{
}
"""

    findings = rule.analyze_regex("app/Models/User.php", content, facts)
    assert findings == []


def test_registration_missing_registered_event_flags_onboarding_user_creation():
    rule = RegistrationMissingRegisteredEventRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class OnboardingController {
    public function store() {
        $user = User::create(['email' => $request->email]);
        return redirect('/billing');
    }
}
"""

    findings = rule.analyze_regex("app/Http/Controllers/OnboardingController.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "registration-missing-registered-event"


def test_registration_missing_registered_event_skips_when_registered_is_dispatched():
    rule = RegistrationMissingRegisteredEventRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class OnboardingController {
    public function store() {
        $user = User::create(['email' => $request->email]);
        event(new Registered($user));
        return redirect('/billing');
    }
}
"""

    findings = rule.analyze_regex("app/Http/Controllers/OnboardingController.php", content, facts)
    assert findings == []


def test_registration_missing_registered_event_skips_contract_interfaces_even_with_create_examples():
    rule = RegistrationMissingRegisteredEventRule(RuleConfig(thresholds={"require_self_service_context": False}))
    facts = Facts(project_path=".")
    content = """
<?php
namespace App\\Services\\Contracts;

/**
 * Implementation note: uses User::create($payload) and dispatches Registered downstream.
 */
interface UserCommandServiceInterface {
    public function register(array $payload): mixed;
}
"""

    findings = rule.analyze_regex("app/Services/Contracts/UserCommandServiceInterface.php", content, facts)
    assert findings == []


def test_sensitive_routes_missing_verified_middleware_flags_sensitive_web_route():
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/billing/portal",
            controller="BillingPortalController",
            action="show",
            middleware=["web", "auth"],
            file_path="routes/web.php",
            line_number=12,
        )
    )

    findings = SensitiveRoutesMissingVerifiedMiddlewareRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert len(findings) == 1
    assert findings[0].rule_id == "sensitive-routes-missing-verified-middleware"


def test_sensitive_routes_missing_verified_middleware_skips_verified_route():
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/billing/portal",
            controller="BillingPortalController",
            action="show",
            middleware=["web", "auth", "verified"],
            file_path="routes/web.php",
            line_number=12,
        )
    )

    findings = SensitiveRoutesMissingVerifiedMiddlewareRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert findings == []


def test_tenant_access_middleware_missing_flags_clinic_route_without_access_guard():
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/clinic/patients",
            controller="Clinic\\PatientsController",
            action="index",
            middleware=["web", "auth", "verified"],
            file_path="routes/web.php",
            line_number=20,
        )
    )

    findings = TenantAccessMiddlewareMissingRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert len(findings) == 1
    assert findings[0].rule_id == "tenant-access-middleware-missing"


def test_tenant_access_middleware_missing_skips_clinic_route_with_access_guard():
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/clinic/patients",
            controller="Clinic\\PatientsController",
            action="index",
            middleware=["web", "auth", "verified", "clinic_access"],
            file_path="routes/web.php",
            line_number=20,
        )
    )

    findings = TenantAccessMiddlewareMissingRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert findings == []


def test_tenant_access_middleware_missing_skips_non_tenant_account_routes():
    facts = Facts(project_path=".")
    facts.files = [
        "app/Http/Controllers/Account/ProfileController.php",
        "app/Models/User.php",
    ]
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/account/profile",
            controller="Account\\ProfileController",
            action="show",
            middleware=["web", "auth", "verified"],
            file_path="routes/web.php",
            line_number=20,
        )
    )

    findings = TenantAccessMiddlewareMissingRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert findings == []


def test_signed_routes_missing_signature_middleware_flags_track_route():
    facts = Facts(project_path=".")
    facts.routes.append(
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

    findings = SignedRoutesMissingSignatureMiddlewareRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert len(findings) == 1
    assert findings[0].rule_id == "signed-routes-missing-signature-middleware"


def test_signed_routes_missing_signature_middleware_skips_signed_route():
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/campaigns/track/{token}",
            controller="CampaignController",
            action="track",
            middleware=["web", "signed"],
            file_path="routes/web.php",
            line_number=32,
        )
    )

    findings = SignedRoutesMissingSignatureMiddlewareRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert findings == []


def test_signed_routes_missing_signature_middleware_skips_internal_verified_flow():
    facts = Facts(project_path=".")
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/email/verify",
            controller="Auth\\EmailVerificationController",
            action="show",
            middleware=["web", "auth", "verified"],
            file_path="routes/web.php",
            line_number=32,
        )
    )

    findings = SignedRoutesMissingSignatureMiddlewareRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert findings == []


def test_unsafe_external_redirect_flags_variable_away_redirect():
    rule = UnsafeExternalRedirectRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class CampaignController {
    public function redirect() {
        return redirect()->away($targetUrl);
    }
}
"""

    findings = rule.analyze_regex("app/Http/Controllers/CampaignController.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "unsafe-external-redirect"


def test_unsafe_external_redirect_skips_trusted_tenant_url_builder():
    rule = UnsafeExternalRedirectRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class TwoFactorEmailController {
    public function create(Request $request) {
        $dashboardUrl = $this->tenantDomains->clinicUrl($clinic, '/dashboard', $request);
        return redirect()->to($dashboardUrl);
    }
}
"""

    findings = rule.analyze_regex("app/Http/Controllers/Auth/TwoFactorEmailController.php", content, facts)
    assert findings == []


def test_unsafe_external_redirect_skips_resolved_dashboard_url_action():
    rule = UnsafeExternalRedirectRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class TwoFactorEmailController {
    public function create(Request $request) {
        $dashboardUrl = $this->resolveDashboardUrl->execute($request);

        if (session('two_factor_email_verified')) {
            return redirect()->to($dashboardUrl);
        }

        return redirect()->to($dashboardUrl);
    }
}
"""

    findings = rule.analyze_regex("app/Http/Controllers/Auth/TwoFactorEmailController.php", content, facts)
    assert findings == []


def test_unsafe_external_redirect_skips_method_scoped_redirect_validation():
    rule = UnsafeExternalRedirectRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class PatientFinancialController {
    public function initiatePayment(Request $request) {
        $redirectUrl = $this->initiatePayment->execute($request);

        if (! is_string($redirectUrl)) {
            abort(422);
        }

        if (! $this->redirectValidator->isAllowed($redirectUrl)) {
            abort(422);
        }

        return redirect()->away($redirectUrl);
    }
}
"""

    findings = rule.analyze_regex("app/Http/Controllers/PatientFinancialController.php", content, facts)
    assert findings == []


def test_unsafe_external_redirect_skips_redirect_from_validating_initiate_payment_action():
    rule = UnsafeExternalRedirectRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class PatientFinancialController {
    public function initiateOnlinePayment(Request $request) {
        $redirectUrl = $this->initiatePayment->execute($request, $invoice);
        return redirect()->away($redirectUrl);
    }
}
"""

    findings = rule.analyze_regex("app/Http/Controllers/PatientFinancialController.php", content, facts)
    assert findings == []


def test_unsafe_external_redirect_skips_booking_service_redirect_after_sanitize_helper():
    rule = UnsafeExternalRedirectRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class BookingRequestService {
    private const ALLOWED_EXTERNAL_HOSTS = ['wa.me'];

    public function buildBookingResponse(array $result) {
        $redirectUrl = $this->bookingService->validateAndSanitizeRedirectUrl(
            $result['redirectUrl'] ?? null,
            self::ALLOWED_EXTERNAL_HOSTS
        );

        return $this->redirectToWhatsApp($redirectUrl);
    }

    private function redirectToWhatsApp(string $redirectUrl) {
        return redirect()->away($redirectUrl);
    }
}
"""

    findings = rule.analyze_regex("app/Services/BookingRequestService.php", content, facts)
    assert findings == []


def test_unsafe_external_redirect_still_flags_signed_request_driven_redirect():
    rule = UnsafeExternalRedirectRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class CampaignController {
    public function redirect(Request $request) {
        abort_unless($request->hasValidSignature(), 403);
        $targetUrl = (string) $request->get('url');
        return redirect()->away($targetUrl);
    }
}
"""

    findings = rule.analyze_regex("app/Http/Controllers/CampaignController.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "unsafe-external-redirect"
