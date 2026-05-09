from __future__ import annotations

from core.ruleset import RuleConfig
from rules.laravel.console_command_missing_tenant_scope import ConsoleCommandMissingTenantScopeRule
from rules.laravel.forced_login_without_authorization import ForcedLoginWithoutAuthorizationRule
from rules.laravel.high_privilege_action_missing_authorization import (
    HighPrivilegeActionMissingAuthorizationRule,
)
from rules.laravel.missing_null_guard_after_relation_load import (
    MissingNullGuardAfterRelationLoadRule,
)
from rules.laravel.tenant_scope_enforcement import TenantScopeEnforcementRule
from rules.laravel.unsafe_redirect import UnsafeRedirectRule
from rules.laravel.url_validation_protocol_bypass import UrlValidationProtocolBypassRule
from rules.laravel.webhook_signature_parameter_unused import WebhookSignatureParameterUnusedRule
from schemas.facts import Facts


def test_webhook_signature_parameter_unused_valid_invalid_fp() -> None:
    rule = WebhookSignatureParameterUnusedRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
<?php
class PaymentWebhookAction
{
    public function execute(array $payload, ?string $hmac): bool
    {
        $this->signatureService->validateHmac($payload, $hmac);
        return true;
    }
}
"""
    invalid = """
<?php
class PaymentWebhookAction
{
    public function execute(array $payload, ?string $hmac): bool
    {
        $eventId = $payload['obj']['id'];
        $this->processPayment($eventId);
        return true;
    }
}
"""
    fp = """
<?php
class PaymentWebhookAction
{
    public function execute(array $payload, ?string $hmac): bool
    {
        return $this->validator->check($payload, $hmac);
    }
}
"""

    assert rule.analyze_regex("app/Actions/Billing/PaymentWebhookAction.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Actions/Billing/PaymentWebhookAction.php", invalid, facts)) == 1
    assert rule.analyze_regex("app/Actions/Billing/PaymentWebhookAction.php", fp, facts) == []


def test_forced_login_without_authorization_valid_invalid_fp() -> None:
    rule = ForcedLoginWithoutAuthorizationRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
<?php
class DemoController
{
    public function enter(Request $request, Clinic $clinic)
    {
        $this->authorize('access', $clinic);
        Auth::guard('web')->login($demoUser);
    }
}
"""
    invalid = """
<?php
class DemoController
{
    public function enter(Request $request, Clinic $clinic)
    {
        abort_if(! $clinic->isDemo(), 404);
        Auth::guard('web')->login($demoUser);
    }
}
"""
    fp = """
<?php
class LoginController
{
    public function login(Request $request)
    {
        Auth::login($user);
    }
}
"""

    assert rule.analyze_regex("app/Http/Controllers/DemoController.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Http/Controllers/DemoController.php", invalid, facts)) == 1
    assert rule.analyze_regex("app/Http/Controllers/Auth/LoginController.php", fp, facts) == []


def test_forced_login_without_authorization_allows_guest_entry_flows() -> None:
    rule = ForcedLoginWithoutAuthorizationRule(RuleConfig())
    facts = Facts(project_path=".")

    create_clinic = """
<?php
class CreateClinicController
{
    use EnsuresGuestOnly;

    public function store(StoreCreateClinicRequest $request)
    {
        $this->ensureGuest('Already authenticated');
        $result = $this->clinicService->createClinicWithUser($request->validated());
        Auth::login($result['user']);
    }
}
"""
    demo = """
<?php
class DemoController
{
    public function enter(Request $request, Clinic $clinic)
    {
        abort_if(Auth::check(), 403, 'Already authenticated');
        abort_if(! $clinic->isDemo(), 404);
        $demoUser = $this->demoService->getOrCreateDemoUser($clinic);
        Auth::guard('web')->login($demoUser);
    }
}
"""

    assert rule.analyze_regex("app/Http/Controllers/Auth/CreateClinicController.php", create_clinic, facts) == []
    assert rule.analyze_regex("app/Http/Controllers/DemoController.php", demo, facts) == []


def test_console_command_missing_tenant_scope_valid_invalid_fp() -> None:
    rule = ConsoleCommandMissingTenantScopeRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
<?php
class SendInvoiceRemindersCommand extends Command
{
    public function handle(): void
    {
        Invoice::where('clinic_id', $clinicId)->whereIn('status', ['overdue'])->get();
    }
}
"""
    invalid = """
<?php
class SendInvoiceRemindersCommand extends Command
{
    public function handle(): void
    {
        Invoice::whereIn('status', ['overdue'])->whereDate('due_date', '<=', now())->get();
    }
}
"""
    fp = """
<?php
class SyncPermissionsCommand extends Command
{
    public function handle(): void
    {
        Permission::where('guard_name', 'web')->get();
    }
}
"""

    assert rule.analyze_regex("app/Console/Commands/SendInvoiceRemindersCommand.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Console/Commands/SendInvoiceRemindersCommand.php", invalid, facts)) == 1
    assert rule.analyze_regex("app/Console/Commands/SyncPermissionsCommand.php", fp, facts) == []


def test_console_command_missing_tenant_scope_allows_platform_level_null_clinic() -> None:
    rule = ConsoleCommandMissingTenantScopeRule(RuleConfig())
    facts = Facts(project_path=".")

    content = """
<?php
class RetryFailedWebhooksCommand extends Command
{
    public function handle(): void
    {
        WebhookEvent::whereNull('clinic_id')->where('status', 'failed')->get();
    }
}
"""

    assert rule.analyze_regex("app/Console/Commands/RetryFailedWebhooksCommand.php", content, facts) == []


def test_high_privilege_action_missing_authorization_valid_invalid_fp() -> None:
    rule = HighPrivilegeActionMissingAuthorizationRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
<?php
class EmergencyAccessService
{
    public function impersonate(User $user): void
    {
        Gate::allows('impersonate', $user) || abort(403);
        Auth::loginUsingId($user->id);
    }
}
"""
    invalid = """
<?php
class EmergencyAccessService
{
    public function start(Request $request): void
    {
        $request->session()->put([
            'emergency_access_active' => true,
        ]);
    }
}
"""
    fp = """
<?php
class EmergencyAccessServiceTest extends TestCase
{
    public function test_start(): void
    {
        $request->session()->put(['emergency_access_active' => true]);
    }
}
"""

    assert rule.analyze_regex("app/Services/EmergencyAccessService.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Services/EmergencyAccessService.php", invalid, facts)) == 1
    assert rule.analyze_regex("tests/Feature/EmergencyAccessServiceTest.php", fp, facts) == []


def test_high_privilege_action_missing_authorization_avoids_architecture_false_positives() -> None:
    rule = HighPrivilegeActionMissingAuthorizationRule(RuleConfig())
    facts = Facts(project_path=".")

    impersonation_controller = """
<?php
class ImpersonationController
{
    public function impersonate(User $user): RedirectResponse
    {
        if (! auth()->user() || ! auth()->user()->isSystemAdmin()) {
            abort(403, 'Unauthorized');
        }
        return $this->service->impersonate($user);
    }
}
"""
    dto = """
<?php
class InertiaUserDTO
{
    public function __construct(
        public ?InertiaImpersonationDTO $impersonation = null,
    ) {}
}
"""
    route_registrar = """
<?php
class BillingPortalRegistrar
{
    public function __invoke(): void
    {
        Route::post('/impersonate/{user}', [ImpersonationController::class, 'impersonate'])
            ->middleware('role:System Admin');
    }
}
"""

    assert rule.analyze_regex("app/Http/Controllers/ImpersonationController.php", impersonation_controller, facts) == []
    assert rule.analyze_regex("app/DTOs/InertiaUserDTO.php", dto, facts) == []
    assert rule.analyze_regex("app/Http/RouteRegistrars/BillingPortalRegistrar.php", route_registrar, facts) == []


def test_high_privilege_action_missing_authorization_allows_onboarding_login_and_session_cleanup() -> None:
    rule = HighPrivilegeActionMissingAuthorizationRule(RuleConfig())
    facts = Facts(project_path=".")

    onboarding = """
<?php
class OnboardingController extends BaseController
{
    use EnsuresGuestOnly;

    public function store(StoreOnboardingRequest $request): RedirectResponse
    {
        $this->ensureGuest('Already authenticated');
        $userId = $this->service->onboard($request->validated());
        Auth::loginUsingId($userId);
    }
}
"""
    cleanup = """
<?php
class EmergencyAccessService
{
    public function stop(Request $request): void
    {
        $request->session()->forget([
            'emergency_access_active',
            'emergency_access_until',
            'emergency_access_reason',
        ]);
    }
}
"""

    assert rule.analyze_regex("app/Http/Controllers/Auth/OnboardingController.php", onboarding, facts) == []
    assert rule.analyze_regex("app/Services/EmergencyAccessService.php", cleanup, facts) == []


def test_url_validation_protocol_bypass_valid_invalid_fp() -> None:
    rule = UrlValidationProtocolBypassRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
<?php
class StoreCampaignRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'redirect_url' => ['nullable', 'string', 'url', 'starts_with:https,http'],
        ];
    }
}
"""
    invalid = """
<?php
class StoreCampaignRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'redirect_url' => ['nullable', 'string', 'url'],
        ];
    }
}
"""
    fp = """
<?php
class StoreProfileRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'avatar_url' => ['nullable', 'string', 'url'],
        ];
    }
}
"""

    assert rule.analyze_regex("app/Http/Requests/StoreCampaignRequest.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Http/Requests/StoreCampaignRequest.php", invalid, facts)) == 1
    assert rule.analyze_regex("app/Http/Requests/StoreProfileRequest.php", fp, facts) == []


def test_missing_null_guard_after_relation_load_valid_invalid_fp() -> None:
    rule = MissingNullGuardAfterRelationLoadRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = """
<?php
class WebhookEventService
{
    public function process(Event $event): void
    {
        $event->loadMissing('clinic');
        abort_if(! $event->clinic, 422, 'Clinic missing.');
        $this->handlerRegistry->process($event);
    }
}
"""
    invalid = """
<?php
class WebhookEventService
{
    public function process(Event $event): void
    {
        $event->loadMissing('clinic');
        $clinicId = $event->clinic->id;
        $this->handlerRegistry->process($event);
    }
}
"""
    fp = """
<?php
class WebhookEventService
{
    public function process(Event $event): void
    {
        $event->loadMissing('clinic');
        $clinic = $event->clinic ?? null;
        $this->handlerRegistry->process($event);
    }
}
"""

    assert rule.analyze_regex("app/Services/WebhookEventService.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Services/WebhookEventService.php", invalid, facts)) == 1
    assert rule.analyze_regex("app/Services/WebhookEventService.php", fp, facts) == []


def test_tenant_scope_enforcement_detects_unscoped_find_or_fail_extension() -> None:
    rule = TenantScopeEnforcementRule(RuleConfig())
    facts = Facts(project_path=".")

    invalid = """
<?php
class InventoryCountService
{
    public function show(string $countId): InventoryCount
    {
        return InventoryCount::findOrFail($countId);
    }
}
"""
    valid = """
<?php
class InventoryCountService
{
    public function show(string $clinicId, string $countId): InventoryCount
    {
        return InventoryCount::where('clinic_id', $clinicId)->findOrFail($countId);
    }
}
"""

    assert len(rule.analyze_regex("app/Services/InventoryCountService.php", invalid, facts)) == 1
    assert rule.analyze_regex("app/Services/InventoryCountService.php", valid, facts) == []


def test_tenant_scope_enforcement_allows_global_legal_page_model() -> None:
    rule = TenantScopeEnforcementRule(RuleConfig())
    facts = Facts(project_path=".")

    content = """
<?php
class LegalPageService
{
    public function updatePage(string $id): LegalPage
    {
        return LegalPage::findOrFail($id);
    }
}
"""

    assert rule.analyze_regex("app/Services/LegalPageService.php", content, facts) == []


def test_unsafe_redirect_detects_self_approving_allowlist_extension() -> None:
    rule = UnsafeRedirectRule(RuleConfig())
    facts = Facts(project_path=".")

    invalid = """
<?php
class CampaignController
{
    public function redirect(string $url)
    {
        $host = parse_url($url, PHP_URL_HOST);
        $extraAllowedHosts[] = $host;
        return $this->redirector->safeRedirect($url, $extraAllowedHosts);
    }
}
"""
    valid = """
<?php
class CampaignController
{
    public function redirect(string $url)
    {
        $allowedHosts = ['myapp.com'];
        return $this->redirector->safeRedirect($url, $allowedHosts);
    }
}
"""

    assert len(rule.analyze_regex("app/Http/Controllers/CampaignController.php", invalid, facts)) == 1
    assert rule.analyze_regex("app/Http/Controllers/CampaignController.php", valid, facts) == []
