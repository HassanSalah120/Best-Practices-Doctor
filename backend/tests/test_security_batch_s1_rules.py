from __future__ import annotations

from core.ruleset import RuleConfig
from rules.laravel.archive_upload_zip_slip_risk import ArchiveUploadZipSlipRiskRule
from rules.laravel.idor_risk_missing_ownership_check import IdorRiskMissingOwnershipCheckRule
from rules.laravel.insecure_file_download_response import InsecureFileDownloadResponseRule
from rules.laravel.path_traversal_file_access import PathTraversalFileAccessRule
from rules.laravel.sanctum_token_scope_missing import SanctumTokenScopeMissingRule
from rules.laravel.sensitive_route_rate_limit_missing import SensitiveRouteRateLimitMissingRule
from rules.laravel.session_fixation_regenerate_missing import SessionFixationRegenerateMissingRule
from rules.laravel.ssrf_risk_http_client import SsrfRiskHttpClientRule
from rules.laravel.upload_mime_extension_mismatch import UploadMimeExtensionMismatchRule
from rules.laravel.upload_size_limit_missing import UploadSizeLimitMissingRule
from rules.laravel.webhook_signature_missing import WebhookSignatureMissingRule
from rules.laravel.weak_password_policy_validation import WeakPasswordPolicyValidationRule
from rules.react.client_open_redirect_unvalidated_navigation import ClientOpenRedirectUnvalidatedNavigationRule
from rules.react.insecure_postmessage_origin_wildcard import InsecurePostMessageOriginWildcardRule
from rules.react.token_storage_insecure_localstorage import TokenStorageInsecureLocalStorageRule
from schemas.facts import Facts, MethodInfo, QueryUsage, RouteInfo


def _facts_with_capabilities(**flags: bool) -> Facts:
    facts = Facts(project_path=".")
    payload = {
        key: {
            "enabled": bool(value),
            "confidence": 1.0,
            "source": "explicit",
            "evidence": ["test"],
        }
        for key, value in flags.items()
    }
    facts.project_context.capabilities = dict(payload)
    facts.project_context.backend_capabilities = dict(payload)
    return facts


def _route(method: str, uri: str, controller: str, action: str, middleware: list[str], line: int = 10) -> RouteInfo:
    return RouteInfo(
        method=method,
        uri=uri,
        controller=controller,
        action=action,
        middleware=middleware,
        file_path="routes/api.php" if uri.startswith("api/") else "routes/web.php",
        line_number=line,
    )


def _method(class_name: str, name: str, call_sites: list[str] | None = None, file_path: str | None = None) -> MethodInfo:
    return MethodInfo(
        name=name,
        class_name=class_name,
        class_fqcn=f"App\\Http\\Controllers\\{class_name}",
        file_path=file_path or f"app/Http/Controllers/{class_name}.php",
        file_hash="fixture",
        line_start=10,
        line_end=70,
        call_sites=call_sites or [],
    )


def test_ssrf_risk_http_client_valid_near_invalid():
    rule = SsrfRiskHttpClientRule(
        RuleConfig(thresholds={"require_external_integrations_capability": True, "min_confidence": 0.8})
    )
    facts = _facts_with_capabilities(external_integrations_heavy=True)

    valid = "<?php Http::get(config('services.crm.url').'/status');"
    near_miss = """
<?php
$url = $request->input('url');
$host = parse_url($url, PHP_URL_HOST);
if (! in_array($host, ['api.partner.com'], true)) abort(422);
Http::get($url);
"""
    invalid = "<?php $url = $request->input('url'); Http::get($url);"

    assert rule.analyze_regex("app/Services/SyncService.php", valid, facts) == []
    assert rule.analyze_regex("app/Services/SyncService.php", near_miss, facts) == []
    assert len(rule.analyze_regex("app/Services/SyncService.php", invalid, facts)) == 1


def test_path_traversal_file_access_valid_near_invalid():
    rule = PathTraversalFileAccessRule(RuleConfig(thresholds={"min_confidence": 0.8}))
    facts = Facts(project_path=".")

    valid = "<?php $path = storage_path('reports/final.csv'); file_get_contents($path);"
    near_miss = """
<?php
$path = $request->input('path');
$full = realpath(storage_path('reports/' . basename($path)));
if (! str_starts_with($full, storage_path('reports'))) abort(403);
file_get_contents($full);
"""
    invalid = "<?php $path = $request->input('path'); file_get_contents($path);"

    assert rule.analyze_regex("app/Services/ReportService.php", valid, facts) == []
    assert rule.analyze_regex("app/Services/ReportService.php", near_miss, facts) == []
    assert len(rule.analyze_regex("app/Services/ReportService.php", invalid, facts)) == 1


def test_insecure_file_download_response_valid_near_invalid():
    rule = InsecureFileDownloadResponseRule(
        RuleConfig(thresholds={"require_auth_or_ownership_guard": True, "min_confidence": 0.8})
    )
    facts = Facts(project_path=".")

    valid = "<?php $path = storage_path('exports/report.pdf'); return response()->download($path);"
    near_miss = """
<?php
$path = $request->input('path');
$this->authorize('view', $invoice);
$resolved = realpath(storage_path('invoices/' . basename($path)));
return response()->download($resolved);
"""
    invalid = "<?php $path = $request->input('path'); return response()->download($path);"

    assert rule.analyze_regex("app/Http/Controllers/InvoiceController.php", valid, facts) == []
    assert rule.analyze_regex("app/Http/Controllers/InvoiceController.php", near_miss, facts) == []
    assert len(rule.analyze_regex("app/Http/Controllers/InvoiceController.php", invalid, facts)) == 1


def test_webhook_signature_missing_valid_near_invalid():
    rule = WebhookSignatureMissingRule(
        RuleConfig(thresholds={"require_external_integrations_capability": True, "min_confidence": 0.8})
    )
    facts = _facts_with_capabilities(external_integrations_heavy=True)
    facts.routes = [
        _route("POST", "/webhooks/stripe", "StripeWebhookController", "handle", ["api", "verify.webhook"]),
        _route("POST", "/webhooks/paymob", "PaymobWebhookController", "handle", ["api"]),
        _route("POST", "/webhooks/twilio", "TwilioWebhookController", "handle", ["api"]),
    ]
    facts.methods = [
        _method("StripeWebhookController", "handle", ["$this->processWebhook->execute($payload);"]),
        _method("PaymobWebhookController", "handle", ["$this->validateSignature->execute($payload, $hmac);"]),
        _method("TwilioWebhookController", "handle", ["$this->processWebhook->execute($payload);"]),
    ]

    findings = rule.analyze(facts)
    assert len(findings) == 1
    assert findings[0].context == "POST /webhooks/twilio"


def test_idor_risk_missing_ownership_check_valid_near_invalid():
    rule = IdorRiskMissingOwnershipCheckRule(
        RuleConfig(thresholds={"require_multi_role_portal_capability": True, "min_confidence": 0.75})
    )
    facts = _facts_with_capabilities(multi_role_portal=True)
    facts.routes = [
        _route("GET", "/portal/invoices/{invoice}", "InvoicesController", "showSafe", ["web", "auth"]),
        _route("GET", "/portal/invoices/{invoice}", "InvoicesController", "showScoped", ["web", "auth"]),
        _route("GET", "/portal/invoices/{invoice}", "InvoicesController", "showUnsafe", ["web", "auth"]),
    ]
    facts.methods = [
        _method("InvoicesController", "showSafe", ["$this->authorize('view', $invoice);"]),
        _method("InvoicesController", "showScoped", []),
        _method("InvoicesController", "showUnsafe", []),
    ]
    facts.queries = [
        QueryUsage(
            file_path="app/Http/Controllers/InvoicesController.php",
            line_number=20,
            method_name="showSafe",
            model="Invoice",
            method_chain="findOrFail",
        ),
        QueryUsage(
            file_path="app/Http/Controllers/InvoicesController.php",
            line_number=30,
            method_name="showScoped",
            model="Invoice",
            method_chain="where('user_id', $user->id)->findOrFail",
        ),
        QueryUsage(
            file_path="app/Http/Controllers/InvoicesController.php",
            line_number=40,
            method_name="showUnsafe",
            model="Invoice",
            method_chain="findOrFail",
        ),
    ]

    findings = rule.analyze(facts)
    assert len(findings) == 1
    assert findings[0].context.endswith("::showUnsafe")


def test_sensitive_route_rate_limit_missing_valid_near_invalid():
    rule = SensitiveRouteRateLimitMissingRule(
        RuleConfig(thresholds={"require_public_surface_capability": True, "min_confidence": 0.75})
    )
    facts = _facts_with_capabilities(mixed_public_dashboard=True)
    facts.routes = [
        _route("POST", "/login", "AuthController", "login", ["web", "guest", "throttle:6,1"]),
        _route("POST", "/portal/account/password", "AccountController", "changePassword", ["web", "auth"]),
        _route("POST", "/register", "AuthController", "register", ["web", "guest"]),
    ]

    findings = rule.analyze(facts)
    assert len(findings) == 1
    assert findings[0].context == "POST /register"


def test_sanctum_token_scope_missing_valid_near_invalid():
    rule = SanctumTokenScopeMissingRule(
        RuleConfig(
            thresholds={
                "require_sanctum_signal": True,
                "require_multi_role_portal_capability": True,
                "min_confidence": 0.75,
            }
        )
    )
    facts = _facts_with_capabilities(multi_role_portal=True)
    facts.routes = [_route("GET", "api/me", "AuthController", "me", ["auth:sanctum"])]
    file_path = "app/Http/Controllers/AuthController.php"

    valid = "<?php $token = $user->createToken('portal', ['invoices:read']); // sanctum"
    near_miss = "<?php $token = $user->createToken('portal', ['*']); // sanctum"
    invalid = "<?php $token = $user->createToken('portal'); // sanctum"

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near_miss, facts) == []
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1


def test_session_fixation_regenerate_missing_valid_near_invalid():
    rule = SessionFixationRegenerateMissingRule(RuleConfig(thresholds={"min_confidence": 0.75}))
    facts = Facts(project_path=".")
    file_path = "app/Http/Controllers/Auth/LoginController.php"

    valid = "<?php if (Auth::attempt($credentials)) { $request->session()->regenerate(); }"
    near_miss = "<?php public function ping() { return response()->json(['ok' => true]); }"
    invalid = "<?php if (Auth::attempt($credentials)) { return redirect('/dashboard'); }"

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near_miss, facts) == []
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1


def test_weak_password_policy_validation_valid_near_invalid():
    rule = WeakPasswordPolicyValidationRule(
        RuleConfig(thresholds={"min_required_length": 8, "min_confidence": 0.7})
    )
    facts = Facts(project_path=".")
    file_path = "app/Http/Controllers/Auth/RegisteredUserController.php"

    valid = "<?php 'password' => ['required', Password::min(12)->mixedCase()->numbers()->symbols()->uncompromised()]"
    near_miss = "<?php 'password' => 'required|string|min:8|confirmed'"
    invalid = "<?php 'password' => 'required|string|min:6|confirmed'"

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near_miss, facts) == []
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1


def test_weak_password_policy_validation_ignores_model_cast_and_current_password():
    rule = WeakPasswordPolicyValidationRule(
        RuleConfig(thresholds={"min_required_length": 8, "min_confidence": 0.7})
    )
    facts = Facts(project_path=".")

    model_cast = """
<?php
class User extends Authenticatable {
    protected function casts(): array
    {
        return [
            'password' => 'hashed',
        ];
    }
}
"""
    profile_current_password = """
<?php
$request->validate([
    'password' => ['required', 'current_password'],
]);
"""

    assert rule.analyze_regex("app/Models/User.php", model_cast, facts) == []
    assert rule.analyze_regex("app/Services/ProfileService.php", profile_current_password, facts) == []


def test_weak_password_policy_validation_ignores_login_request_password_field():
    rule = WeakPasswordPolicyValidationRule(
        RuleConfig(thresholds={"min_required_length": 8, "min_confidence": 0.7})
    )
    facts = Facts(project_path=".")
    login_request = """
<?php
class LoginRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'username' => ['required', 'string'],
            'password' => ['required', 'string'],
        ];
    }
}
"""

    assert rule.analyze_regex("app/Http/Requests/Lms/LoginRequest.php", login_request, facts) == []


def test_upload_mime_extension_mismatch_valid_near_invalid():
    rule = UploadMimeExtensionMismatchRule(
        RuleConfig(thresholds={"require_upload_capability": True, "min_confidence": 0.75})
    )
    facts = _facts_with_capabilities(file_upload_storage_heavy=True)
    file_path = "app/Http/Controllers/MediaController.php"

    valid = "<?php $request->validate(['file' => 'required|file|mimes:jpg,png|mimetypes:image/jpeg,image/png']);"
    near_miss = "<?php $request->validate(['file' => 'required|file|mimes:jpg,png']);"
    invalid = """
<?php
$request->validate(['file' => 'required|file|mimes:jpg,png']);
$ext = $request->file('file')->getClientOriginalExtension();
"""

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near_miss, facts) == []
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1


def test_archive_upload_zip_slip_risk_valid_near_invalid():
    rule = ArchiveUploadZipSlipRiskRule(
        RuleConfig(thresholds={"require_upload_capability": True, "min_confidence": 0.8})
    )
    facts = _facts_with_capabilities(file_upload_storage_heavy=True)
    file_path = "app/Services/ArchiveService.php"

    valid = """
<?php
$zip = new ZipArchive();
$target = realpath(storage_path('imports'));
if (str_starts_with($target, storage_path('imports'))) {
    $zip->extractTo($target);
}
"""
    near_miss = "<?php $zip = new ZipArchive(); $zip->open($path);"
    invalid = "<?php $zip = new ZipArchive(); $zip->open($path); $zip->extractTo($targetDir);"

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near_miss, facts) == []
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1


def test_upload_size_limit_missing_valid_near_invalid():
    rule = UploadSizeLimitMissingRule(
        RuleConfig(thresholds={"require_upload_capability": True, "min_confidence": 0.7})
    )
    facts = _facts_with_capabilities(file_upload_storage_heavy=True)
    file_path = "app/Http/Controllers/ProfileController.php"

    valid = "<?php $request->validate(['avatar' => 'required|image|mimes:jpg,png|max:2048']);"
    near_miss = "<?php $request->validate(['name' => 'required|string|max:255']);"
    invalid = "<?php $request->validate(['avatar' => 'required|image|mimes:jpg,png']);"

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near_miss, facts) == []
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1


def test_upload_size_limit_missing_accepts_dynamic_max_rule_in_form_request():
    rule = UploadSizeLimitMissingRule(
        RuleConfig(thresholds={"require_upload_capability": True, "min_confidence": 0.7})
    )
    facts = _facts_with_capabilities(file_upload_storage_heavy=True)
    file_path = "app/Http/Requests/Lms/UploadImageRequest.php"
    content = """
<?php
class UploadImageRequest extends FormRequest
{
    public function rules(): array
    {
        $maxSizeKb = 2048;
        return [
            'file' => ['required', 'image', 'max:'.$maxSizeKb],
        ];
    }
}
"""

    assert rule.analyze_regex(file_path, content, facts) == []


def test_upload_size_limit_missing_skips_upload_config_settings():
    rule = UploadSizeLimitMissingRule(
        RuleConfig(thresholds={"require_upload_capability": True, "min_confidence": 0.7})
    )
    facts = _facts_with_capabilities(file_upload_storage_heavy=True)
    content = """
<?php
return [
    'upload' => [
        'max_size_kb' => (int) env('APP_UPLOAD_MAX_SIZE_KB', 2048),
        'answer_image_max_size_kb' => (int) env('APP_UPLOAD_ANSWER_IMAGE_MAX_SIZE_KB', 2048),
    ],
];
"""

    assert rule.analyze_regex("config/app.php", content, facts) == []


def test_insecure_postmessage_origin_wildcard_valid_near_invalid():
    rule = InsecurePostMessageOriginWildcardRule(
        RuleConfig(thresholds={"require_public_surface_capability": True, "min_confidence": 0.9})
    )
    facts = _facts_with_capabilities(mixed_public_dashboard=True)
    file_path = "resources/js/pages/Auth/EmbedBridge.tsx"

    valid = "window.parent.postMessage({ ok: true }, window.location.origin);"
    near_miss = "const message = { ok: true };"
    invalid = "window.parent.postMessage({ token }, '*');"

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near_miss, facts) == []
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1


def test_token_storage_insecure_localstorage_valid_near_invalid():
    rule = TokenStorageInsecureLocalStorageRule(
        RuleConfig(thresholds={"require_public_surface_capability": True, "min_confidence": 0.8})
    )
    facts = _facts_with_capabilities(mixed_public_dashboard=True)
    file_path = "resources/js/services/authStorage.ts"

    valid = "localStorage.setItem('theme', 'dark');"
    near_miss = "sessionStorage.setItem('locale', 'en');"
    invalid = "localStorage.setItem('access_token', token);"

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near_miss, facts) == []
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1


def test_client_open_redirect_unvalidated_navigation_valid_near_invalid():
    rule = ClientOpenRedirectUnvalidatedNavigationRule(
        RuleConfig(thresholds={"require_public_surface_capability": True, "min_confidence": 0.8})
    )
    facts = _facts_with_capabilities(mixed_public_dashboard=True)
    file_path = "resources/js/pages/Auth/Login.tsx"

    valid = """
const next = new URLSearchParams(window.location.search).get('next');
if (next && next.startsWith('/')) {
  router.visit(next);
}
"""
    near_miss = "const next = new URLSearchParams(window.location.search).get('next');"
    invalid = """
const next = new URLSearchParams(window.location.search).get('next');
router.visit(next);
"""

    assert rule.analyze_regex(file_path, valid, facts) == []
    assert rule.analyze_regex(file_path, near_miss, facts) == []
    assert len(rule.analyze_regex(file_path, invalid, facts)) == 1
