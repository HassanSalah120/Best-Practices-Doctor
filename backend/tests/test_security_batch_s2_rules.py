from __future__ import annotations

from core.ruleset import RuleConfig
from rules.laravel.csrf_exception_wildcard_risk import CsrfExceptionWildcardRiskRule
from rules.laravel.host_header_poisoning_risk import HostHeaderPoisoningRiskRule
from rules.laravel.password_reset_token_hardening_missing import PasswordResetTokenHardeningMissingRule
from rules.laravel.security_headers_baseline_missing import SecurityHeadersBaselineMissingRule
from rules.laravel.sensitive_response_cache_control_missing import SensitiveResponseCacheControlMissingRule
from rules.laravel.webhook_replay_protection_missing import WebhookReplayProtectionMissingRule
from rules.laravel.xml_xxe_risk import XmlXxeRiskRule
from rules.laravel.zip_bomb_risk import ZipBombRiskRule
from rules.react.dangerous_html_sink_without_sanitizer import DangerousHtmlSinkWithoutSanitizerRule
from rules.react.postmessage_receiver_origin_not_verified import PostMessageReceiverOriginNotVerifiedRule
from schemas.facts import Facts, MethodInfo, RouteInfo


def _method(class_name: str, name: str, calls: list[str], file_path: str | None = None) -> MethodInfo:
    return MethodInfo(
        name=name,
        class_name=class_name,
        class_fqcn=f"App\\Http\\Controllers\\{class_name}",
        file_path=file_path or f"app/Http/Controllers/{class_name}.php",
        file_hash="fixture",
        line_start=10,
        line_end=80,
        call_sites=calls,
    )


def _route(method: str, uri: str, controller: str, action: str, middleware: list[str]) -> RouteInfo:
    return RouteInfo(
        method=method,
        uri=uri,
        controller=controller,
        action=action,
        middleware=middleware,
        file_path="routes/web.php",
        line_number=12,
        source="artisan",
    )


def test_csrf_exception_wildcard_risk_regex():
    rule = CsrfExceptionWildcardRiskRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "<?php $middleware->validateCsrfTokens(except: ['/webhooks/stripe']);"
    invalid = "<?php $middleware->validateCsrfTokens(except: ['webhooks/*']);"

    assert rule.analyze_regex("bootstrap/app.php", valid, facts) == []
    assert len(rule.analyze_regex("bootstrap/app.php", invalid, facts)) == 1


def test_host_header_poisoning_risk_ast():
    rule = HostHeaderPoisoningRiskRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.methods = [
        _method("SafeController", "go", ["$host = $request->getHost();", "if ($this->isAllowedHost($host)) {}", "return redirect()->to($host);"]),
        _method("UnsafeController", "go", ["$host = $request->getHost();", "return redirect()->to($host . '/login');"]),
    ]
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context.endswith("UnsafeController::go")


def test_xml_xxe_risk_ast():
    rule = XmlXxeRiskRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.methods = [
        _method("SafeXmlController", "parse", ["$dom->loadXML($xml, LIBXML_NONET);"]),
        _method("UnsafeXmlController", "parse", ["$dom->loadXML($xml);"]),
    ]
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context.endswith("UnsafeXmlController::parse")


def test_zip_bomb_risk_ast():
    rule = ZipBombRiskRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.methods = [
        _method("SafeArchiveController", "extract", ["$zip->open($path);", "$limit = $zip->numFiles;", "$zip->extractTo($dir);"]),
        _method("UnsafeArchiveController", "extract", ["$zip->open($path);", "$zip->extractTo($dir);"]),
    ]
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].context.endswith("UnsafeArchiveController::extract")


def test_sensitive_response_cache_control_missing_ast():
    rule = SensitiveResponseCacheControlMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.routes = [
        _route("GET", "/portal/account", "AccountController", "showSafe", ["web", "auth"]),
        _route("GET", "/portal/account", "AccountController", "showUnsafe", ["web", "auth"]),
    ]
    facts.methods = [
        _method("AccountController", "showSafe", ["return response()->json($data)->header('Cache-Control', 'no-store');"]),
        _method("AccountController", "showUnsafe", ["return response()->json($data);"]),
    ]
    findings = rule.run(facts, project_type="laravel_inertia_react").findings
    assert len(findings) == 1
    assert findings[0].context == "GET /portal/account"


def test_sensitive_response_cache_control_missing_skips_no_store_middleware():
    rule = SensitiveResponseCacheControlMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.routes = [
        _route("GET", "/portal/account", "AccountController", "show", ["web", "auth", "no.store"]),
    ]
    facts.methods = [
        _method("AccountController", "show", ["return response()->json($data);"]),
    ]

    findings = rule.run(facts, project_type="laravel_inertia_react").findings
    assert findings == []


def test_sensitive_response_cache_control_missing_skips_no_store_middleware_class_reference():
    rule = SensitiveResponseCacheControlMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.routes = [
        _route(
            "GET",
            "/lms/account",
            "LmsController",
            "show",
            ["web", "auth", "App\\Http\\Middleware\\NoStoreCacheMiddleware"],
        ),
    ]
    facts.methods = [
        _method("LmsController", "show", ["return response()->json($payload);"]),
    ]

    findings = rule.run(facts, project_type="laravel_inertia_react").findings
    assert findings == []


def test_sensitive_response_cache_control_missing_skips_short_no_store_middleware_class_name():
    rule = SensitiveResponseCacheControlMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.routes = [
        _route(
            "GET",
            "/lms/admin/game",
            "LmsPageController",
            "adminGame",
            ["web", "auth", "lms.admin", "NoStoreCacheMiddleware"],
        ),
    ]
    facts.methods = [
        _method("LmsPageController", "adminGame", ["return response()->json($payload);"]),
    ]

    findings = rule.run(facts, project_type="laravel_inertia_react").findings
    assert findings == []


def test_sensitive_response_cache_control_missing_skips_cache_control_dot_notation():
    """Test that 'cache.control' (dot notation) middleware alias is recognized.

    This is a regression test for a false positive where the scanner
    failed to recognize Laravel middleware aliases using dot notation.
    See: https://github.com/HassanSalah120/Best-Practices-Doctor/issues/XXX
    """
    rule = SensitiveResponseCacheControlMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.routes = [
        _route(
            "GET",
            "/lms/admin/game",
            "AdminController",
            "game",
            ["auth", "lms.admin", "cache.control"],  # Dot notation middleware alias
        ),
    ]
    facts.methods = [
        _method("AdminController", "game", ["return response()->json($data);"]),
    ]

    findings = rule.run(facts, project_type="laravel_inertia_react").findings
    assert findings == []


def test_password_reset_token_hardening_missing_ast():
    rule = PasswordResetTokenHardeningMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.routes = [
        _route("POST", "/reset-password", "ResetController", "safe", ["web", "guest"]),
        _route("POST", "/reset-password", "ResetController", "unsafe", ["web", "guest"]),
    ]
    facts.methods = [
        _method("ResetController", "safe", ["Password::reset($credentials, function() {});"]),
        _method("ResetController", "unsafe", ["$token = $request->input('token');", "$email = $request->input('email');", "$password = $request->input('password');"]),
    ]
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].related_methods and findings[0].related_methods[0].endswith("ResetController::unsafe")


def test_security_headers_baseline_missing_ast():
    rule = SecurityHeadersBaselineMissingRule(RuleConfig())
    safe = Facts(project_path=".")
    safe.files = ["routes/web.php"]
    safe.methods = [_method("SecurityHeaders", "handle", ["return $response->header('X-Frame-Options', 'DENY');"], "app/Http/Middleware/SecurityHeaders.php")]
    assert rule.run(safe, project_type="laravel_blade").findings == []

    unsafe = Facts(project_path=".")
    unsafe.files = ["routes/web.php", "resources/views/welcome.blade.php"]
    unsafe.methods = [_method("HomeController", "index", ["return view('welcome');"])]
    findings = rule.run(unsafe, project_type="laravel_blade").findings
    assert len(findings) == 1


def test_webhook_replay_protection_missing_ast():
    rule = WebhookReplayProtectionMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.project_context.capabilities = {
        "external_integrations_heavy": {"enabled": True, "confidence": 1.0, "source": "explicit", "evidence": ["test"]}
    }
    facts.routes = [
        _route("POST", "/webhooks/stripe", "StripeWebhookController", "safe", ["api"]),
        _route("POST", "/webhooks/stripe", "StripeWebhookController", "unsafe", ["api"]),
    ]
    facts.methods = [
        _method("StripeWebhookController", "safe", ["$this->validateSignature($payload);", "$this->assertRecentTimestamp($payload);"]),
        _method("StripeWebhookController", "unsafe", ["$this->validateSignature($payload);", "$this->processWebhook($payload);"]),
    ]
    findings = rule.run(facts, project_type="laravel_blade").findings
    assert len(findings) == 1
    assert findings[0].related_methods and findings[0].related_methods[0].endswith("StripeWebhookController::unsafe")


def test_postmessage_receiver_origin_not_verified_ast():
    rule = PostMessageReceiverOriginNotVerifiedRule(RuleConfig())
    facts = Facts(project_path=".")
    valid = "window.addEventListener('message', (event) => { if (event.origin !== allowedOrigin) return; handle(event.data); });"
    invalid = "window.addEventListener('message', (event) => { handle(event.data); });"
    assert rule.analyze_ast("resources/js/pages/Embed.tsx", valid, facts) == []
    assert len(rule.analyze_ast("resources/js/pages/Embed.tsx", invalid, facts)) == 1


def test_dangerous_html_sink_without_sanitizer_ast():
    rule = DangerousHtmlSinkWithoutSanitizerRule(RuleConfig())
    facts = Facts(project_path=".")
    valid = "const clean = DOMPurify.sanitize(html); return <div dangerouslySetInnerHTML={{ __html: clean }} />;"
    invalid = "return <div dangerouslySetInnerHTML={{ __html: html }} />;"
    assert rule.analyze_ast("resources/js/components/Preview.tsx", valid, facts) == []
    assert len(rule.analyze_ast("resources/js/components/Preview.tsx", invalid, facts)) == 1


def test_dangerous_html_sink_without_sanitizer_style_tag():
    rule = DangerousHtmlSinkWithoutSanitizerRule(RuleConfig())
    facts = Facts(project_path=".")
    invalid = """
export function Footer() {
  return (
    <style
      dangerouslySetInnerHTML={{
        __html: `
          .ticker { animation: marquee 35s linear infinite; }
        `
      }}
    />
  );
}
"""
    valid = """
import DOMPurify from 'dompurify';
export function Footer({ cssText }) {
  const safe = DOMPurify.sanitize(cssText);
  return <style dangerouslySetInnerHTML={{ __html: safe }} />;
}
"""
    assert len(rule.analyze_ast("resources/js/components/Footer.tsx", invalid, facts)) == 1
    assert rule.analyze_ast("resources/js/components/Footer.tsx", valid, facts) == []
