from __future__ import annotations

from core.ruleset import RuleConfig
from rules.laravel.api_debug_trace_leak import ApiDebugTraceLeakRule
from rules.laravel.cookie_samesite_missing import CookieSameSiteMissingRule
from rules.laravel.livewire_public_prop_mass_assignment import LivewirePublicPropMassAssignmentRule
from rules.laravel.missing_content_security_policy import MissingContentSecurityPolicyRule
from rules.laravel.missing_hsts_header import MissingHstsHeaderRule
from rules.laravel.password_hash_weak_algorithm import PasswordHashWeakAlgorithmRule
from rules.laravel.plain_text_sensitive_config import PlainTextSensitiveConfigRule
from rules.laravel.timing_attack_token_comparison import TimingAttackTokenComparisonRule
from rules.php.pcre_redos_risk import PcreRedosRiskRule
from rules.php.unsafe_file_include_variable import UnsafeFileIncludeVariableRule
from rules.react.api_key_in_client_bundle import ApiKeyInClientBundleRule
from rules.react.client_side_auth_only import ClientSideAuthOnlyRule
from schemas.facts import Facts


def test_missing_hsts_header_valid_invalid_edge():
    rule = MissingHstsHeaderRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "<?php $response->headers->set('Strict-Transport-Security', 'max-age=31536000');"
    invalid = "<?php class Kernel { protected $middleware = ['auth']; }"
    edge = "<?php return ['name' => 'app'];"

    assert rule.analyze_regex("app/Http/Middleware/SecurityHeaders.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Http/Kernel.php", invalid, facts)) == 1
    assert rule.analyze_regex("config/app.php", edge, facts) == []


def test_cookie_samesite_missing_valid_invalid_edge():
    rule = CookieSameSiteMissingRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "<?php return ['same_site' => 'lax'];"
    invalid = "<?php return ['same_site' => null];"
    edge = "<?php return ['same_site' => env('SESSION_SAME_SITE', 'strict')];"

    assert rule.analyze_regex("config/session.php", valid, facts) == []
    assert len(rule.analyze_regex("config/session.php", invalid, facts)) == 1
    assert rule.analyze_regex("config/session.php", edge, facts) == []


def test_timing_attack_token_comparison_valid_invalid_edge():
    rule = TimingAttackTokenComparisonRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "<?php if (hash_equals($expectedToken, $providedToken)) { return true; }"
    invalid = "<?php if ($expectedToken === $providedToken) { return true; }"
    edge = "<?php if ($expectedToken === $providedToken) { return true; }"

    assert rule.analyze_regex("app/Services/TokenService.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Services/TokenService.php", invalid, facts)) == 1
    assert rule.analyze_regex("tests/Feature/TokenServiceTest.php", edge, facts) == []


def test_password_hash_weak_algorithm_valid_invalid_edge():
    rule = PasswordHashWeakAlgorithmRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "<?php $hash = Hash::make($password);"
    invalid = "<?php $hash = md5($password);"
    edge = "<?php $checksum = md5($fileContent);"

    assert rule.analyze_regex("app/Services/AuthService.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Services/AuthService.php", invalid, facts)) == 1
    assert rule.analyze_regex("app/Services/FileService.php", edge, facts) == []


def test_api_debug_trace_leak_valid_invalid_edge():
    rule = ApiDebugTraceLeakRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "APP_ENV=production\nAPP_DEBUG=false\n"
    invalid = "APP_ENV=production\nAPP_DEBUG=true\n"
    edge = "<?php return ['debug' => env('APP_DEBUG', false)];"

    assert rule.analyze_regex(".env", valid, facts) == []
    assert len(rule.analyze_regex(".env", invalid, facts)) == 1
    assert rule.analyze_regex("config/app.php", edge, facts) == []


def test_plain_text_sensitive_config_valid_invalid_edge():
    rule = PlainTextSensitiveConfigRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "<?php return ['stripe_secret' => env('STRIPE_SECRET')];"
    invalid = "<?php return ['stripe_secret' => 'sk_live_123456789'];"
    edge = "<?php return ['api_key' => ''];"

    assert rule.analyze_regex("config/services.php", valid, facts) == []
    assert len(rule.analyze_regex("config/services.php", invalid, facts)) == 1
    assert rule.analyze_regex("config/services.php", edge, facts) == []


def test_livewire_public_prop_mass_assignment_valid_invalid_edge():
    rule = LivewirePublicPropMassAssignmentRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "<?php class Profile extends Component { #[Locked] public string $userId; }"
    invalid = "<?php class Profile extends Component { public string $userId; }"
    edge = "<?php class Profile extends Component { public array $listeners = []; }"

    assert rule.analyze_regex("app/Livewire/Profile.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Livewire/Profile.php", invalid, facts)) == 1
    assert rule.analyze_regex("app/Livewire/Profile.php", edge, facts) == []


def test_missing_content_security_policy_valid_invalid_edge():
    rule = MissingContentSecurityPolicyRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "<?php $response->headers->set('Content-Security-Policy', \"default-src 'self'\");"
    invalid = "<?php class Kernel { protected $middleware = ['auth']; }"
    edge = "<?php return ['name' => 'app'];"

    assert rule.analyze_regex("app/Http/Middleware/SecurityHeaders.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Http/Kernel.php", invalid, facts)) == 1
    assert rule.analyze_regex("config/app.php", edge, facts) == []


def test_pcre_redos_risk_valid_invalid_edge():
    rule = PcreRedosRiskRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "<?php preg_match('/^[a-z0-9_-]+$/i', $value);"
    invalid = "<?php preg_match('/(a+)+$/', $input);"
    edge = "<?php preg_match('/(a+)+$/', $input);"

    assert rule.analyze_regex("app/Services/RegexService.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Services/RegexService.php", invalid, facts)) == 1
    assert rule.analyze_regex("tests/Feature/RegexServiceTest.php", edge, facts) == []


def test_unsafe_file_include_variable_valid_invalid_edge():
    rule = UnsafeFileIncludeVariableRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "<?php require __DIR__ . '/template.php';"
    invalid = "<?php include $templatePath;"
    edge = "<?php if (in_array($templatePath, $whitelist, true)) { include $templatePath; }"

    assert rule.analyze_regex("app/Http/Controllers/ViewController.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Http/Controllers/ViewController.php", invalid, facts)) == 1
    assert rule.analyze_regex("app/Http/Controllers/ViewController.php", edge, facts) == []


def test_api_key_in_client_bundle_valid_invalid_edge():
    rule = ApiKeyInClientBundleRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "const baseUrl = import.meta.env.VITE_API_URL;"
    invalid = 'const API_KEY = "test_fake_12345";'
    edge = "// API_KEY = test_fake_12345"

    assert rule.analyze_regex("resources/js/app.tsx", valid, facts) == []
    assert len(rule.analyze_regex("resources/js/app.tsx", invalid, facts)) == 1
    assert rule.analyze_regex("resources/js/app.tsx", edge, facts) == []


def test_client_side_auth_only_valid_invalid_edge():
    rule = ClientSideAuthOnlyRule(RuleConfig())
    facts = Facts(project_path=".")

    valid = "const { auth } = usePage().props; return auth.canAccess ? <Admin /> : null;"
    invalid = "return isAdmin && <DeleteButton />;"
    edge = "return isAdmin && <DeleteButton />;"

    assert rule.analyze_regex("resources/js/Pages/Admin.tsx", valid, facts) == []
    assert len(rule.analyze_regex("resources/js/Pages/Admin.tsx", invalid, facts)) == 1
    assert rule.analyze_regex("resources/js/Pages/__tests__/Admin.test.tsx", edge, facts) == []
