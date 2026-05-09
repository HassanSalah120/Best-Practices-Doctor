from core.ruleset import RuleConfig
from rules.laravel.authorization_missing_on_sensitive_reads import AuthorizationMissingOnSensitiveReadsRule
from rules.laravel.insecure_session_cookie_config import InsecureSessionCookieConfigRule
from rules.laravel.unsafe_csp_policy import UnsafeCspPolicyRule
from rules.laravel.job_missing_idempotency_guard import JobMissingIdempotencyGuardRule
from rules.laravel.composer_dependency_below_secure_version import ComposerDependencyBelowSecureVersionRule
from rules.laravel.npm_dependency_below_secure_version import NpmDependencyBelowSecureVersionRule
from rules.laravel.inertia_shared_props_sensitive_data import InertiaSharedPropsSensitiveDataRule
from rules.laravel.inertia_shared_props_eager_query import InertiaSharedPropsEagerQueryRule
from rules.laravel.job_missing_retry_policy import JobMissingRetryPolicyRule
from rules.laravel.job_http_call_missing_timeout import JobHttpCallMissingTimeoutRule
from rules.laravel.policy_coverage_on_mutations import PolicyCoverageOnMutationsRule
from rules.laravel.authorization_bypass_risk import AuthorizationBypassRiskRule
from rules.laravel._dependency_versioning import load_dependency_advisory_catalog
from schemas.facts import ClassInfo, Facts, MethodInfo, QueryUsage, RouteInfo


def test_authorization_missing_on_sensitive_reads_flags_sensitive_show_without_policy():
    facts = Facts(project_path=".")
    facts.controllers.append(
        ClassInfo(
            name="PatientsController",
            fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            file_hash="deadbeef",
        )
    )
    facts.methods.append(
        MethodInfo(
            name="show",
            class_name="PatientsController",
            class_fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            file_hash="deadbeef",
            line_start=12,
            line_end=28,
        )
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            line_number=14,
            method_name="show",
            model="Patient",
            method_chain="findOrFail",
        )
    )
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/clinic/patients/{patient}",
            controller="Clinic\\PatientsController",
            action="show",
            middleware=["web", "auth", "verified"],
            file_path="routes/web.php",
            line_number=22,
        )
    )

    findings = AuthorizationMissingOnSensitiveReadsRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert len(findings) == 1
    assert findings[0].rule_id == "authorization-missing-on-sensitive-reads"


def test_authorization_missing_on_sensitive_reads_skips_when_authorize_present():
    facts = Facts(project_path=".")
    facts.controllers.append(
        ClassInfo(
            name="PatientsController",
            fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            file_hash="deadbeef",
        )
    )
    facts.methods.append(
        MethodInfo(
            name="show",
            class_name="PatientsController",
            class_fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            file_hash="deadbeef",
            line_start=12,
            line_end=28,
            call_sites=["$this->authorize('view', $patient);"],
        )
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            line_number=14,
            method_name="show",
            model="Patient",
            method_chain="findOrFail",
        )
    )
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/clinic/patients/{patient}",
            controller="Clinic\\PatientsController",
            action="show",
            middleware=["web", "auth", "verified"],
            file_path="routes/web.php",
            line_number=22,
        )
    )

    findings = AuthorizationMissingOnSensitiveReadsRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert findings == []


def test_authorization_missing_on_sensitive_reads_skips_when_controller_uses_authorize_resource():
    facts = Facts(project_path=".")
    facts.controllers.append(
        ClassInfo(
            name="PatientsController",
            fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            file_hash="deadbeef",
        )
    )
    facts.methods.extend(
        [
            MethodInfo(
                name="__construct",
                class_name="PatientsController",
                class_fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
                file_path="app/Http/Controllers/Clinic/PatientsController.php",
                file_hash="deadbeef",
                call_sites=["$this->authorizeResource(Patient::class, 'patient');"],
            ),
            MethodInfo(
                name="show",
                class_name="PatientsController",
                class_fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
                file_path="app/Http/Controllers/Clinic/PatientsController.php",
                file_hash="deadbeef",
                line_start=12,
                line_end=28,
            ),
        ]
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            line_number=14,
            method_name="show",
            model="Patient",
            method_chain="findOrFail",
        )
    )
    facts.routes.append(
        RouteInfo(
            method="GET",
            uri="/clinic/patients/{patient}",
            controller="Clinic\\PatientsController",
            action="show",
            middleware=["web", "auth", "verified"],
            file_path="routes/web.php",
            line_number=22,
        )
    )

    findings = AuthorizationMissingOnSensitiveReadsRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert findings == []


def test_insecure_session_cookie_config_flags_weak_settings():
    rule = InsecureSessionCookieConfigRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
return [
    'http_only' => false,
    'secure' => env('SESSION_SECURE_COOKIE', false),
    'same_site' => null,
];
"""

    findings = rule.analyze_regex("config/session.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "insecure-session-cookie-config"


def test_insecure_session_cookie_config_skips_hardened_settings():
    rule = InsecureSessionCookieConfigRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
return [
    'http_only' => true,
    'secure' => env('SESSION_SECURE_COOKIE', true),
    'same_site' => 'lax',
];
"""

    findings = rule.analyze_regex("config/session.php", content, facts)
    assert findings == []


def test_unsafe_csp_policy_flags_unsafe_inline():
    rule = UnsafeCspPolicyRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
$response->headers->set('Content-Security-Policy', \"default-src 'self'; script-src 'self' 'unsafe-inline'\");
"""

    findings = rule.analyze_regex("app/Http/Middleware/SecurityHeaders.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "unsafe-csp-policy"


def test_unsafe_csp_policy_skips_safe_policy():
    rule = UnsafeCspPolicyRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
$response->headers->set('Content-Security-Policy', \"default-src 'self'; script-src 'self' 'nonce-123'\");
"""

    findings = rule.analyze_regex("app/Http/Middleware/SecurityHeaders.php", content, facts)
    assert findings == []


def test_job_missing_idempotency_guard_flags_side_effecting_job():
    rule = JobMissingIdempotencyGuardRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class SendCampaignJob implements ShouldQueue
{
    public function handle(): void
    {
        Mail::to($this->email)->send($message);
    }
}
"""

    findings = rule.analyze_regex("app/Jobs/SendCampaignJob.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "job-missing-idempotency-guard"


def test_job_missing_idempotency_guard_skips_unique_job():
    rule = JobMissingIdempotencyGuardRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class SendCampaignJob implements ShouldQueue, ShouldBeUnique
{
    public function uniqueId(): string
    {
        return (string) $this->campaignId;
    }

    public function handle(): void
    {
        Mail::to($this->email)->send($message);
    }
}
"""

    findings = rule.analyze_regex("app/Jobs/SendCampaignJob.php", content, facts)
    assert findings == []


def test_composer_dependency_below_secure_version_flags_lockfile_version():
    rule = ComposerDependencyBelowSecureVersionRule(RuleConfig())
    facts = Facts(project_path=".", files=["composer.lock"])
    content = """
{
  "packages": [
    { "name": "league/commonmark", "version": "2.8.0" }
  ]
}
"""

    findings = rule.analyze_regex("composer.lock", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "composer-dependency-below-secure-version"


def test_composer_dependency_below_secure_version_skips_patched_version():
    rule = ComposerDependencyBelowSecureVersionRule(RuleConfig())
    facts = Facts(project_path=".", files=["composer.lock"])
    content = """
{
  "packages": [
    { "name": "league/commonmark", "version": "2.8.1" }
  ]
}
"""

    findings = rule.analyze_regex("composer.lock", content, facts)
    assert findings == []


def test_npm_dependency_below_secure_version_flags_package_json_without_lock():
    rule = NpmDependencyBelowSecureVersionRule(RuleConfig())
    facts = Facts(project_path=".", files=["package.json"])
    content = """
{
  "dependencies": {
    "dompurify": "^3.3.1"
  }
}
"""

    findings = rule.analyze_regex("package.json", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "npm-dependency-below-secure-version"


def test_npm_dependency_below_secure_version_skips_patched_lockfile_version():
    rule = NpmDependencyBelowSecureVersionRule(RuleConfig())
    facts = Facts(project_path=".", files=["package-lock.json"])
    content = """
{
  "packages": {
    "": { "name": "demo" },
    "node_modules/dompurify": { "version": "3.3.2" }
  }
}
"""

    findings = rule.analyze_regex("package-lock.json", content, facts)
    assert findings == []


def test_inertia_shared_props_sensitive_data_flags_raw_user_share():
    rule = InertiaSharedPropsSensitiveDataRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'auth.user' => $request->user(),
        ]);
    }
}
"""

    findings = rule.analyze_regex("app/Http/Middleware/HandleInertiaRequests.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-shared-props-sensitive-data"


def test_inertia_shared_props_sensitive_data_skips_whitelisted_fields():
    rule = InertiaSharedPropsSensitiveDataRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'auth.user' => fn () => $request->user()?->only('id', 'name', 'email'),
        ]);
    }
}
"""

    findings = rule.analyze_regex("app/Http/Middleware/HandleInertiaRequests.php", content, facts)
    assert findings == []


def test_inertia_shared_props_eager_query_flags_direct_count():
    rule = InertiaSharedPropsEagerQueryRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'stats' => Order::count(),
        ]);
    }
}
"""

    findings = rule.analyze_regex("app/Http/Middleware/HandleInertiaRequests.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "inertia-shared-props-eager-query"


def test_inertia_shared_props_eager_query_skips_lazy_closure():
    rule = InertiaSharedPropsEagerQueryRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class HandleInertiaRequests {
    public function share(Request $request): array {
        return array_merge(parent::share($request), [
            'stats' => fn () => Order::count(),
        ]);
    }
}
"""

    findings = rule.analyze_regex("app/Http/Middleware/HandleInertiaRequests.php", content, facts)
    assert findings == []


def test_job_missing_retry_policy_flags_side_effect_job_without_retry_controls():
    rule = JobMissingRetryPolicyRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class SyncBillingJob implements ShouldQueue
{
    public function handle(): void
    {
        Http::post('https://api.example.com/sync', []);
    }
}
"""

    findings = rule.analyze_regex("app/Jobs/SyncBillingJob.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "job-missing-retry-policy"


def test_job_missing_retry_policy_skips_job_with_backoff():
    rule = JobMissingRetryPolicyRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class SyncBillingJob implements ShouldQueue
{
    public $tries = 3;

    public function backoff(): array
    {
        return [10, 30, 60];
    }

    public function handle(): void
    {
        Http::post('https://api.example.com/sync', []);
    }
}
"""

    findings = rule.analyze_regex("app/Jobs/SyncBillingJob.php", content, facts)
    assert findings == []


def test_job_http_call_missing_timeout_flags_http_job_without_timeout():
    rule = JobHttpCallMissingTimeoutRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class SyncBillingJob implements ShouldQueue
{
    public function handle(): void
    {
        Http::post('https://api.example.com/sync', []);
    }
}
"""

    findings = rule.analyze_regex("app/Jobs/SyncBillingJob.php", content, facts)
    assert len(findings) == 1
    assert findings[0].rule_id == "job-http-call-missing-timeout"


def test_job_http_call_missing_timeout_skips_job_with_timeout():
    rule = JobHttpCallMissingTimeoutRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class SyncBillingJob implements ShouldQueue
{
    public $timeout = 60;

    public function handle(): void
    {
        Http::timeout(10)->post('https://api.example.com/sync', []);
    }
}
"""

    findings = rule.analyze_regex("app/Jobs/SyncBillingJob.php", content, facts)
    assert findings == []


def test_policy_coverage_on_mutations_skips_authorize_resource_controller():
    facts = Facts(project_path=".")
    facts.controllers.append(
        ClassInfo(
            name="PatientsController",
            fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            file_hash="deadbeef",
        )
    )
    facts.methods.extend(
        [
            MethodInfo(
                name="__construct",
                class_name="PatientsController",
                class_fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
                file_path="app/Http/Controllers/Clinic/PatientsController.php",
                file_hash="deadbeef",
                call_sites=["$this->authorizeResource(Patient::class, 'patient');"],
            ),
            MethodInfo(
                name="update",
                class_name="PatientsController",
                class_fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
                file_path="app/Http/Controllers/Clinic/PatientsController.php",
                file_hash="deadbeef",
                line_start=20,
                line_end=40,
            ),
        ]
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            line_number=25,
            method_name="update",
            model="Patient",
            method_chain="findOrFail->update",
        )
    )

    findings = PolicyCoverageOnMutationsRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert findings == []


def test_authorization_bypass_risk_skips_authorize_resource_controller():
    facts = Facts(project_path=".")
    facts.controllers.append(
        ClassInfo(
            name="PatientsController",
            fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            file_hash="deadbeef",
        )
    )
    facts.methods.extend(
        [
            MethodInfo(
                name="__construct",
                class_name="PatientsController",
                class_fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
                file_path="app/Http/Controllers/Clinic/PatientsController.php",
                file_hash="deadbeef",
                call_sites=["$this->authorizeResource(Patient::class, 'patient');"],
            ),
            MethodInfo(
                name="update",
                class_name="PatientsController",
                class_fqcn="App\\Http\\Controllers\\Clinic\\PatientsController",
                file_path="app/Http/Controllers/Clinic/PatientsController.php",
                file_hash="deadbeef",
                line_start=20,
                line_end=40,
            ),
        ]
    )
    facts.queries.append(
        QueryUsage(
            file_path="app/Http/Controllers/Clinic/PatientsController.php",
            line_number=25,
            method_name="update",
            model="Patient",
            method_chain="findOrFail->update",
        )
    )

    findings = AuthorizationBypassRiskRule(RuleConfig()).run(
        facts, project_type="laravel_blade"
    ).findings
    assert findings == []


def test_dependency_advisory_catalog_loads_curated_entries():
    catalog = load_dependency_advisory_catalog()
    assert catalog["composer"]["league/commonmark"].minimum_version == "2.8.1"
    assert catalog["npm"]["dompurify"].minimum_version == "3.3.2"
