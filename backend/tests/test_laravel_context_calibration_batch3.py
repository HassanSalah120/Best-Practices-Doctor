from __future__ import annotations

from core.context_profiles import ContextProfileMatrix
from core.ruleset import RuleConfig
from rules.laravel.api_resource_usage import ApiResourceUsageRule
from rules.laravel.job_http_call_missing_timeout import JobHttpCallMissingTimeoutRule
from rules.laravel.job_missing_idempotency_guard import JobMissingIdempotencyGuardRule
from rules.laravel.job_missing_retry_policy import JobMissingRetryPolicyRule
from rules.laravel.missing_api_resource import MissingApiResourceRule
from rules.laravel.missing_auth_on_mutating_api_routes import MissingAuthOnMutatingApiRoutesRule
from rules.laravel.missing_throttle_on_auth_api_routes import MissingThrottleOnAuthApiRoutesRule
from rules.laravel.transaction_required_for_multi_write import TransactionRequiredForMultiWriteRule
from schemas.facts import Facts, MethodInfo, QueryUsage, RouteInfo


def _enable_capability(facts: Facts, capability: str) -> None:
    facts.project_context.backend_capabilities[capability] = {
        "enabled": True,
        "confidence": 0.9,
        "source": "test",
    }


def test_missing_api_resource_batch3_valid_near_invalid():
    rule = MissingApiResourceRule(RuleConfig(thresholds={"min_confidence": 0.6}))
    facts = Facts(project_path=".")

    valid = """
<?php
namespace App\\Http\\Controllers\\Api;
class UserController {
    public function index() {
        return UserResource::collection(User::paginate(10));
    }
}
"""
    near_miss = """
<?php
namespace App\\Http\\Controllers\\Api;
class UserController {
    public function index() {
        $users = User::query()->paginate(10);
        return $users;
    }
}
"""
    invalid = """
<?php
namespace App\\Http\\Controllers\\Api;
class UserController {
    public function index() {
        return User::all();
    }
}
"""

    assert rule.analyze_regex("app/Http/Controllers/Api/UserController.php", valid, facts) == []
    assert len(rule.analyze_regex("app/Http/Controllers/Api/UserController.php", near_miss, facts)) == 1
    assert len(rule.analyze_regex("app/Http/Controllers/Api/UserController.php", invalid, facts)) == 1


def test_api_resource_usage_batch3_valid_near_invalid():
    rule = ApiResourceUsageRule(RuleConfig(thresholds={"min_confidence": 0.6}))
    facts = Facts(project_path=".")

    valid = """
<?php
namespace App\\Http\\Controllers\\Api;
class SessionController {
    public function show() {
        return new SessionResource($session);
    }
}
"""
    near_miss = """
<?php
namespace App\\Http\\Controllers\\Api;
class SessionController {
    public function store() {
        return ['status' => 'ok', 'message' => 'queued'];
    }
}
"""
    invalid = """
<?php
namespace App\\Http\\Controllers\\Api;
class SessionController {
    public function index() {
        return ['data' => $sessions, 'pagination' => $meta];
    }
}
"""

    assert rule.analyze_regex("app/Http/Controllers/Api/SessionController.php", valid, facts) == []
    assert rule.analyze_regex("app/Http/Controllers/Api/SessionController.php", near_miss, facts) == []
    assert len(rule.analyze_regex("app/Http/Controllers/Api/SessionController.php", invalid, facts)) == 1


def test_missing_auth_on_mutating_api_routes_batch3_valid_near_invalid():
    rule = MissingAuthOnMutatingApiRoutesRule(RuleConfig(thresholds={"min_confidence": 0.7}))
    facts = Facts(project_path=".")
    facts.routes = [
        RouteInfo(
            method="POST",
            uri="/patients/authenticated",
            controller="PatientController",
            action="store",
            middleware=["auth:sanctum"],
            file_path="routes/api.php",
            line_number=7,
        ),
        RouteInfo(
            method="POST",
            uri="/login",
            controller="AuthController",
            action="login",
            middleware=[],
            file_path="routes/api.php",
            line_number=12,
        ),
        RouteInfo(
            method="POST",
            uri="/patients",
            controller="PatientController",
            action="store",
            middleware=[],
            file_path="routes/api.php",
            line_number=18,
        ),
    ]

    findings = rule.analyze(facts)
    assert len(findings) == 1
    assert findings[0].line_start == 18


def test_missing_throttle_on_auth_api_routes_batch3_valid_near_invalid():
    rule = MissingThrottleOnAuthApiRoutesRule(RuleConfig(thresholds={"min_confidence": 0.66}))
    facts = Facts(project_path=".")
    facts.routes = [
        RouteInfo(
            method="POST",
            uri="/auth/login",
            controller="AuthController",
            action="login",
            middleware=["auth:sanctum", "throttle:login"],
            file_path="routes/api.php",
            line_number=6,
        ),
        RouteInfo(
            method="POST",
            uri="/patients",
            controller="PatientController",
            action="store",
            middleware=["auth:sanctum"],
            file_path="routes/api.php",
            line_number=12,
        ),
        RouteInfo(
            method="POST",
            uri="/auth/password/reset",
            controller="AuthController",
            action="reset",
            middleware=["auth:sanctum"],
            file_path="routes/api.php",
            line_number=20,
        ),
    ]

    findings = rule.analyze(facts)
    assert len(findings) == 1
    assert findings[0].line_start == 20


def test_transaction_required_for_multi_write_batch3_valid_near_invalid():
    rule = TransactionRequiredForMultiWriteRule(
        RuleConfig(
            thresholds={
                "min_write_calls": 2,
                "min_distinct_models": 2,
                "ignore_idempotent_batches": True,
            }
        )
    )

    valid = Facts(project_path=".")
    valid.methods.append(
        MethodInfo(
            name="syncInvoices",
            class_name="BillingService",
            class_fqcn="App\\Services\\BillingService",
            file_path="app/Services/BillingService.php",
            file_hash="h1",
            line_start=10,
            line_end=45,
            loc=36,
        )
    )
    valid.queries.extend(
        [
            QueryUsage(
                file_path="app/Services/BillingService.php",
                line_number=18,
                method_name="syncInvoices",
                model="Invoice",
                method_chain="query->upsert",
                query_type="insert",
            ),
            QueryUsage(
                file_path="app/Services/BillingService.php",
                line_number=22,
                method_name="syncInvoices",
                model="Payment",
                method_chain="query->upsert",
                query_type="insert",
            ),
        ]
    )
    assert rule.analyze(valid) == []

    near_miss = Facts(project_path=".")
    near_miss.methods.append(
        MethodInfo(
            name="touchInvoices",
            class_name="BillingService",
            class_fqcn="App\\Services\\BillingService",
            file_path="app/Services/BillingService.php",
            file_hash="h2",
            line_start=10,
            line_end=48,
            loc=39,
        )
    )
    near_miss.queries.extend(
        [
            QueryUsage(
                file_path="app/Services/BillingService.php",
                line_number=20,
                method_name="touchInvoices",
                model="Invoice",
                method_chain="query->update",
                query_type="update",
            ),
            QueryUsage(
                file_path="app/Services/BillingService.php",
                line_number=24,
                method_name="touchInvoices",
                model="Invoice",
                method_chain="query->update",
                query_type="update",
            ),
        ]
    )
    assert rule.analyze(near_miss) == []

    invalid = Facts(project_path=".")
    invalid.methods.append(
        MethodInfo(
            name="finalizeInvoice",
            class_name="BillingService",
            class_fqcn="App\\Services\\BillingService",
            file_path="app/Services/BillingService.php",
            file_hash="h3",
            line_start=10,
            line_end=72,
            loc=63,
        )
    )
    invalid.queries.extend(
        [
            QueryUsage(
                file_path="app/Services/BillingService.php",
                line_number=25,
                method_name="finalizeInvoice",
                model="Invoice",
                method_chain="query->create",
                query_type="insert",
            ),
            QueryUsage(
                file_path="app/Services/BillingService.php",
                line_number=31,
                method_name="finalizeInvoice",
                model="Payment",
                method_chain="query->create",
                query_type="insert",
            ),
        ]
    )
    assert len(rule.analyze(invalid)) == 1


def test_job_missing_idempotency_guard_batch3_valid_near_invalid():
    rule = JobMissingIdempotencyGuardRule(
        RuleConfig(
            thresholds={
                "require_queue_capability": True,
                "ignore_db_only_jobs": True,
                "min_confidence": 0.6,
            }
        )
    )

    facts = Facts(project_path=".")
    _enable_capability(facts, "queue_heavy")

    valid = """
<?php
class SendCampaignJob implements ShouldQueue, ShouldBeUnique {
    public function uniqueId(): string { return (string) $this->campaignId; }
    public function handle(): void {
        Http::post('https://api.example.com/campaigns', []);
    }
}
"""
    near_miss = """
<?php
class UpdateStatsJob implements ShouldQueue {
    public function handle(): void {
        $row->update(['count' => 1]);
    }
}
"""
    invalid = """
<?php
class SendCampaignJob implements ShouldQueue {
    public function handle(): void {
        Mail::to($this->email)->send($message);
    }
}
"""

    assert rule.analyze_regex("app/Jobs/SendCampaignJob.php", valid, facts) == []
    assert rule.analyze_regex("app/Jobs/UpdateStatsJob.php", near_miss, facts) == []
    assert len(rule.analyze_regex("app/Jobs/SendCampaignJob.php", invalid, facts)) == 1


def test_job_missing_retry_policy_batch3_valid_near_invalid():
    rule = JobMissingRetryPolicyRule(
        RuleConfig(
            thresholds={
                "require_queue_capability": True,
                "ignore_db_only_jobs": True,
                "min_confidence": 0.6,
            }
        )
    )
    facts = Facts(project_path=".")
    _enable_capability(facts, "queue_heavy")

    valid = """
<?php
class SyncBillingJob implements ShouldQueue {
    public $tries = 3;
    public function backoff(): array { return [10, 30, 60]; }
    public function handle(): void {
        Http::post('https://api.example.com/sync', []);
    }
}
"""
    near_miss = """
<?php
class UpdateStatsJob implements ShouldQueue {
    public function handle(): void {
        $model->update(['counter' => 1]);
    }
}
"""
    invalid = """
<?php
class SyncBillingJob implements ShouldQueue {
    public function handle(): void {
        Http::post('https://api.example.com/sync', []);
    }
}
"""

    assert rule.analyze_regex("app/Jobs/SyncBillingJob.php", valid, facts) == []
    assert rule.analyze_regex("app/Jobs/UpdateStatsJob.php", near_miss, facts) == []
    assert len(rule.analyze_regex("app/Jobs/SyncBillingJob.php", invalid, facts)) == 1


def test_job_http_call_missing_timeout_batch3_valid_near_invalid():
    rule = JobHttpCallMissingTimeoutRule(
        RuleConfig(
            thresholds={
                "require_queue_capability": True,
                "min_confidence": 0.6,
            }
        )
    )
    facts = Facts(project_path=".")
    _enable_capability(facts, "external_integrations_heavy")

    valid = """
<?php
class SyncBillingJob implements ShouldQueue {
    public function handle(): void {
        Http::timeout(10)->post('https://api.example.com/sync', []);
    }
}
"""
    near_miss = """
<?php
class SyncBillingJob implements ShouldQueue {
    private int $defaultTimeout = 10;
    public function handle(): void {
        Http::post('https://api.example.com/sync', []);
    }
}
"""
    invalid = """
<?php
class SyncBillingJob implements ShouldQueue {
    public function handle(): void {
        Http::post('https://api.example.com/sync', []);
    }
}
"""

    assert rule.analyze_regex("app/Jobs/SyncBillingJob.php", valid, facts) == []
    assert rule.analyze_regex("app/Jobs/SyncBillingJob.php", near_miss, facts) == []
    assert len(rule.analyze_regex("app/Jobs/SyncBillingJob.php", invalid, facts)) == 1


def test_batch3_context_matrix_calibration_entries_are_active():
    matrix = ContextProfileMatrix.load_default()

    default_ctx = matrix.resolve_context()
    queue_ctx = matrix.resolve_context(explicit_capabilities={"queue_heavy": True})
    api_ctx = matrix.resolve_context(explicit_profile="api-first", explicit_project_type="api_backend")

    assert matrix.calibrate_rule("job-missing-idempotency-guard", default_ctx)["enabled"] is False
    assert matrix.calibrate_rule("job-missing-idempotency-guard", queue_ctx)["enabled"] is True
    assert matrix.calibrate_rule("job-missing-retry-policy", queue_ctx)["enabled"] is True
    assert matrix.calibrate_rule("job-http-call-missing-timeout", queue_ctx)["enabled"] is True

    api_resource = matrix.calibrate_rule("missing-api-resource", api_ctx)
    api_resource_usage = matrix.calibrate_rule("api-resource-usage", api_ctx)
    assert api_resource["severity"] == "high"
    assert api_resource_usage["severity"] in {"medium", "high"}
