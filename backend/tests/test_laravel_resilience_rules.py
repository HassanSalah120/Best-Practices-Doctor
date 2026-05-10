from __future__ import annotations

from rules.laravel.api_endpoint_missing_idempotency_key import ApiEndpointMissingIdempotencyKeyRule
from rules.laravel.cache_missing_fallback import CacheMissingFallbackRule
from rules.laravel.http_call_missing_fallback import HttpCallMissingFallbackRule
from rules.laravel.queue_job_missing_failure_handling import QueueJobMissingFailureHandlingRule
from schemas.facts import Facts


def _facts() -> Facts:
    return Facts(project_path=".")


def _php(body: str) -> str:
    return "<?php\n" + body


def test_api_endpoint_missing_idempotency_key_valid_guarded_endpoint():
    rule = ApiEndpointMissingIdempotencyKeyRule()
    content = _php(
        """
class CheckoutController {
    public function store(Request $request) {
        $key = $request->header('Idempotency-Key');
        return Idempotency::run($key, fn () => Order::create($request->validated()));
    }
}
""",
    )

    assert rule.analyze_regex("app/Http/Controllers/CheckoutController.php", content, _facts()) == []


def test_api_endpoint_missing_idempotency_key_invalid_mutating_endpoint():
    rule = ApiEndpointMissingIdempotencyKeyRule()
    content = _php(
        """
class CheckoutController {
    public function store(Request $request) {
        return Order::create($request->validated());
    }
}
""",
    )

    findings = rule.analyze_regex("app/Http/Controllers/CheckoutController.php", content, _facts())
    assert len(findings) == 1
    assert findings[0].rule_id == "api-endpoint-missing-idempotency-key"


def test_api_endpoint_missing_idempotency_key_fp_guard_read_only_method():
    rule = ApiEndpointMissingIdempotencyKeyRule()
    content = _php(
        """
class CheckoutController {
    public function index(Request $request) {
        return Order::query()->latest()->paginate();
    }
}
""",
    )

    assert rule.analyze_regex("app/Http/Controllers/CheckoutController.php", content, _facts()) == []


def test_http_call_missing_fallback_invalid_unassigned_call():
    rule = HttpCallMissingFallbackRule()
    content = _php(
        """
class PaymentGateway {
    public function charge(array $payload): void {
        Http::post('https://pay.example/charge', $payload);
    }
}
""",
    )

    findings = rule.analyze_ast("app/Services/PaymentGateway.php", content, _facts())
    assert len(findings) == 1
    assert findings[0].rule_id == "http-call-missing-fallback"


def test_http_call_missing_fallback_valid_try_catch():
    rule = HttpCallMissingFallbackRule()
    content = _php(
        """
class PaymentGateway {
    public function charge(array $payload): void {
        try {
            Http::timeout(5)->post('https://pay.example/charge', $payload);
        } catch (Throwable $e) {
            report($e);
        }
    }
}
""",
    )

    assert rule.analyze_ast("app/Services/PaymentGateway.php", content, _facts()) == []


def test_http_call_missing_fallback_valid_assigned_response_guard():
    rule = HttpCallMissingFallbackRule()
    content = _php(
        """
class PaymentGateway {
    public function charge(array $payload): void {
        $response = Http::timeout(5)->withToken($token)->post('https://pay.example/charge', $payload);
        if ($response->successful()) {
            return;
        }
        report($response->status());
    }
}
""",
    )

    assert rule.analyze_ast("app/Services/PaymentGateway.php", content, _facts()) == []


def test_http_call_missing_fallback_fp_guard_fake_is_ignored():
    rule = HttpCallMissingFallbackRule()
    content = _php(
        """
class PaymentGatewayTest {
    public function fake(): void {
        Http::fake();
    }
}
""",
    )

    assert rule.analyze_ast("tests/Feature/PaymentGatewayTest.php", content, _facts()) == []


def test_queue_job_missing_failure_handling_valid_failed_handler():
    rule = QueueJobMissingFailureHandlingRule()
    content = _php(
        """
class SyncInvoice implements ShouldQueue {
    public function handle(): void {
        Http::post('https://billing.example/sync');
    }
    public function failed(Throwable $e): void {
        report($e);
    }
}
""",
    )

    assert rule.analyze_regex("app/Jobs/SyncInvoice.php", content, _facts()) == []


def test_queue_job_missing_failure_handling_invalid_side_effecting_job():
    rule = QueueJobMissingFailureHandlingRule()
    content = _php(
        """
class SyncInvoice implements ShouldQueue {
    public function handle(): void {
        Http::post('https://billing.example/sync');
    }
}
""",
    )

    findings = rule.analyze_regex("app/Jobs/SyncInvoice.php", content, _facts())
    assert len(findings) == 1
    assert findings[0].rule_id == "queue-job-missing-failure-handling"


def test_queue_job_missing_failure_handling_fp_guard_no_side_effects():
    rule = QueueJobMissingFailureHandlingRule()
    content = _php(
        """
class CalculateTotals implements ShouldQueue {
    public function handle(): void {
        $total = collect([1, 2, 3])->sum();
    }
}
""",
    )

    assert rule.analyze_regex("app/Jobs/CalculateTotals.php", content, _facts()) == []


def test_cache_missing_fallback_invalid_array_access_reports_usage_line():
    rule = CacheMissingFallbackRule()
    content = _php(
        """
class ProfileService {
    public function name(): string {
        $user = Cache::get('current-user');
        return $user['name'];
    }
}
""",
    )

    findings = rule.analyze_ast("app/Services/ProfileService.php", content, _facts())
    assert len(findings) == 1
    assert findings[0].rule_id == "cache-missing-fallback"
    assert findings[0].line_start == 6


def test_cache_missing_fallback_invalid_unassigned_call():
    rule = CacheMissingFallbackRule()
    content = _php(
        """
class ProfileService {
    public function cached() {
        return Cache::get('current-user');
    }
}
""",
    )

    findings = rule.analyze_ast("app/Services/ProfileService.php", content, _facts())
    assert len(findings) == 1


def test_cache_missing_fallback_valid_default_argument():
    rule = CacheMissingFallbackRule()
    content = _php(
        """
class ProfileService {
    public function cached(): array {
        return Cache::get('current-user', []);
    }
}
""",
    )

    assert rule.analyze_ast("app/Services/ProfileService.php", content, _facts()) == []


def test_cache_missing_fallback_fp_guard_coalescing_assignment():
    rule = CacheMissingFallbackRule()
    content = _php(
        """
class ProfileService {
    public function cached(): array {
        $user = Cache::get('current-user') ?? [];
        return $user['name'] ?? null;
    }
}
""",
    )

    assert rule.analyze_ast("app/Services/ProfileService.php", content, _facts()) == []


def test_cache_missing_fallback_valid_null_guard_before_deref():
    rule = CacheMissingFallbackRule()
    content = _php(
        """
class ProfileService {
    public function cached(): ?string {
        $user = Cache::get('current-user');
        if ($user === null) {
            return null;
        }
        return $user->name();
    }
}
""",
    )

    assert rule.analyze_ast("app/Services/ProfileService.php", content, _facts()) == []
