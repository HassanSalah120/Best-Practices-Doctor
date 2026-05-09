from __future__ import annotations

from pathlib import Path

from core.ruleset import RuleConfig
from rules.laravel.controller_business_logic import ControllerBusinessLogicRule
from rules.laravel.dto_suggestion import DtoSuggestionRule
from rules.laravel.missing_content_security_policy import MissingContentSecurityPolicyRule
from rules.laravel.missing_hsts_header import MissingHstsHeaderRule
from rules.laravel.missing_index_on_lookup_columns import MissingIndexOnLookupColumnsRule
from rules.laravel.model_hidden_sensitive_attributes_missing import (
    ModelHiddenSensitiveAttributesMissingRule,
)
from rules.laravel.notification_shouldqueue_missing import NotificationShouldQueueMissingRule
from rules.laravel.plain_text_sensitive_config import PlainTextSensitiveConfigRule
from rules.laravel.sensitive_model_appends_risk import SensitiveModelAppendsRiskRule
from rules.laravel.service_extraction import ServiceExtractionRule
from rules.laravel.upload_size_limit_missing import UploadSizeLimitMissingRule
from rules.laravel.webhook_replay_protection_missing import WebhookReplayProtectionMissingRule
from rules.php.unsafe_file_include_variable import UnsafeFileIncludeVariableRule
from schemas.facts import (
    AssocArrayLiteral,
    ClassInfo,
    Facts,
    MethodInfo,
    MigrationTableChange,
    ModelAttributeConfig,
    RouteInfo,
    UseImport,
)
from schemas.metrics import MethodMetrics


def _class(name: str, fqcn: str, file_path: str, *, extends: str | None = None, implements: list[str] | None = None) -> ClassInfo:
    return ClassInfo(
        name=name,
        fqcn=fqcn,
        file_path=file_path,
        file_hash="fixture",
        extends=extends,
        implements=implements or [],
    )


def _method(
    class_name: str,
    class_fqcn: str,
    name: str,
    file_path: str,
    *,
    call_sites: list[str] | None = None,
    parameters: list[str] | None = None,
    loc: int = 40,
) -> MethodInfo:
    return MethodInfo(
        name=name,
        class_name=class_name,
        class_fqcn=class_fqcn,
        file_path=file_path,
        file_hash="fixture",
        line_start=10,
        line_end=10 + max(5, loc),
        loc=loc,
        call_sites=call_sites or [],
        parameters=parameters or [],
    )


def test_notification_shouldqueue_missing_skips_when_parent_chain_implements_interface():
    rule = NotificationShouldQueueMissingRule(RuleConfig())
    facts = Facts(project_path=".")

    base = _class(
        name="BaseQueueableNotification",
        fqcn="App\\Notifications\\BaseQueueableNotification",
        file_path="app/Notifications/BaseQueueableNotification.php",
        implements=["Illuminate\\Contracts\\Queue\\ShouldQueue"],
    )
    child = _class(
        name="BillingDebtNudgeNotification",
        fqcn="App\\Notifications\\BillingDebtNudgeNotification",
        file_path="app/Notifications/BillingDebtNudgeNotification.php",
        extends="BaseQueueableNotification",
    )
    facts.classes = [base, child]
    facts.notifications = [child]
    facts.methods = [
        _method(
            class_name="BillingDebtNudgeNotification",
            class_fqcn="App\\Notifications\\BillingDebtNudgeNotification",
            name="toMail",
            file_path="app/Notifications/BillingDebtNudgeNotification.php",
            call_sites=["MailMessage::make();"],
        ),
    ]

    assert rule.analyze(facts) == []


def test_missing_index_on_lookup_columns_skips_change_operation_snippet():
    rule = MissingIndexOnLookupColumnsRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.migration_table_changes = [
        MigrationTableChange(
            file_path="database/migrations/2026_03_02_000014_modify_insurance_claims_invoice_id.php",
            line_number=12,
            table_name="insurance_claims",
            operation="add_column",
            column_name="invoice_id",
            column_type="uuid",
            snippet="$table->uuid('invoice_id')->nullable()->change();",
        ),
    ]

    assert rule.analyze(facts) == []


def test_missing_content_security_policy_skips_when_header_exists_in_security_middleware(tmp_path: Path):
    rule = MissingContentSecurityPolicyRule(RuleConfig())
    project_root = tmp_path
    middleware_file = project_root / "app/Http/Middleware/SecurityHeadersMiddleware.php"
    middleware_file.parent.mkdir(parents=True, exist_ok=True)
    middleware_file.write_text(
        "<?php $response->headers->set('Content-Security-Policy', \"default-src 'self'\");",
        encoding="utf-8",
    )

    kernel_rel = "app/Http/Kernel.php"
    facts = Facts(
        project_path=str(project_root),
        files=[kernel_rel, "app/Http/Middleware/SecurityHeadersMiddleware.php"],
    )
    kernel_payload = "<?php class Kernel { protected $middleware = ['auth']; }"

    assert rule.analyze_regex(kernel_rel, kernel_payload, facts) == []


def test_missing_hsts_header_skips_when_header_exists_in_security_middleware(tmp_path: Path):
    rule = MissingHstsHeaderRule(RuleConfig())
    project_root = tmp_path
    middleware_file = project_root / "app/Http/Middleware/SecurityHeadersMiddleware.php"
    middleware_file.parent.mkdir(parents=True, exist_ok=True)
    middleware_file.write_text(
        "<?php $response->headers->set('Strict-Transport-Security', 'max-age=31536000');",
        encoding="utf-8",
    )

    kernel_rel = "app/Http/Kernel.php"
    facts = Facts(
        project_path=str(project_root),
        files=[kernel_rel, "app/Http/Middleware/SecurityHeadersMiddleware.php"],
    )
    kernel_payload = "<?php class Kernel { protected $middleware = ['auth']; }"

    assert rule.analyze_regex(kernel_rel, kernel_payload, facts) == []


def test_webhook_replay_protection_missing_skips_replay_guard_middleware():
    rule = WebhookReplayProtectionMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.routes = [
        RouteInfo(
            method="POST",
            uri="/webhooks/paymob",
            controller="PaymentCallbackController",
            action="handlePaymobWebhook",
            middleware=["webhook_replay_guard"],
            file_path="routes/webhooks.php",
            line_number=8,
        ),
    ]
    facts.methods = [
        _method(
            class_name="PaymentCallbackController",
            class_fqcn="App\\Http\\Controllers\\PaymentCallbackController",
            name="handlePaymobWebhook",
            file_path="app/Http/Controllers/PaymentCallbackController.php",
            call_sites=["$this->validateSignature($payload);"],
        ),
    ]

    assert rule.analyze(facts) == []


def test_model_hidden_sensitive_attributes_missing_skips_boolean_status_appends():
    rule = ModelHiddenSensitiveAttributesMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.model_attribute_configs = [
        ModelAttributeConfig(
            file_path="app/Models/User.php",
            line_number=50,
            model_name="User",
            property_name="hidden",
            values=["password", "remember_token", "two_factor_secret", "two_factor_recovery_codes"],
        ),
        ModelAttributeConfig(
            file_path="app/Models/User.php",
            line_number=68,
            model_name="User",
            property_name="appends",
            values=["profile_photo_url", "two_factor_enabled"],
        ),
    ]

    assert rule.analyze(facts) == []


def test_sensitive_model_appends_risk_skips_boolean_status_flags():
    rule = SensitiveModelAppendsRiskRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.model_attribute_configs = [
        ModelAttributeConfig(
            file_path="app/Models/User.php",
            line_number=68,
            model_name="User",
            property_name="appends",
            values=["profile_photo_url", "two_factor_enabled"],
        ),
    ]

    assert rule.analyze(facts) == []


def test_plain_text_sensitive_config_skips_identifier_values_in_permission_config():
    rule = PlainTextSensitiveConfigRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
return [
    'passwords' => 'users',
    'model_morph_key' => 'model_id',
    'team_foreign_key' => 'team_id',
    'key' => 'spatie.permission.cache',
];
"""

    assert rule.analyze_regex("config/permission.php", content, facts) == []


def test_unsafe_file_include_variable_skips_static_dir_assignment_pattern():
    rule = UnsafeFileIncludeVariableRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
if (file_exists($maintenance = __DIR__.'/../storage/framework/maintenance.php')) {
    require $maintenance;
}
"""

    assert rule.analyze_regex("public/index.php", content, facts) == []


def test_upload_size_limit_missing_skips_when_manual_guard_exists():
    rule = UploadSizeLimitMissingRule(RuleConfig())
    facts = Facts(project_path=".")
    content = """
<?php
class ImportInventoryCsvAction
{
    public function execute(UploadedFile $file): int
    {
        $maxUploadKb = 2048;
        $sizeInBytes = $file->getSize();
        $maxBytes = $maxUploadKb * 1024;
        if ($sizeInBytes > $maxBytes) { abort(422); }
        validator(['file' => $file], ['file' => ['required', 'file', 'mimes:csv,txt']])->validate();
        return 1;
    }
}
"""

    assert rule.analyze_regex("app/Actions/Inventory/ImportInventoryCsvAction.php", content, facts) == []


def test_service_extraction_skips_thin_controller_when_service_property_is_used():
    rule = ServiceExtractionRule(RuleConfig())
    facts = Facts(project_path=".")
    controller = _class(
        name="BillingWebhooksController",
        fqcn="App\\Http\\Controllers\\BillingWebhooksController",
        file_path="app/Http/Controllers/BillingWebhooksController.php",
    )
    facts.controllers = [controller]
    facts.methods = [
        _method(
            class_name="BillingWebhooksController",
            class_fqcn="App\\Http\\Controllers\\BillingWebhooksController",
            name="retry",
            file_path="app/Http/Controllers/BillingWebhooksController.php",
            loc=90,
            parameters=["Request $request", "string $id"],
            call_sites=[
                "$event = $this->events->findById($id);",
                "$this->authorize('retry', $event);",
                "$this->service->retry($id);",
                "$this->auditLog->log('retry', $event);",
                "session()->flash('status', 'Webhook retried');",
                "return redirect()->back();",
            ],
        ),
    ]

    assert rule.analyze(facts) == []


def test_controller_business_logic_skips_delegated_service_orchestration():
    rule = ControllerBusinessLogicRule(RuleConfig())
    method = _method(
        class_name="InvoiceController",
        class_fqcn="App\\Http\\Controllers\\InvoiceController",
        name="downloadPdf",
        file_path="app/Http/Controllers/InvoiceController.php",
        loc=95,
        parameters=["Request $request", "string $id"],
        call_sites=[
            "$invoice = $this->service->getInvoice($id);",
            "if (! $invoice) { abort(404); }",
            "$this->authorize('download', $invoice);",
            "$response = $this->service->downloadPdfResponse($id, $request->boolean('inline'));",
            "if (! $response) { abort(404); }",
            "return $response;",
        ],
    )
    facts = Facts(project_path=".")
    facts.controllers = [
        _class(
            name="InvoiceController",
            fqcn="App\\Http\\Controllers\\InvoiceController",
            file_path="app/Http/Controllers/InvoiceController.php",
        ),
    ]
    facts.methods = [method]
    metrics = {
        method.method_fqn: MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=8,
            has_business_logic=True,
            business_logic_confidence=0.75,
            query_count=1,
            validation_count=1,
            conditional_count=4,
            loop_count=0,
            has_external_api_calls=False,
            has_file_operations=False,
        ),
    }

    assert rule.analyze(facts, metrics=metrics) == []


def test_dto_suggestion_skips_actions_already_importing_dto_contracts():
    rule = DtoSuggestionRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.use_imports = [
        UseImport(
            file_path="app/Actions/Billing/GetBillingLedgerAction.php",
            line_number=6,
            fqcn="App\\DTOs\\Billing\\BillingLedgerFiltersDTO",
        ),
    ]
    facts.assoc_arrays = [
        AssocArrayLiteral(
            file_path="app/Actions/Billing/GetBillingLedgerAction.php",
            line_number=42,
            method_name="execute",
            class_fqcn="App\\Actions\\Billing\\GetBillingLedgerAction",
            key_count=14,
            used_as="assignment",
            target="payload",
            snippet="['clinic_id' => $clinicId, ...]",
        ),
    ]

    assert rule.analyze(facts) == []


def test_dto_suggestion_skips_middleware_prop_bags_and_transport_layers():
    rule = DtoSuggestionRule(RuleConfig())
    facts = Facts(project_path=".")
    facts.assoc_arrays = [
        AssocArrayLiteral(
            file_path="app/Http/Middleware/ShareJetstreamData.php",
            line_number=61,
            method_name="share",
            class_fqcn="App\\Http\\Middleware\\ShareJetstreamData",
            key_count=12,
            used_as="return",
            target="share",
            snippet="['auth' => [...], 'flash' => [...]]",
        ),
        AssocArrayLiteral(
            file_path="app/Actions/Dashboard/GetPlatformCommunicationAction.php",
            line_number=27,
            method_name="buildPayload",
            class_fqcn="App\\Actions\\Dashboard\\GetPlatformCommunicationAction",
            key_count=14,
            used_as="return",
            target="response",
            snippet="['alerts' => [...], 'messages' => [...]]",
        ),
    ]

    assert rule.analyze(facts) == []


def test_service_extraction_skips_service_controller_with_dto_orchestration():
    rule = ServiceExtractionRule(RuleConfig())
    facts = Facts(project_path=".")
    controller = _class(
        name="ServiceController",
        fqcn="App\\Http\\Controllers\\ServiceController",
        file_path="app/Http/Controllers/ServiceController.php",
    )
    facts.controllers = [controller]
    facts.methods = [
        _method(
            class_name="ServiceController",
            class_fqcn="App\\Http\\Controllers\\ServiceController",
            name="__construct",
            file_path="app/Http/Controllers/ServiceController.php",
            loc=8,
            parameters=["ServiceServiceInterface $service"],
            call_sites=[],
        ),
        _method(
            class_name="ServiceController",
            class_fqcn="App\\Http\\Controllers\\ServiceController",
            name="index",
            file_path="app/Http/Controllers/ServiceController.php",
            loc=68,
            parameters=["ServiceIndexFiltersDTO $filtersDto", "Request $request"],
            call_sites=[
                "$filters = ServiceIndexFiltersDTO::from($request->validated());",
                "$services = $this->service->index($filters);",
                "return Inertia::render('Services/Index', ['services' => $services]);",
            ],
        ),
        _method(
            class_name="ServiceController",
            class_fqcn="App\\Http\\Controllers\\ServiceController",
            name="store",
            file_path="app/Http/Controllers/ServiceController.php",
            loc=66,
            parameters=["StoreServiceDTO $dto", "Request $request"],
            call_sites=[
                "$payload = StoreServiceDTO::from($request->validated());",
                "$service = $this->service->store($payload);",
                "return redirect()->route('services.show', $service);",
            ],
        ),
    ]

    assert rule.analyze(facts) == []
