"""Laravel rules init."""
from .action_class_naming_consistency import ActionClassNamingConsistencyRule
from .action_class_suggestion import ActionClassSuggestionRule
from .api_debug_trace_leak import ApiDebugTraceLeakRule
from .api_endpoint_missing_idempotency_key import ApiEndpointMissingIdempotencyKeyRule
from .api_resource_usage import ApiResourceUsageRule
from .api_response_inconsistent_shape import ApiResponseInconsistentShapeRule
from .archive_upload_zip_slip_risk import ArchiveUploadZipSlipRiskRule
from .asset_versioning_check import AssetVersioningCheckRule
from .authorization_bypass_risk import AuthorizationBypassRiskRule
from .authorization_missing_on_sensitive_reads import AuthorizationMissingOnSensitiveReadsRule
from .blade_component_no_fallback_slot import BladeComponentNoFallbackSlotRule
from .blade_queries import BladeQueriesRule
from .blade_xss_risk import BladeXssRiskRule
from .broadcast_channel_authorization_missing import BroadcastChannelAuthorizationMissingRule
from .business_logic_in_migration import BusinessLogicInMigrationRule
from .cache_missing_fallback import CacheMissingFallbackRule
from .cache_stampede_risk import CacheStampedeRiskRule
from .chunk_missing_for_large_datasets import ChunkMissingForLargeDatasetsRule
from .column_selection_suggestion import ColumnSelectionSuggestionRule
from .composer_dependency_below_secure_version import ComposerDependencyBelowSecureVersionRule
from .console_command_missing_tenant_scope import ConsoleCommandMissingTenantScopeRule
from .contract_suggestion import ContractSuggestionRule
from .controller_business_logic import ControllerBusinessLogicRule
from .controller_index_filter_duplication import ControllerIndexFilterDuplicationRule
from .controller_query_direct import ControllerQueryDirectRule

# Phase 3 architecture rules
from .controller_returning_view_in_api import ControllerReturningViewInApiRule
from .controller_validation_inline import ControllerInlineValidationRule
from .cookie_samesite_missing import CookieSameSiteMissingRule

# Phase 1 security rules
from .cors_misconfiguration import CorsMisconfigurationRule
from .csrf_exception_wildcard_risk import CsrfExceptionWildcardRiskRule
from .custom_exception_suggestion import CustomExceptionSuggestionRule
from .date_format_missing_cast import DateFormatMissingCastRule
from .debug_exposure_risk import DebugExposureRiskRule
from .debug_mode_exposure import DebugModeExposureRule
from .destructive_migration_without_safety_guard import DestructiveMigrationWithoutSafetyGuardRule
from .dto_suggestion import DtoSuggestionRule
from .duplicate_route_definition import DuplicateRouteDefinitionRule
from .eager_loading import EagerLoadingRule
from .eloquent_raw_where_string import EloquentRawWhereStringRule
from .enum_suggestion import EnumSuggestionRule
from .env_usage import EnvOutsideConfigRule
from .error_pages_missing import ErrorPagesMissingRule
from .fat_controller import FatControllerRule
from .forced_login_without_authorization import ForcedLoginWithoutAuthorizationRule
from .hardcoded_magic_strings import HardcodedMagicStringsRule

# New performance and security rules
from .hardcoded_secrets import HardcodedSecretsRule
from .heavy_logic_in_routes import HeavyLogicInRoutesRule
from .high_privilege_action_missing_authorization import HighPrivilegeActionMissingAuthorizationRule
from .host_header_poisoning_risk import HostHeaderPoisoningRiskRule
from .http_call_missing_fallback import HttpCallMissingFallbackRule
from .idor_risk_missing_ownership_check import IdorRiskMissingOwnershipCheckRule
from .inertia_shared_props_eager_query import InertiaSharedPropsEagerQueryRule
from .inertia_shared_props_payload_budget import InertiaSharedPropsPayloadBudgetRule
from .inertia_shared_props_sensitive_data import InertiaSharedPropsSensitiveDataRule
from .insecure_deserialization import InsecureDeserializationRule
from .insecure_file_download_response import InsecureFileDownloadResponseRule
from .insecure_random_for_security import InsecureRandomForSecurityRule
from .insecure_session_cookie_config import InsecureSessionCookieConfigRule
from .ioc_instead_of_new import IocInsteadOfNewRule
from .job_http_call_missing_timeout import JobHttpCallMissingTimeoutRule
from .job_missing_idempotency_guard import JobMissingIdempotencyGuardRule
from .job_missing_retry_policy import JobMissingRetryPolicyRule
from .laravel_naming_conventions import LaravelNamingConventionsRule
from .listener_shouldqueue_missing_for_io_bound_handler import (
    ListenerShouldQueueMissingForIoBoundHandlerRule,
)
from .livewire_public_prop_mass_assignment import LivewirePublicPropMassAssignmentRule
from .mass_assignment_risk import MassAssignmentRiskRule
from .massive_model import MassiveModelRule
from .missing_api_rate_limit_headers import MissingApiRateLimitHeadersRule
from .missing_api_resource import MissingApiResourceRule
from .missing_auth_on_mutating_api_routes import MissingAuthOnMutatingApiRoutesRule
from .missing_cache_for_reference_data import MissingCacheForReferenceDataRule
from .missing_circuit_breaker import MissingCircuitBreakerRule
from .missing_content_security_policy import MissingContentSecurityPolicyRule
from .missing_csrf_token_verification import MissingCsrfTokenVerificationRule
from .missing_domain_event import MissingDomainEventRule
from .missing_feature_flag_pattern import MissingFeatureFlagPatternRule
from .missing_foreign_key_in_migration import MissingForeignKeyInMigrationRule
from .missing_form_request import MissingFormRequestRule
from .missing_health_check_endpoint import MissingHealthCheckEndpointRule
from .missing_hsts_header import MissingHstsHeaderRule
from .missing_https_enforcement import MissingHttpsEnforcementRule
from .missing_index_on_lookup_columns import MissingIndexOnLookupColumnsRule
from .missing_model_factory import MissingModelFactoryRule
from .missing_model_observer_registration import MissingModelObserverRegistrationRule
from .missing_null_guard_after_relation_load import MissingNullGuardAfterRelationLoadRule

# Phase 2 performance rules
from .missing_pagination import MissingPaginationRule
from .missing_rate_limiting import MissingRateLimitingRule
from .missing_throttle_on_auth_api_routes import MissingThrottleOnAuthApiRoutesRule
from .model_cross_model_query import ModelCrossModelQueryRule
from .model_hidden_sensitive_attributes_missing import ModelHiddenSensitiveAttributesMissingRule
from .n_plus_one_risk import NPlusOneRiskRule
from .no_closure_routes import NoClosureRoutesRule
from .no_json_encode_in_controllers import NoJsonEncodeInControllersRule
from .no_log_debug_in_app import NoLogDebugInAppRule
from .no_pagination_on_relationship import NoPaginationOnRelationshipRule
from .notification_shouldqueue_missing import NotificationShouldQueueMissingRule
from .npm_dependency_below_secure_version import NpmDependencyBelowSecureVersionRule
from .null_filtering_suggestion import NullFilteringSuggestionRule
from .observer_heavy_logic import ObserverHeavyLogicRule
from .password_hash_weak_algorithm import PasswordHashWeakAlgorithmRule
from .password_reset_token_hardening_missing import PasswordResetTokenHardeningMissingRule
from .path_traversal_file_access import PathTraversalFileAccessRule
from .plain_text_sensitive_config import PlainTextSensitiveConfigRule
from .policy_coverage_on_mutations import PolicyCoverageOnMutationsRule
from .public_api_versioning_missing import PublicApiVersioningMissingRule
from .queue_job_missing_failure_handling import QueueJobMissingFailureHandlingRule
from .realtime_advisory import (
    PublicAnonymousMutationAbuseReadinessRule,
    RealtimeConfigOutsideLaravelConfigRule,
    RealtimeInMemoryStateScalabilityRule,
    WebSocketHandlerIntegrationTestsMissingRule,
)
from .registration_missing_registered_event import RegistrationMissingRegisteredEventRule
from .repository_suggestion import RepositorySuggestionRule
from .sanctum_token_scope_missing import SanctumTokenScopeMissingRule
# Inventory/dataflow rules
from .missing_inventory_lock_on_decrement import MissingInventoryLockOnDecrementRule
from .negative_stock_not_guarded import NegativeStockNotGuardedRule

# Inertia architecture rules
from .inertia_api_route_returns_inertia import InertiaApiRouteReturnsInertiaRule
from .inertia_conditional_wants_json import InertiaConditionalWantsJsonRule
from .inertia_get_with_side_effects import InertiaGetWithSideEffectsRule
from .inertia_hybrid_controller import InertiaHybridControllerRule
from .inertia_post_returns_render import InertiaPostReturnsRenderRule
from .inertia_route_returns_json_response import InertiaRouteReturnsJsonResponseRule
from .inertia_session_flash_on_api import InertiaSessionFlashOnApiRule

# Other standalone rules
from .composite_index_on_tenant_models import CompositeIndexOnTenantModelsRule
from .controller_inheritance_inconsistency import ControllerInheritanceInconsistencyRule
from .malformed_authorization_call import MalformedAuthorizationCallRule
from .obsolete_x_xss_header import ObsoleteXXssHeaderRule
from .phi_encryption_missing import PhiEncryptionMissingRule
from .tenant_global_scope_missing import TenantGlobalScopeMissingRule

from .sanctum_token_scope_missing import SanctumTokenScopeMissingRule
from .security_headers_baseline_missing import SecurityHeadersBaselineMissingRule
from .sensitive_data_logging import SensitiveDataLoggingRule
from .sensitive_model_appends_risk import SensitiveModelAppendsRiskRule
from .sensitive_response_cache_control_missing import SensitiveResponseCacheControlMissingRule
from .sensitive_route_rate_limit_missing import SensitiveRouteRateLimitMissingRule
from .sensitive_routes_missing_verified_middleware import (
    SensitiveRoutesMissingVerifiedMiddlewareRule,
)
from .service_extraction import ServiceExtractionRule
from .service_provider_heavy_boot import ServiceProviderHeavyBootRule
from .session_fixation_regenerate_missing import SessionFixationRegenerateMissingRule
from .signed_routes_missing_signature_middleware import SignedRoutesMissingSignatureMiddlewareRule
from .sql_injection_risk import SqlInjectionRiskRule
from .ssrf_risk_http_client import SsrfRiskHttpClientRule
from .synchronous_mail_in_request import SynchronousMailInRequestRule
from .tenant_access_middleware_missing import TenantAccessMiddlewareMissingRule
from .tenant_scope_enforcement import TenantScopeEnforcementRule
from .test_no_database_trait import TestNoDatabaseTraitRule
from .timing_attack_token_comparison import TimingAttackTokenComparisonRule
from .transaction_required_for_multi_write import TransactionRequiredForMultiWriteRule
from .unsafe_csp_policy import UnsafeCspPolicyRule
from .unsafe_external_redirect import UnsafeExternalRedirectRule
from .unsafe_file_upload import UnsafeFileUploadRule
from .unsafe_redirect import UnsafeRedirectRule
from .unused_service_class import UnusedServiceClassRule
from .unvalidated_login_redirect import UnvalidatedLoginRedirectRule
from .upload_mime_extension_mismatch import UploadMimeExtensionMismatchRule
from .upload_size_limit_missing import UploadSizeLimitMissingRule
from .url_validation_protocol_bypass import UrlValidationProtocolBypassRule
from .user_model_missing_must_verify_email import UserModelMissingMustVerifyEmailRule
from .weak_password_policy_validation import WeakPasswordPolicyValidationRule
from .webhook_replay_protection_missing import WebhookReplayProtectionMissingRule
from .webhook_signature_missing import WebhookSignatureMissingRule
from .webhook_signature_parameter_unused import WebhookSignatureParameterUnusedRule
from .xml_xxe_risk import XmlXxeRiskRule
from .zip_bomb_risk import ZipBombRiskRule

__all__ = [
    "FatControllerRule",
    "MissingFormRequestRule",
    "ServiceExtractionRule",
    "EnumSuggestionRule",
    "BladeQueriesRule",
    "RepositorySuggestionRule",
    "ContractSuggestionRule",
    "CustomExceptionSuggestionRule",
    "EagerLoadingRule",
    "NPlusOneRiskRule",
    "EnvOutsideConfigRule",
    "IocInsteadOfNewRule",
    "ControllerQueryDirectRule",
    "ControllerBusinessLogicRule",
    "ControllerInlineValidationRule",
    "ControllerIndexFilterDuplicationRule",
    "DtoSuggestionRule",
    "MassAssignmentRiskRule",
    "ActionClassSuggestionRule",
    "ActionClassNamingConsistencyRule",
    "MassiveModelRule",
    "ModelCrossModelQueryRule",
    "UnsafeFileUploadRule",
    "NoJsonEncodeInControllersRule",
    "ApiResourceUsageRule",
    "NoLogDebugInAppRule",
    "NoClosureRoutesRule",
    "HeavyLogicInRoutesRule",
    "DuplicateRouteDefinitionRule",
    "MissingRateLimitingRule",
    "MissingThrottleOnAuthApiRoutesRule",
    "MissingAuthOnMutatingApiRoutesRule",
    "PolicyCoverageOnMutationsRule",
    "AuthorizationBypassRiskRule",
    "TransactionRequiredForMultiWriteRule",
    "TenantScopeEnforcementRule",
    "UnusedServiceClassRule",
    "BladeXssRiskRule",
    "UserModelMissingMustVerifyEmailRule",
    "RegistrationMissingRegisteredEventRule",
    "MissingForeignKeyInMigrationRule",
    "MissingIndexOnLookupColumnsRule",
    "DestructiveMigrationWithoutSafetyGuardRule",
    "ModelHiddenSensitiveAttributesMissingRule",
    "SensitiveModelAppendsRiskRule",
    "SensitiveRoutesMissingVerifiedMiddlewareRule",
    "TenantAccessMiddlewareMissingRule",
    "SignedRoutesMissingSignatureMiddlewareRule",
    "UnsafeRedirectRule",
    "UnsafeExternalRedirectRule",
    "UnvalidatedLoginRedirectRule",
    "AuthorizationMissingOnSensitiveReadsRule",
    "InsecureSessionCookieConfigRule",
    "UnsafeCspPolicyRule",
    "SsrfRiskHttpClientRule",
    "PathTraversalFileAccessRule",
    "InsecureFileDownloadResponseRule",
    "WebhookSignatureMissingRule",
    "WebhookReplayProtectionMissingRule",
    "IdorRiskMissingOwnershipCheckRule",
    "SensitiveRouteRateLimitMissingRule",
    "SanctumTokenScopeMissingRule",
    "SessionFixationRegenerateMissingRule",
    "WeakPasswordPolicyValidationRule",
    "UploadMimeExtensionMismatchRule",
    "ArchiveUploadZipSlipRiskRule",
    "UploadSizeLimitMissingRule",
    "CsrfExceptionWildcardRiskRule",
    "HostHeaderPoisoningRiskRule",
    "XmlXxeRiskRule",
    "ZipBombRiskRule",
    "SensitiveResponseCacheControlMissingRule",
    "PasswordResetTokenHardeningMissingRule",
    "SecurityHeadersBaselineMissingRule",
    "ApiEndpointMissingIdempotencyKeyRule",
    "JobMissingIdempotencyGuardRule",
    "QueueJobMissingFailureHandlingRule",
    "ComposerDependencyBelowSecureVersionRule",
    "NpmDependencyBelowSecureVersionRule",
    "InertiaSharedPropsSensitiveDataRule",
    "InertiaSharedPropsEagerQueryRule",
    "InertiaSharedPropsPayloadBudgetRule",
    "JobMissingRetryPolicyRule",
    "JobHttpCallMissingTimeoutRule",
    "NotificationShouldQueueMissingRule",
    "ListenerShouldQueueMissingForIoBoundHandlerRule",
    "BroadcastChannelAuthorizationMissingRule",
    "ObserverHeavyLogicRule",
    "PublicApiVersioningMissingRule",
    "ErrorPagesMissingRule",
    "MissingHstsHeaderRule",
    "CookieSameSiteMissingRule",
    "TimingAttackTokenComparisonRule",
    "PasswordHashWeakAlgorithmRule",
    "ApiDebugTraceLeakRule",
    "PlainTextSensitiveConfigRule",
    "LivewirePublicPropMassAssignmentRule",
    "MissingContentSecurityPolicyRule",
    "DebugExposureRiskRule",
    # New performance and security rules
    "HardcodedSecretsRule",
    "SensitiveDataLoggingRule",
    "ColumnSelectionSuggestionRule",
    "SqlInjectionRiskRule",
    "MissingCacheForReferenceDataRule",
    "InsecureRandomForSecurityRule",
    "DebugModeExposureRule",
    "MissingHttpsEnforcementRule",
    "NullFilteringSuggestionRule",
    "AssetVersioningCheckRule",
    # Phase 1 security rules
    "CorsMisconfigurationRule",
    "MissingCsrfTokenVerificationRule",
    "InsecureDeserializationRule",
    # Phase 2 performance rules
    "MissingPaginationRule",
    # Phase 3 architecture rules
    "ControllerReturningViewInApiRule",
    "MissingApiResourceRule",
    "CacheStampedeRiskRule",
    "CacheMissingFallbackRule",
    "SynchronousMailInRequestRule",
    "ServiceProviderHeavyBootRule",
    "BusinessLogicInMigrationRule",
    "MissingHealthCheckEndpointRule",
    "MissingModelFactoryRule",
    "TestNoDatabaseTraitRule",
    "MissingCircuitBreakerRule",
    "HttpCallMissingFallbackRule",
    "MissingDomainEventRule",
    "ChunkMissingForLargeDatasetsRule",
    "LaravelNamingConventionsRule",
    "HardcodedMagicStringsRule",
    "DateFormatMissingCastRule",
    "WebhookSignatureParameterUnusedRule",
    "ForcedLoginWithoutAuthorizationRule",
    "ConsoleCommandMissingTenantScopeRule",
    "HighPrivilegeActionMissingAuthorizationRule",
    "UrlValidationProtocolBypassRule",
    "MissingNullGuardAfterRelationLoadRule",
    "MissingApiRateLimitHeadersRule",
    "EloquentRawWhereStringRule",
    "MissingModelObserverRegistrationRule",
    "BladeComponentNoFallbackSlotRule",
    "ApiResponseInconsistentShapeRule",
    "NoPaginationOnRelationshipRule",
    "MissingFeatureFlagPatternRule",
    "RealtimeInMemoryStateScalabilityRule",
    "WebSocketHandlerIntegrationTestsMissingRule",
    "RealtimeConfigOutsideLaravelConfigRule",
    "PublicAnonymousMutationAbuseReadinessRule",
    "MissingInventoryLockOnDecrementRule",
    "NegativeStockNotGuardedRule",
    "InertiaApiRouteReturnsInertiaRule",
    "InertiaConditionalWantsJsonRule",
    "InertiaGetWithSideEffectsRule",
    "InertiaHybridControllerRule",
    "InertiaPostReturnsRenderRule",
    "InertiaRouteReturnsJsonResponseRule",
    "InertiaSessionFlashOnApiRule",
    "CompositeIndexOnTenantModelsRule",
    "ControllerInheritanceInconsistencyRule",
    "MalformedAuthorizationCallRule",
    "ObsoleteXXssHeaderRule",
    "PhiEncryptionMissingRule",
    "TenantGlobalScopeMissingRule",
]
