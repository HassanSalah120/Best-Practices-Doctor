"""Laravel rules init."""
from .fat_controller import FatControllerRule
from .missing_form_request import MissingFormRequestRule
from .service_extraction import ServiceExtractionRule
from .enum_suggestion import EnumSuggestionRule
from .blade_queries import BladeQueriesRule
from .repository_suggestion import RepositorySuggestionRule
from .contract_suggestion import ContractSuggestionRule
from .custom_exception_suggestion import CustomExceptionSuggestionRule
from .eager_loading import EagerLoadingRule
from .n_plus_one_risk import NPlusOneRiskRule
from .env_usage import EnvOutsideConfigRule
from .ioc_instead_of_new import IocInsteadOfNewRule
from .controller_query_direct import ControllerQueryDirectRule
from .controller_business_logic import ControllerBusinessLogicRule
from .controller_validation_inline import ControllerInlineValidationRule
from .controller_index_filter_duplication import ControllerIndexFilterDuplicationRule
from .dto_suggestion import DtoSuggestionRule
from .mass_assignment_risk import MassAssignmentRiskRule
from .action_class_suggestion import ActionClassSuggestionRule
from .action_class_naming_consistency import ActionClassNamingConsistencyRule
from .massive_model import MassiveModelRule
from .model_cross_model_query import ModelCrossModelQueryRule
from .unsafe_file_upload import UnsafeFileUploadRule
from .no_json_encode_in_controllers import NoJsonEncodeInControllersRule
from .api_resource_usage import ApiResourceUsageRule
from .no_log_debug_in_app import NoLogDebugInAppRule
from .no_closure_routes import NoClosureRoutesRule
from .heavy_logic_in_routes import HeavyLogicInRoutesRule
from .duplicate_route_definition import DuplicateRouteDefinitionRule
from .missing_rate_limiting import MissingRateLimitingRule
from .missing_throttle_on_auth_api_routes import MissingThrottleOnAuthApiRoutesRule
from .missing_auth_on_mutating_api_routes import MissingAuthOnMutatingApiRoutesRule
from .policy_coverage_on_mutations import PolicyCoverageOnMutationsRule
from .authorization_bypass_risk import AuthorizationBypassRiskRule
from .transaction_required_for_multi_write import TransactionRequiredForMultiWriteRule
from .tenant_scope_enforcement import TenantScopeEnforcementRule
from .unused_service_class import UnusedServiceClassRule
from .blade_xss_risk import BladeXssRiskRule
from .user_model_missing_must_verify_email import UserModelMissingMustVerifyEmailRule
from .registration_missing_registered_event import RegistrationMissingRegisteredEventRule
from .missing_foreign_key_in_migration import MissingForeignKeyInMigrationRule
from .missing_index_on_lookup_columns import MissingIndexOnLookupColumnsRule
from .destructive_migration_without_safety_guard import DestructiveMigrationWithoutSafetyGuardRule
from .model_hidden_sensitive_attributes_missing import ModelHiddenSensitiveAttributesMissingRule
from .sensitive_model_appends_risk import SensitiveModelAppendsRiskRule
from .sensitive_routes_missing_verified_middleware import SensitiveRoutesMissingVerifiedMiddlewareRule
from .tenant_access_middleware_missing import TenantAccessMiddlewareMissingRule
from .signed_routes_missing_signature_middleware import SignedRoutesMissingSignatureMiddlewareRule
from .unsafe_redirect import UnsafeRedirectRule
from .unsafe_external_redirect import UnsafeExternalRedirectRule
from .unvalidated_login_redirect import UnvalidatedLoginRedirectRule
from .authorization_missing_on_sensitive_reads import AuthorizationMissingOnSensitiveReadsRule
from .insecure_session_cookie_config import InsecureSessionCookieConfigRule
from .unsafe_csp_policy import UnsafeCspPolicyRule
from .ssrf_risk_http_client import SsrfRiskHttpClientRule
from .path_traversal_file_access import PathTraversalFileAccessRule
from .insecure_file_download_response import InsecureFileDownloadResponseRule
from .webhook_signature_missing import WebhookSignatureMissingRule
from .webhook_replay_protection_missing import WebhookReplayProtectionMissingRule
from .idor_risk_missing_ownership_check import IdorRiskMissingOwnershipCheckRule
from .sensitive_route_rate_limit_missing import SensitiveRouteRateLimitMissingRule
from .sanctum_token_scope_missing import SanctumTokenScopeMissingRule
from .session_fixation_regenerate_missing import SessionFixationRegenerateMissingRule
from .weak_password_policy_validation import WeakPasswordPolicyValidationRule
from .upload_mime_extension_mismatch import UploadMimeExtensionMismatchRule
from .archive_upload_zip_slip_risk import ArchiveUploadZipSlipRiskRule
from .upload_size_limit_missing import UploadSizeLimitMissingRule
from .csrf_exception_wildcard_risk import CsrfExceptionWildcardRiskRule
from .host_header_poisoning_risk import HostHeaderPoisoningRiskRule
from .xml_xxe_risk import XmlXxeRiskRule
from .zip_bomb_risk import ZipBombRiskRule
from .sensitive_response_cache_control_missing import SensitiveResponseCacheControlMissingRule
from .password_reset_token_hardening_missing import PasswordResetTokenHardeningMissingRule
from .security_headers_baseline_missing import SecurityHeadersBaselineMissingRule
from .job_missing_idempotency_guard import JobMissingIdempotencyGuardRule
from .composer_dependency_below_secure_version import ComposerDependencyBelowSecureVersionRule
from .npm_dependency_below_secure_version import NpmDependencyBelowSecureVersionRule
from .inertia_shared_props_sensitive_data import InertiaSharedPropsSensitiveDataRule
from .inertia_shared_props_eager_query import InertiaSharedPropsEagerQueryRule
from .inertia_shared_props_payload_budget import InertiaSharedPropsPayloadBudgetRule
from .job_missing_retry_policy import JobMissingRetryPolicyRule
from .job_http_call_missing_timeout import JobHttpCallMissingTimeoutRule
from .notification_shouldqueue_missing import NotificationShouldQueueMissingRule
from .listener_shouldqueue_missing_for_io_bound_handler import ListenerShouldQueueMissingForIoBoundHandlerRule
from .broadcast_channel_authorization_missing import BroadcastChannelAuthorizationMissingRule
from .observer_heavy_logic import ObserverHeavyLogicRule
from .public_api_versioning_missing import PublicApiVersioningMissingRule
from .error_pages_missing import ErrorPagesMissingRule
from .missing_hsts_header import MissingHstsHeaderRule
from .cookie_samesite_missing import CookieSameSiteMissingRule
from .timing_attack_token_comparison import TimingAttackTokenComparisonRule
from .password_hash_weak_algorithm import PasswordHashWeakAlgorithmRule
from .api_debug_trace_leak import ApiDebugTraceLeakRule
from .plain_text_sensitive_config import PlainTextSensitiveConfigRule
from .livewire_public_prop_mass_assignment import LivewirePublicPropMassAssignmentRule
from .missing_content_security_policy import MissingContentSecurityPolicyRule
from .debug_exposure_risk import DebugExposureRiskRule
# New performance and security rules
from .hardcoded_secrets import HardcodedSecretsRule
from .sensitive_data_logging import SensitiveDataLoggingRule
from .column_selection_suggestion import ColumnSelectionSuggestionRule
from .sql_injection_risk import SqlInjectionRiskRule
from .missing_cache_for_reference_data import MissingCacheForReferenceDataRule
from .insecure_random_for_security import InsecureRandomForSecurityRule
from .debug_mode_exposure import DebugModeExposureRule
from .missing_https_enforcement import MissingHttpsEnforcementRule
from .null_filtering_suggestion import NullFilteringSuggestionRule
from .asset_versioning_check import AssetVersioningCheckRule
# Phase 1 security rules
from .cors_misconfiguration import CorsMisconfigurationRule
from .missing_csrf_token_verification import MissingCsrfTokenVerificationRule
from .insecure_deserialization import InsecureDeserializationRule
# Phase 2 performance rules
from .missing_pagination import MissingPaginationRule
# Phase 3 architecture rules
from .controller_returning_view_in_api import ControllerReturningViewInApiRule
from .missing_api_resource import MissingApiResourceRule

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
    "JobMissingIdempotencyGuardRule",
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
]
