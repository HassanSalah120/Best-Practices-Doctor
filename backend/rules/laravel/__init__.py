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
from .dto_suggestion import DtoSuggestionRule
from .mass_assignment_risk import MassAssignmentRiskRule
from .action_class_suggestion import ActionClassSuggestionRule
from .massive_model import MassiveModelRule
from .unsafe_file_upload import UnsafeFileUploadRule
from .no_json_encode_in_controllers import NoJsonEncodeInControllersRule
from .api_resource_usage import ApiResourceUsageRule
from .no_log_debug_in_app import NoLogDebugInAppRule
from .no_closure_routes import NoClosureRoutesRule
from .heavy_logic_in_routes import HeavyLogicInRoutesRule
from .duplicate_route_definition import DuplicateRouteDefinitionRule
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
from .sensitive_routes_missing_verified_middleware import SensitiveRoutesMissingVerifiedMiddlewareRule
from .tenant_access_middleware_missing import TenantAccessMiddlewareMissingRule
from .signed_routes_missing_signature_middleware import SignedRoutesMissingSignatureMiddlewareRule
from .unsafe_external_redirect import UnsafeExternalRedirectRule
from .authorization_missing_on_sensitive_reads import AuthorizationMissingOnSensitiveReadsRule
from .insecure_session_cookie_config import InsecureSessionCookieConfigRule
from .unsafe_csp_policy import UnsafeCspPolicyRule
from .job_missing_idempotency_guard import JobMissingIdempotencyGuardRule
from .composer_dependency_below_secure_version import ComposerDependencyBelowSecureVersionRule
from .npm_dependency_below_secure_version import NpmDependencyBelowSecureVersionRule
from .inertia_shared_props_sensitive_data import InertiaSharedPropsSensitiveDataRule
from .inertia_shared_props_eager_query import InertiaSharedPropsEagerQueryRule
from .job_missing_retry_policy import JobMissingRetryPolicyRule
from .job_http_call_missing_timeout import JobHttpCallMissingTimeoutRule
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
    "DtoSuggestionRule",
    "MassAssignmentRiskRule",
    "ActionClassSuggestionRule",
    "MassiveModelRule",
    "UnsafeFileUploadRule",
    "NoJsonEncodeInControllersRule",
    "ApiResourceUsageRule",
    "NoLogDebugInAppRule",
    "NoClosureRoutesRule",
    "HeavyLogicInRoutesRule",
    "DuplicateRouteDefinitionRule",
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
    "SensitiveRoutesMissingVerifiedMiddlewareRule",
    "TenantAccessMiddlewareMissingRule",
    "SignedRoutesMissingSignatureMiddlewareRule",
    "UnsafeExternalRedirectRule",
    "AuthorizationMissingOnSensitiveReadsRule",
    "InsecureSessionCookieConfigRule",
    "UnsafeCspPolicyRule",
    "JobMissingIdempotencyGuardRule",
    "ComposerDependencyBelowSecureVersionRule",
    "NpmDependencyBelowSecureVersionRule",
    "InertiaSharedPropsSensitiveDataRule",
    "InertiaSharedPropsEagerQueryRule",
    "JobMissingRetryPolicyRule",
    "JobHttpCallMissingTimeoutRule",
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
