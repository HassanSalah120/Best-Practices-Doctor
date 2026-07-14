"""
Rule Registry

Rule class registry, discovery, aliases, and validation.
Extracted from rule_engine.py for modularity.
"""

import contextlib
import logging
import os
import pkgutil
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date
from importlib import import_module
from pathlib import Path

from core.context_profiles import (
    ContextProfileMatrix,
    ContextSignalState,
    EffectiveContext,
    load_react_context_matrix,
)
from core.path_utils import normalize_rel_path
from core.ruleset import RuleConfig, Ruleset
from rules.base import Rule, RuleResult
from rules.devops import (
    AppDebugNotFalseInProductionRule,
    AppEnvNotSetToProductionRule,
    CiCdHardeningMissingRule,
    EnvCommittedToGitRule,
    EnvExampleMissingOrOutOfSyncRule,
    MissingQueueWorkerSupervisionRule,
    NoLoggingStrategyConfiguredRule,
    StoragePathsNotInGitignoreRule,
)

# Import all rules
from rules.laravel import (
    ActionClassNamingConsistencyRule,
    ActionClassSuggestionRule,
    ApiDebugTraceLeakRule,
    ApiEndpointMissingIdempotencyKeyRule,
    ApiResourceUsageRule,
    ApiResponseInconsistentShapeRule,
    ArchiveUploadZipSlipRiskRule,
    AssetVersioningCheckRule,
    AuthorizationBypassRiskRule,
    AuthorizationMissingOnSensitiveReadsRule,
    BladeComponentNoFallbackSlotRule,
    BladeQueriesRule,
    BladeXssRiskRule,
    BroadcastChannelAuthorizationMissingRule,
    BusinessLogicInMigrationRule,
    CacheMissingFallbackRule,
    CacheStampedeRiskRule,
    ChunkMissingForLargeDatasetsRule,
    # Performance rules
    ColumnSelectionSuggestionRule,
    ComposerDependencyBelowSecureVersionRule,
    CompositeIndexOnTenantModelsRule,
    ConsoleCommandMissingTenantScopeRule,
    ContractSuggestionRule,
    ControllerBusinessLogicRule,
    ControllerIndexFilterDuplicationRule,
    ControllerInlineValidationRule,
    ControllerQueryDirectRule,
    # Architecture rules
    ControllerReturningViewInApiRule,
    CookieSameSiteMissingRule,
    CorsMisconfigurationRule,
    CsrfExceptionWildcardRiskRule,
    CustomExceptionSuggestionRule,
    DateFormatMissingCastRule,
    DebugExposureRiskRule,
    DebugModeExposureRule,
    DestructiveMigrationWithoutSafetyGuardRule,
    DtoSuggestionRule,
    DuplicateRouteDefinitionRule,
    EagerLoadingRule,
    EloquentRawWhereStringRule,
    EnumSuggestionRule,
    EnvOutsideConfigRule,
    ErrorPagesMissingRule,
    FatControllerRule,
    ForcedLoginWithoutAuthorizationRule,
    HardcodedMagicStringsRule,
    # Security rules
    HardcodedSecretsRule,
    HeavyLogicInRoutesRule,
    HighPrivilegeActionMissingAuthorizationRule,
    HostHeaderPoisoningRiskRule,
    HttpCallMissingFallbackRule,
    IdorRiskMissingOwnershipCheckRule,
    InertiaApiRouteReturnsInertiaRule,
    InertiaConditionalWantsJsonRule,
    InertiaGetWithSideEffectsRule,
    InertiaHybridControllerRule,
    InertiaPostReturnsRenderRule,
    InertiaRouteReturnsJsonResponseRule,
    InertiaSessionFlashOnApiRule,
    InertiaSharedPropsEagerQueryRule,
    InertiaSharedPropsPayloadBudgetRule,
    InertiaSharedPropsSensitiveDataRule,
    InsecureDeserializationRule,
    InsecureFileDownloadResponseRule,
    InsecureRandomForSecurityRule,
    InsecureSessionCookieConfigRule,
    IocInsteadOfNewRule,
    JobHttpCallMissingTimeoutRule,
    JobMissingIdempotencyGuardRule,
    JobMissingRetryPolicyRule,
    LaravelNamingConventionsRule,
    ListenerShouldQueueMissingForIoBoundHandlerRule,
    LivewirePublicPropMassAssignmentRule,
    MassAssignmentRiskRule,
    MassiveModelRule,
    MissingApiRateLimitHeadersRule,
    MissingApiResourceRule,
    MissingAuthOnMutatingApiRoutesRule,
    MissingCacheForReferenceDataRule,
    MissingCircuitBreakerRule,
    MissingContentSecurityPolicyRule,
    MissingCsrfTokenVerificationRule,
    MissingDomainEventRule,
    MissingFeatureFlagPatternRule,
    MissingForeignKeyInMigrationRule,
    MissingFormRequestRule,
    MissingHealthCheckEndpointRule,
    MissingHstsHeaderRule,
    MissingHttpsEnforcementRule,
    MissingIndexOnLookupColumnsRule,
    MissingInventoryLockOnDecrementRule,
    MissingModelFactoryRule,
    MissingModelObserverRegistrationRule,
    MissingNullGuardAfterRelationLoadRule,
    MissingPaginationRule,
    MissingRateLimitingRule,
    MissingThrottleOnAuthApiRoutesRule,
    ModelCrossModelQueryRule,
    ModelHiddenSensitiveAttributesMissingRule,
    NegativeStockNotGuardedRule,
    NoClosureRoutesRule,
    NoJsonEncodeInControllersRule,
    NoLogDebugInAppRule,
    NoPaginationOnRelationshipRule,
    NotificationShouldQueueMissingRule,
    NPlusOneRiskRule,
    NpmDependencyBelowSecureVersionRule,
    NullFilteringSuggestionRule,
    ObserverHeavyLogicRule,
    PasswordHashWeakAlgorithmRule,
    PasswordResetTokenHardeningMissingRule,
    PathTraversalFileAccessRule,
    PlainTextSensitiveConfigRule,
    PolicyCoverageOnMutationsRule,
    PublicAnonymousMutationAbuseReadinessRule,
    PublicApiVersioningMissingRule,
    QueueJobMissingFailureHandlingRule,
    RealtimeConfigOutsideLaravelConfigRule,
    RealtimeInMemoryStateScalabilityRule,
    RegistrationMissingRegisteredEventRule,
    RepositorySuggestionRule,
    SanctumTokenScopeMissingRule,
    SecurityHeadersBaselineMissingRule,
    SensitiveDataLoggingRule,
    SensitiveModelAppendsRiskRule,
    SensitiveResponseCacheControlMissingRule,
    SensitiveRouteRateLimitMissingRule,
    SensitiveRoutesMissingVerifiedMiddlewareRule,
    ServiceExtractionRule,
    ServiceProviderHeavyBootRule,
    SessionFixationRegenerateMissingRule,
    SignedRoutesMissingSignatureMiddlewareRule,
    SsrfRiskHttpClientRule,
    SynchronousMailInRequestRule,
    SqlInjectionRiskRule as LaravelSqlInjectionRiskRule,
    TenantAccessMiddlewareMissingRule,
    TenantScopeEnforcementRule,
    TestNoDatabaseTraitRule,
    TimingAttackTokenComparisonRule,
    TransactionRequiredForMultiWriteRule,
    UnsafeCspPolicyRule,
    UnsafeFileUploadRule,
    UnsafeRedirectRule,
    UnsafeExternalRedirectRule,
    UnusedServiceClassRule,
    UnvalidatedLoginRedirectRule,
    UploadMimeExtensionMismatchRule,
    UploadSizeLimitMissingRule,
    UrlValidationProtocolBypassRule,
    UserModelMissingMustVerifyEmailRule,
    WeakPasswordPolicyValidationRule,
    WebhookReplayProtectionMissingRule,
    WebhookSignatureMissingRule,
    WebhookSignatureParameterUnusedRule,
    WebSocketHandlerIntegrationTestsMissingRule,
    XmlXxeRiskRule,
    ZipBombRiskRule,
    MalformedAuthorizationCallRule,
    PhiEncryptionMissingRule,
    ObsoleteXXssHeaderRule,
    ControllerInheritanceInconsistencyRule,
    CompositeIndexOnTenantModelsRule,
    TenantGlobalScopeMissingRule,
)
from rules.php import (
    ArrayUnpackingInLoopRule,
    BulkInsertMissingRule,
    CatchTooBroadRule,
    CircularDependencyRule,
    CommandInjectionRiskRule,
    ConfigInLoopRule,
    DryViolationRule,
    ExceptionSwallowingRule,
    GodClassRule,
    HighComplexityRule,
    HighCouplingClassRule,
    LongMethodRule,
    LowCoverageFilesRule,
    MissingReturnTypeNullableRule,
    MissingStrictTypesRule,
    MissingTypeDeclarationsRule,
    MutableGlobalStateRule,
    PcreRedosRiskRule,
    PreferImportsRule,
    RawSqlRule,
    SqlInjectionRiskRule as PhpSqlInjectionRiskRule,
    StaticHelperAbuseRule,
    StringConcatInLoopRule,
    TestsMissingRule,
    TooManyDependenciesRule,
    UnsafeEvalRule,
    UnsafeFileIncludeVariableRule,
    UnsafeUnserializeRule,
    UnusedPrivateMethodRule,
    TestCoverageRatioRule,
)
from rules.react import (
    AccessibleAuthenticationRule,
    AnimationNoPauseControlRule,
    AnonymousDefaultExportComponentRule,
    APGAccordionDisclosureContractRule,
    APGComboboxContractRule,
    APGMenuButtonContractRule,
    APGTabsKeyboardContractRule,
    ApiKeyInClientBundleRule,
    AutocompleteMissingRule,
    AutoplayMediaRule,
    # React gap expansion rules
    AvoidPropsToStateCopyRule,
    ButtonTextVagueRule,
    CanonicalMissingOrInvalidRule,
    ClientOpenRedirectUnvalidatedNavigationRule,
    ClientSideAuthOnlyRule,
    ColorContrastRatioRule,
    ConsoleLogInProductionCodeRule,
    ContextOversizedProviderRule,
    ContextProviderInlineValueRule,
    ControlledUncontrolledInputMismatchRule,
    CrawlableInternalNavigationRequiredRule,
    CrossFeatureImportBoundaryRule,
    CssColorOnlyStateIndicatorRule,
    CssFixedLayoutPxRule,
    CssFocusOutlineWithoutReplacementRule,
    CssFontSizePxRule,
    CssHoverOnlyInteractionRule,
    CssSpacingPxRule,
    DangerousHtmlSinkWithoutSanitizerRule,
    DerivedStateInEffectRule,
    DialogFocusRestoreMissingRule,
    DuplicateKeySourceRule,
    EffectEventRelaySmellRule,
    ErrorMessageMissingRule,
    ExhaustiveDepsASTRule,
    FocusIndicatorMissingRule,
    FocusLostOnRouteChangeRule,
    FocusNotObscuredRule,
    FormDoubleSubmitRule,
    FormLabelAssociationRule,
    H1SingletonViolationRule,
    HardcodedUserFacingStringsRule,
    HeadingOrderRule,
    HooksInConditionalOrLoopRule,
    ImageAltMissingRule,
    InertiaFormUsesFetchRule,
    InertiaInternalLinkAnchorRule,
    InertiaPageMissingErrorBoundaryRule,
    InertiaPageMissingHeadRule,
    InertiaReloadWithoutOnlyRule,
    InlineLogicRule,
    InlinePropObjectArrayRule,
    InputDebounceMissingRule,
    InsecurePostMessageOriginWildcardRule,
    InteractiveAccessibleNameRequiredRule,
    InteractiveElementA11yRule,
    JsonLdStructuredDataInvalidOrMismatchedRule,
    JsxAriaAttributeFormatRule,
    LanguageAttributeMissingRule,
    LargeComponentRule,
    LargeCustomHookRule,
    LazyWithoutSuspenseRule,
    LinkTextVagueRule,
    LongPageNoTocRule,
    LooseDefaultObjectPropRule,
    # React SEO expansion rules
    MetaDescriptionMissingOrGenericRule,
    MissingEmptyStateRule,
    MissingErrorBoundaryGeneralRule,
    MissingFieldsetLegendRule,
    MissingKeyOnListRenderRule,
    MissingListVirtualizationRule,
    MissingLoadingStateRule,
    # Phase 3 React architecture rules
    MissingPropsTypeRule,
    MissingRouteCodeSplittingRule,
    MissingUseCallbackForEventHandlersRule,
    # Phase 2 React performance rules
    MissingUseMemoForExpensiveCalcRule,
    ModalTrapFocusRule,
    MultipleExportedComponentsPerFileRule,
    NoArrayIndexKeyRule,
    NoDangerouslySetInnerHtmlRule,
    NoDirectUseEffectRule,
    NoInlineHooksRule,
    NoInlineServicesRule,
    NoInlineTypesRule,
    NoNestedComponentsRule,
    OutsideClickWithoutKeyboardFallbackRule,
    PageIndexabilityConflictRule,
    # Phase 5 WCAG-based UX rules
    PageTitleMissingRule,
    PlaceholderAsLabelRule,
    PostMessageReceiverOriginNotVerifiedRule,
    PropsStateSyncEffectSmellRule,
    QueryKeyInstabilityRule,
    ReactEventListenerCleanupRequiredRule,
    ReactNoPropsMutationRule,
    ReactNoRandomKeyRule,
    ReactNoStateMutationRule,
    ReactParentChildSpacingOverlapRule,
    ReactProjectStructureConsistencyRule,
    ReactSideEffectsInRenderRule,
    ReactTimerCleanupRequiredRule,
    RedundantEntryRule,
    RefAccessDuringRenderRule,
    RefUsedAsReactiveStateRule,
    RobotsDirectiveRiskRule,
    RouteShellMissingErrorBoundaryRule,
    SafeTargetBlankRule,
    # WCAG/APG AST accessibility rules
    SemanticWrapperBreakageRule,
    SkipLinkMissingRule,
    StaleClosureInListenerRule,
    StaleClosureInTimerRule,
    StateUpdateInRenderRule,
    StatusMessageAnnouncementRule,
    SuspenseFallbackMissingRule,
    TableMissingHeadersRule,
    TailwindAppearanceNoneRiskRule,
    TailwindArbitraryLayoutSizeRule,
    TailwindArbitraryRadiusShadowRule,
    TailwindArbitrarySpacingRule,
    TailwindArbitraryTextSizeRule,
    TailwindArbitraryValueOveruseRule,
    # CSS/Tailwind accessibility rules
    TailwindMotionReduceMissingRule,
    TokenStorageInsecureLocalStorageRule,
    # Phase 4 UX/A11y rules
    TouchTargetSizeRule,
    # Process-based rules (external tools)
    TypeScriptTypeCheckRule,
    UnhandledPromiseInHandlerRule,
    UnsafeAsyncHandlerWithoutGuardRule,
    UnstableReactKeyRule,
    UnthrottledScrollResizeHandlerRule,
    # AST-based rules (higher accuracy)
    UseCallbackASTRule,
    UseCallbackOveruseRule,
    # Phase 1 React rules
    UseEffectCleanupMissingRule,
    UseEffectDependencyArrayRule,
    UseEffectFetchWithoutAbortRule,
    UselessSuspenseBoundaryRule,
    UseMemoASTRule,
    UseMemoOveruseRule,
    VideoMissingCaptionsRule,
    WindowAnyTypingRule,
    ViteChunkConfigMissingRule,
)
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

logger = logging.getLogger(__name__)


@dataclass
class EngineResult:
    """Result from running all rules."""
    findings: list[Finding] = field(default_factory=list)
    rules_run: int = 0
    rules_skipped: int = 0
    suppressed_count: int = 0
    deduped_overlap_count: int = 0
    filtered_by_confidence: int = 0
    differential_filtered: int = 0
    execution_time_ms: float = 0.0
    rule_results: dict[str, RuleResult] = field(default_factory=dict)


# Registry of all available rules
ALL_RULES: dict[str, type[Rule]] = {
    # DevOps rules
    "env-example-missing-or-out-of-sync": EnvExampleMissingOrOutOfSyncRule,
    "env-committed-to-git": EnvCommittedToGitRule,
    "app-debug-not-false-in-production": AppDebugNotFalseInProductionRule,
    "app-env-not-set-to-production": AppEnvNotSetToProductionRule,
    "missing-queue-worker-supervision": MissingQueueWorkerSupervisionRule,
    "no-logging-strategy-configured": NoLoggingStrategyConfiguredRule,
    "storage-paths-not-in-gitignore": StoragePathsNotInGitignoreRule,
    "ci-cd-hardening-missing": CiCdHardeningMissingRule,

    # Laravel rules
    "fat-controller": FatControllerRule,
    "missing-form-request": MissingFormRequestRule,
    "service-extraction": ServiceExtractionRule,
    "enum-suggestion": EnumSuggestionRule,
    "blade-queries": BladeQueriesRule,
    "repository-suggestion": RepositorySuggestionRule,
    "contract-suggestion": ContractSuggestionRule,
    "custom-exception-suggestion": CustomExceptionSuggestionRule,
    "eager-loading": EagerLoadingRule,
    "n-plus-one-risk": NPlusOneRiskRule,
    "env-outside-config": EnvOutsideConfigRule,
    "ioc-instead-of-new": IocInsteadOfNewRule,
    "controller-query-direct": ControllerQueryDirectRule,
    "controller-business-logic": ControllerBusinessLogicRule,
    "controller-inline-validation": ControllerInlineValidationRule,
    "controller-index-filter-duplication": ControllerIndexFilterDuplicationRule,
    "dto-suggestion": DtoSuggestionRule,
    "mass-assignment-risk": MassAssignmentRiskRule,
    "action-class-suggestion": ActionClassSuggestionRule,
    "action-class-naming-consistency": ActionClassNamingConsistencyRule,
    "massive-model": MassiveModelRule,
    "model-cross-model-query": ModelCrossModelQueryRule,
    "unsafe-file-upload": UnsafeFileUploadRule,
    "unused-service-class": UnusedServiceClassRule,

    # Regex lint rules (file-content scans)
    "no-json-encode-in-controllers": NoJsonEncodeInControllersRule,
    "api-resource-usage": ApiResourceUsageRule,
    "no-log-debug-in-app": NoLogDebugInAppRule,
    "negative-stock-not-guarded": NegativeStockNotGuardedRule,
    "no-closure-routes": NoClosureRoutesRule,
    "heavy-logic-in-routes": HeavyLogicInRoutesRule,
    "duplicate-route-definition": DuplicateRouteDefinitionRule,
    "missing-rate-limiting": MissingRateLimitingRule,
    "missing-auth-on-mutating-api-routes": MissingAuthOnMutatingApiRoutesRule,
    "policy-coverage-on-mutations": PolicyCoverageOnMutationsRule,
    "authorization-bypass-risk": AuthorizationBypassRiskRule,
    "transaction-required-for-multi-write": TransactionRequiredForMultiWriteRule,
    "tenant-scope-enforcement": TenantScopeEnforcementRule,
    "blade-xss-risk": BladeXssRiskRule,
    "user-model-missing-must-verify-email": UserModelMissingMustVerifyEmailRule,
    "registration-missing-registered-event": RegistrationMissingRegisteredEventRule,
    "missing-foreign-key-in-migration": MissingForeignKeyInMigrationRule,
    "missing-index-on-lookup-columns": MissingIndexOnLookupColumnsRule,
    "destructive-migration-without-safety-guard": DestructiveMigrationWithoutSafetyGuardRule,
    "model-hidden-sensitive-attributes-missing": ModelHiddenSensitiveAttributesMissingRule,
    "sensitive-model-appends-risk": SensitiveModelAppendsRiskRule,
    "sensitive-routes-missing-verified-middleware": SensitiveRoutesMissingVerifiedMiddlewareRule,
    "tenant-access-middleware-missing": TenantAccessMiddlewareMissingRule,
    "signed-routes-missing-signature-middleware": SignedRoutesMissingSignatureMiddlewareRule,
    "unsafe-redirect": UnsafeRedirectRule,
    "ssrf-risk-http-client": SsrfRiskHttpClientRule,
    "path-traversal-file-access": PathTraversalFileAccessRule,
    "insecure-file-download-response": InsecureFileDownloadResponseRule,
    "webhook-signature-missing": WebhookSignatureMissingRule,
    "idor-risk-missing-ownership-check": IdorRiskMissingOwnershipCheckRule,
    "sanctum-token-scope-missing": SanctumTokenScopeMissingRule,
    "session-fixation-regenerate-missing": SessionFixationRegenerateMissingRule,
    "weak-password-policy-validation": WeakPasswordPolicyValidationRule,
    "upload-mime-extension-mismatch": UploadMimeExtensionMismatchRule,
    "archive-upload-zip-slip-risk": ArchiveUploadZipSlipRiskRule,
    "upload-size-limit-missing": UploadSizeLimitMissingRule,
    "csrf-exception-wildcard-risk": CsrfExceptionWildcardRiskRule,
    "host-header-poisoning-risk": HostHeaderPoisoningRiskRule,
    "xml-xxe-risk": XmlXxeRiskRule,
    "zip-bomb-risk": ZipBombRiskRule,
    "sensitive-response-cache-control-missing": SensitiveResponseCacheControlMissingRule,
    "password-reset-token-hardening-missing": PasswordResetTokenHardeningMissingRule,
    "security-headers-baseline-missing": SecurityHeadersBaselineMissingRule,
    "api-endpoint-missing-idempotency-key": ApiEndpointMissingIdempotencyKeyRule,
    "webhook-replay-protection-missing": WebhookReplayProtectionMissingRule,
    "authorization-missing-on-sensitive-reads": AuthorizationMissingOnSensitiveReadsRule,
    "insecure-session-cookie-config": InsecureSessionCookieConfigRule,
    "unsafe-csp-policy": UnsafeCspPolicyRule,
    "job-missing-idempotency-guard": JobMissingIdempotencyGuardRule,
    "queue-job-missing-failure-handling": QueueJobMissingFailureHandlingRule,
    "composer-dependency-below-secure-version": ComposerDependencyBelowSecureVersionRule,
    "npm-dependency-below-secure-version": NpmDependencyBelowSecureVersionRule,
    "inertia-api-route-returns-inertia": InertiaApiRouteReturnsInertiaRule,
    "inertia-conditional-wants-json": InertiaConditionalWantsJsonRule,
    "inertia-get-with-side-effects": InertiaGetWithSideEffectsRule,
    "inertia-hybrid-controller": InertiaHybridControllerRule,
    "inertia-post-returns-render": InertiaPostReturnsRenderRule,
    "inertia-route-returns-json-response": InertiaRouteReturnsJsonResponseRule,
    "inertia-session-flash-on-api": InertiaSessionFlashOnApiRule,
    "inertia-shared-props-sensitive-data": InertiaSharedPropsSensitiveDataRule,
    "inertia-shared-props-eager-query": InertiaSharedPropsEagerQueryRule,
    "inertia-shared-props-payload-budget": InertiaSharedPropsPayloadBudgetRule,
    "job-missing-retry-policy": JobMissingRetryPolicyRule,
    "job-http-call-missing-timeout": JobHttpCallMissingTimeoutRule,
    "notification-shouldqueue-missing": NotificationShouldQueueMissingRule,
    "listener-shouldqueue-missing-for-io-bound-handler": ListenerShouldQueueMissingForIoBoundHandlerRule,
    "broadcast-channel-authorization-missing": BroadcastChannelAuthorizationMissingRule,
    "observer-heavy-logic": ObserverHeavyLogicRule,
    "public-api-versioning-missing": PublicApiVersioningMissingRule,

    # Security rules (Laravel)
    "hardcoded-secrets": HardcodedSecretsRule,
    "debug-exposure-risk": DebugExposureRiskRule,
    "cors-misconfiguration": CorsMisconfigurationRule,
    "missing-csrf-token-verification": MissingCsrfTokenVerificationRule,
    "missing-https-enforcement": MissingHttpsEnforcementRule,
    "insecure-deserialization": InsecureDeserializationRule,
    "insecure-random-for-security": InsecureRandomForSecurityRule,
    "sensitive-data-logging": SensitiveDataLoggingRule,
    "missing-hsts-header": MissingHstsHeaderRule,
    "cookie-samesite-missing": CookieSameSiteMissingRule,
    "timing-attack-token-comparison": TimingAttackTokenComparisonRule,
    "password-hash-weak-algorithm": PasswordHashWeakAlgorithmRule,
    "plain-text-sensitive-config": PlainTextSensitiveConfigRule,
    "livewire-public-prop-mass-assignment": LivewirePublicPropMassAssignmentRule,
    "missing-content-security-policy": MissingContentSecurityPolicyRule,
    "webhook-signature-parameter-unused": WebhookSignatureParameterUnusedRule,
    "forced-login-without-authorization": ForcedLoginWithoutAuthorizationRule,
    "console-command-missing-tenant-scope": ConsoleCommandMissingTenantScopeRule,
    "high-privilege-action-missing-authorization": HighPrivilegeActionMissingAuthorizationRule,
    "url-validation-protocol-bypass": UrlValidationProtocolBypassRule,

    # Performance rules (Laravel)
    "column-selection-suggestion": ColumnSelectionSuggestionRule,
    "missing-cache-for-reference-data": MissingCacheForReferenceDataRule,
    "missing-pagination": MissingPaginationRule,
    "error-pages-missing": ErrorPagesMissingRule,
    "null-filtering-suggestion": NullFilteringSuggestionRule,
    "asset-versioning-check": AssetVersioningCheckRule,

    # Architecture rules (Laravel)
    "controller-returning-view-in-api": ControllerReturningViewInApiRule,
    "missing-api-resource": MissingApiResourceRule,
    "cache-stampede-risk": CacheStampedeRiskRule,
    "cache-missing-fallback": CacheMissingFallbackRule,
    "synchronous-mail-in-request": SynchronousMailInRequestRule,
    "service-provider-heavy-boot": ServiceProviderHeavyBootRule,
    "business-logic-in-migration": BusinessLogicInMigrationRule,
    "missing-health-check-endpoint": MissingHealthCheckEndpointRule,
    "missing-inventory-lock-on-decrement": MissingInventoryLockOnDecrementRule,
    "missing-model-factory": MissingModelFactoryRule,
    "test-no-database-trait": TestNoDatabaseTraitRule,
    "missing-circuit-breaker": MissingCircuitBreakerRule,
    "http-call-missing-fallback": HttpCallMissingFallbackRule,
    "missing-domain-event": MissingDomainEventRule,
    "chunk-missing-for-large-datasets": ChunkMissingForLargeDatasetsRule,
    "laravel-naming-conventions": LaravelNamingConventionsRule,
    "hardcoded-magic-strings": HardcodedMagicStringsRule,
    "date-format-missing-cast": DateFormatMissingCastRule,
    "missing-null-guard-after-relation-load": MissingNullGuardAfterRelationLoadRule,
    "missing-api-rate-limit-headers": MissingApiRateLimitHeadersRule,
    "eloquent-raw-where-string": EloquentRawWhereStringRule,
    "missing-model-observer-registration": MissingModelObserverRegistrationRule,
    "blade-component-no-fallback-slot": BladeComponentNoFallbackSlotRule,
    "api-response-inconsistent-shape": ApiResponseInconsistentShapeRule,
    "no-pagination-on-relationship": NoPaginationOnRelationshipRule,
    "missing-feature-flag-pattern": MissingFeatureFlagPatternRule,
    "realtime-inmemory-state-scalability": RealtimeInMemoryStateScalabilityRule,
    "websocket-handler-integration-tests-missing": WebSocketHandlerIntegrationTestsMissingRule,
    "realtime-config-outside-laravel-config": RealtimeConfigOutsideLaravelConfigRule,
    "public-anonymous-mutation-abuse-readiness": PublicAnonymousMutationAbuseReadinessRule,
    "malformed-authorization-call": MalformedAuthorizationCallRule,
    "phi-encryption-missing": PhiEncryptionMissingRule,
    "obsolete-x-xss-protection-header": ObsoleteXXssHeaderRule,
    "controller-inheritance-inconsistency": ControllerInheritanceInconsistencyRule,
    "composite-index-on-tenant-models": CompositeIndexOnTenantModelsRule,
    "tenant-global-scope-missing": TenantGlobalScopeMissingRule,
    # PHP rules
    "dry-violation": DryViolationRule,
    "high-complexity": HighComplexityRule,
    "long-method": LongMethodRule,
    "god-class": GodClassRule,
    "too-many-dependencies": TooManyDependenciesRule,
    "raw-sql": RawSqlRule,
    "config-in-loop": ConfigInLoopRule,
    "static-helper-abuse": StaticHelperAbuseRule,
    "unused-private-method": UnusedPrivateMethodRule,
    "circular-dependency": CircularDependencyRule,
    "high-coupling-class": HighCouplingClassRule,
    "prefer-imports": PreferImportsRule,
    "unsafe-eval": UnsafeEvalRule,
    "unsafe-unserialize": UnsafeUnserializeRule,
    "command-injection-risk": CommandInjectionRiskRule,
    # The PHP implementation is framework-neutral and analyzes parsed call facts.
    # Keep the Laravel regex implementation as an internal compatibility wrapper
    # so native PHP and Laravel projects share one canonical rule id.
    "sql-injection-risk": PhpSqlInjectionRiskRule,

    # Quality gates
    "tests-missing": TestsMissingRule,
    "test-coverage-ratio": TestCoverageRatioRule,
    "low-coverage-files": LowCoverageFilesRule,
    "pcre-redos-risk": PcreRedosRiskRule,
    "unsafe-file-include-variable": UnsafeFileIncludeVariableRule,
    "missing-strict-types": MissingStrictTypesRule,
    "missing-type-declarations": MissingTypeDeclarationsRule,
    "exception-swallowing": ExceptionSwallowingRule,
    "mutable-global-state": MutableGlobalStateRule,
    "array-unpacking-in-loop": ArrayUnpackingInLoopRule,
    "string-concat-in-loop": StringConcatInLoopRule,
    "bulk-insert-missing": BulkInsertMissingRule,
    "missing-return-type-nullable": MissingReturnTypeNullableRule,
    "catch-too-broad": CatchTooBroadRule,

    # React rules
    "large-react-component": LargeComponentRule,
    "inline-api-logic": InlineLogicRule,
    "react-useeffect-deps": UseEffectDependencyArrayRule,
    "react-no-array-index-key": NoArrayIndexKeyRule,
    "hooks-in-conditional-or-loop": HooksInConditionalOrLoopRule,
    "missing-key-on-list-render": MissingKeyOnListRenderRule,
    "hardcoded-user-facing-strings": HardcodedUserFacingStringsRule,
    "interactive-element-a11y": InteractiveElementA11yRule,
    "form-label-association": FormLabelAssociationRule,
    "no-nested-components": NoNestedComponentsRule,
    "no-dangerously-set-inner-html": NoDangerouslySetInnerHtmlRule,
    "img-alt-missing": ImageAltMissingRule,
    "safe-target-blank": SafeTargetBlankRule,
    "no-inline-hooks": NoInlineHooksRule,
    "no-inline-types": NoInlineTypesRule,
    "no-inline-services": NoInlineServicesRule,
    "react-parent-child-spacing-overlap": ReactParentChildSpacingOverlapRule,
    "react-project-structure-consistency": ReactProjectStructureConsistencyRule,
    "inertia-page-missing-head": InertiaPageMissingHeadRule,
    "inertia-internal-link-anchor": InertiaInternalLinkAnchorRule,
    "inertia-form-uses-fetch": InertiaFormUsesFetchRule,
    "anonymous-default-export-component": AnonymousDefaultExportComponentRule,
    "multiple-exported-react-components": MultipleExportedComponentsPerFileRule,
    "context-provider-inline-value": ContextProviderInlineValueRule,
    "react-useeffect-fetch-without-abort": UseEffectFetchWithoutAbortRule,
    "no-direct-useeffect": NoDirectUseEffectRule,
    "derived-state-in-effect": DerivedStateInEffectRule,
    "state-update-in-render": StateUpdateInRenderRule,
    "large-custom-hook": LargeCustomHookRule,
    "cross-feature-import-boundary": CrossFeatureImportBoundaryRule,
    "query-key-instability": QueryKeyInstabilityRule,
    "effect-event-relay-smell": EffectEventRelaySmellRule,
    "route-shell-missing-error-boundary": RouteShellMissingErrorBoundaryRule,
    "unsafe-async-handler-without-guard": UnsafeAsyncHandlerWithoutGuardRule,
    "react-no-random-key": ReactNoRandomKeyRule,
    "react-no-props-mutation": ReactNoPropsMutationRule,
    "react-no-state-mutation": ReactNoStateMutationRule,
    "react-side-effects-in-render": ReactSideEffectsInRenderRule,
    "react-event-listener-cleanup-required": ReactEventListenerCleanupRequiredRule,
    "react-timer-cleanup-required": ReactTimerCleanupRequiredRule,
    "inertia-reload-without-only": InertiaReloadWithoutOnlyRule,
    "insecure-postmessage-origin-wildcard": InsecurePostMessageOriginWildcardRule,
    "token-storage-insecure-localstorage": TokenStorageInsecureLocalStorageRule,
    "client-open-redirect-unvalidated-navigation": ClientOpenRedirectUnvalidatedNavigationRule,
    "api-key-in-client-bundle": ApiKeyInClientBundleRule,
    "client-side-auth-only": ClientSideAuthOnlyRule,
    "postmessage-receiver-origin-not-verified": PostMessageReceiverOriginNotVerifiedRule,
    "dangerous-html-sink-without-sanitizer": DangerousHtmlSinkWithoutSanitizerRule,

    # Phase 1 React rules
    "useeffect-cleanup-missing": UseEffectCleanupMissingRule,

    # Phase 2 React performance rules
    "missing-usememo-for-expensive-calc": MissingUseMemoForExpensiveCalcRule,
    "missing-usecallback-for-event-handlers": MissingUseCallbackForEventHandlersRule,

    # Phase 3 React architecture rules
    "missing-props-type": MissingPropsTypeRule,

    # Phase 4 UX/A11y rules
    "touch-target-size": TouchTargetSizeRule,
    "placeholder-as-label": PlaceholderAsLabelRule,
    "link-text-vague": LinkTextVagueRule,
    "button-text-vague": ButtonTextVagueRule,
    "autocomplete-missing": AutocompleteMissingRule,
    "heading-order": HeadingOrderRule,
    "focus-indicator-missing": FocusIndicatorMissingRule,
    "skip-link-missing": SkipLinkMissingRule,
    "modal-trap-focus": ModalTrapFocusRule,
    "error-message-missing": ErrorMessageMissingRule,
    "long-page-no-toc": LongPageNoTocRule,
    "color-contrast-ratio": ColorContrastRatioRule,

    # Phase 5 WCAG-based UX rules
    "page-title-missing": PageTitleMissingRule,
    "language-attribute-missing": LanguageAttributeMissingRule,
    "status-message-announcement": StatusMessageAnnouncementRule,
    "autoplay-media": AutoplayMediaRule,
    "redundant-entry": RedundantEntryRule,
    "accessible-authentication": AccessibleAuthenticationRule,
    "focus-not-obscured": FocusNotObscuredRule,
    "semantic-wrapper-breakage": SemanticWrapperBreakageRule,
    "interactive-accessible-name-required": InteractiveAccessibleNameRequiredRule,
    "jsx-aria-attribute-format": JsxAriaAttributeFormatRule,
    "outside-click-without-keyboard-fallback": OutsideClickWithoutKeyboardFallbackRule,
    "apg-tabs-keyboard-contract": APGTabsKeyboardContractRule,
    "apg-accordion-disclosure-contract": APGAccordionDisclosureContractRule,
    "apg-menu-button-contract": APGMenuButtonContractRule,
    "apg-combobox-contract": APGComboboxContractRule,
    "dialog-focus-restore-missing": DialogFocusRestoreMissingRule,
    # React gap expansion rules
    "avoid-props-to-state-copy": AvoidPropsToStateCopyRule,
    "props-state-sync-effect-smell": PropsStateSyncEffectSmellRule,
    "controlled-uncontrolled-input-mismatch": ControlledUncontrolledInputMismatchRule,
    "usememo-overuse": UseMemoOveruseRule,
    "usecallback-overuse": UseCallbackOveruseRule,
    "context-oversized-provider": ContextOversizedProviderRule,
    "lazy-without-suspense": LazyWithoutSuspenseRule,
    "suspense-fallback-missing": SuspenseFallbackMissingRule,
    "stale-closure-in-timer": StaleClosureInTimerRule,
    "stale-closure-in-listener": StaleClosureInListenerRule,
    "duplicate-key-source": DuplicateKeySourceRule,
    "missing-loading-state": MissingLoadingStateRule,
    "missing-empty-state": MissingEmptyStateRule,
    "ref-access-during-render": RefAccessDuringRenderRule,
    "ref-used-as-reactive-state": RefUsedAsReactiveStateRule,
    # React SEO expansion rules
    "meta-description-missing-or-generic": MetaDescriptionMissingOrGenericRule,
    "canonical-missing-or-invalid": CanonicalMissingOrInvalidRule,
    "robots-directive-risk": RobotsDirectiveRiskRule,
    "crawlable-internal-navigation-required": CrawlableInternalNavigationRequiredRule,
    "jsonld-structured-data-invalid-or-mismatched": JsonLdStructuredDataInvalidOrMismatchedRule,
    "h1-singleton-violation": H1SingletonViolationRule,
    "page-indexability-conflict": PageIndexabilityConflictRule,
    "css-font-size-px": CssFontSizePxRule,
    "css-spacing-px": CssSpacingPxRule,
    "css-fixed-layout-px": CssFixedLayoutPxRule,
    "tailwind-arbitrary-value-overuse": TailwindArbitraryValueOveruseRule,
    "tailwind-arbitrary-text-size": TailwindArbitraryTextSizeRule,
    "tailwind-arbitrary-spacing": TailwindArbitrarySpacingRule,
    "tailwind-arbitrary-layout-size": TailwindArbitraryLayoutSizeRule,
    "tailwind-arbitrary-radius-shadow": TailwindArbitraryRadiusShadowRule,
    "tailwind-motion-reduce-missing": TailwindMotionReduceMissingRule,
    "tailwind-appearance-none-risk": TailwindAppearanceNoneRiskRule,
    "css-focus-outline-without-replacement": CssFocusOutlineWithoutReplacementRule,
    "css-hover-only-interaction": CssHoverOnlyInteractionRule,
    "css-color-only-state-indicator": CssColorOnlyStateIndicatorRule,

    # AST-based React rules (higher accuracy)
    "usecallback-ast": UseCallbackASTRule,
    "usememo-ast": UseMemoASTRule,
    "exhaustive-deps-ast": ExhaustiveDepsASTRule,

    # Process-based rules (external tools)
    "typescript-type-check": TypeScriptTypeCheckRule,
    "unthrottled-scroll-resize-handler": UnthrottledScrollResizeHandlerRule,
    "missing-list-virtualization": MissingListVirtualizationRule,
    "input-debounce-missing": InputDebounceMissingRule,
    "missing-route-code-splitting": MissingRouteCodeSplittingRule,
    "missing-error-boundary-general": MissingErrorBoundaryGeneralRule,
    "unhandled-promise-in-handler": UnhandledPromiseInHandlerRule,
    "form-double-submit": FormDoubleSubmitRule,
    "focus-lost-on-route-change": FocusLostOnRouteChangeRule,
    "table-missing-headers": TableMissingHeadersRule,
    "missing-fieldset-legend": MissingFieldsetLegendRule,
    "video-missing-captions": VideoMissingCaptionsRule,
    "animation-no-pause-control": AnimationNoPauseControlRule,
    "inline-prop-object-array": InlinePropObjectArrayRule,
    "unstable-react-key": UnstableReactKeyRule,
    "loose-default-object-prop": LooseDefaultObjectPropRule,
    "console-log-in-production-code": ConsoleLogInProductionCodeRule,
    "inertia-page-missing-error-boundary": InertiaPageMissingErrorBoundaryRule,
    "useless-suspense-boundary": UselessSuspenseBoundaryRule,
    "window-any-typing": WindowAnyTypingRule,
    "vite-chunk-config-missing": ViteChunkConfigMissingRule,
}

WRAPPED_INTERNAL_RULES: dict[str, str] = {
    "missing-throttle-on-auth-api-routes": "missing-rate-limiting",
    "sensitive-route-rate-limit-missing": "missing-rate-limiting",
    "debug-mode-exposure": "debug-exposure-risk",
    "api-debug-trace-leak": "debug-exposure-risk",
    "unsafe-external-redirect": "unsafe-redirect",
    "unvalidated-login-redirect": "unsafe-redirect",
    "laravel-sql-injection-risk": "sql-injection-risk",
}

LEGACY_RULE_ALIASES: dict[str, str] = {
    "rate-limit-public-forms": "missing-rate-limiting",
    "rate-limit-password-reset": "missing-rate-limiting",
}

INTERNAL_RULE_WRAPPERS: dict[str, str] = dict(WRAPPED_INTERNAL_RULES)

RULE_ALIASES: dict[str, str] = {
    **WRAPPED_INTERNAL_RULES,
    **LEGACY_RULE_ALIASES,
}


def resolve_rule_alias(rule_id: str) -> str:
    """Resolve legacy/alias ids to canonical runtime ids."""
    current = str(rule_id or "").strip()
    if not current:
        return current
    seen: set[str] = set()
    while current in RULE_ALIASES and current not in seen:
        seen.add(current)
        current = RULE_ALIASES[current]
    return current


def _iter_rule_subclasses(base: type[Rule]) -> list[type[Rule]]:
    """Collect every loaded subclass recursively."""
    out: list[type[Rule]] = []
    stack: list[type[Rule]] = list(base.__subclasses__())
    seen: set[type[Rule]] = set()
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        out.append(cls)
        stack.extend(cls.__subclasses__())
    return out


_RULE_DISCOVERY_FAMILIES: tuple[str, ...] = ("rules.laravel", "rules.react", "rules.php")


def _import_discovery_modules() -> list[str]:
    """Import rule modules under known families and return imported module names."""
    imported: list[str] = []
    for family_module in _RULE_DISCOVERY_FAMILIES:
        try:
            family_pkg = import_module(family_module)
        except Exception as exc:
            logger.warning("Rule discovery failed to import %s: %s", family_module, exc)
            continue

        imported.append(family_module)
        for module_info in pkgutil.walk_packages(
            family_pkg.__path__,
            prefix=f"{family_module}.",
        ):
            module_name = str(module_info.name)
            try:
                import_module(module_name)
                imported.append(module_name)
            except Exception as exc:
                logger.warning("Rule discovery skipped module %s: %s", module_name, exc)
    return imported


def discover_rules() -> dict[str, type[Rule]]:
    """Discover rules by importing modules and scanning loaded Rule subclasses."""
    _import_discovery_modules()
    discovered: dict[str, type[Rule]] = {}
    for rule_cls in _iter_rule_subclasses(Rule):
        rule_id = str(getattr(rule_cls, "id", "") or "").strip()
        if not rule_id:
            logger.warning(
                "Rule discovery skipped malformed rule class %s.%s: missing `id`",
                str(getattr(rule_cls, "__module__", "unknown")),
                str(getattr(rule_cls, "__name__", "Rule")),
            )
            continue
        if rule_id == "base-rule":
            continue
        if rule_id in discovered and discovered[rule_id] is not rule_cls:
            logger.debug(
                "Rule discovery duplicate id '%s': keeping %s, skipping %s",
                rule_id,
                discovered[rule_id].__name__,
                rule_cls.__name__,
            )
            continue
        discovered[rule_id] = rule_cls
    return discovered


def get_unaccounted_discovered_rule_ids(
    discovered_registry: dict[str, type[Rule]] | None = None,
    manual_registry: dict[str, type[Rule]] | None = None,
) -> list[str]:
    discovered = set((discovered_registry or DISCOVERED_RULES).keys())
    manual = set((manual_registry or ALL_RULES).keys())
    wrapped = set(WRAPPED_INTERNAL_RULES.keys())
    return sorted(discovered - manual - wrapped)


def build_rule_registry(
    manual_registry: dict[str, type[Rule]] | None = None,
    discovered_registry: dict[str, type[Rule]] | None = None,
) -> dict[str, type[Rule]]:
    """Merge manual registry with discovered rules (manual remains authoritative)."""
    manual = dict(manual_registry or {})
    discovered = dict(discovered_registry or discover_rules())
    merged = dict(manual)

    added = 0
    for rule_id, rule_cls in discovered.items():
        if rule_id in merged:
            continue
        merged[rule_id] = rule_cls
        added += 1

    logger.info(
        "Rule discovery complete: manual=%d discovered=%d merged=%d added=%d",
        len(manual),
        len(discovered),
        len(merged),
        added,
    )
    _validate_rule_registry(merged)
    return merged


def _validate_rule_registry(registry: dict[str, type[Rule]]) -> None:
    """Guard against silent registry corruption from malformed entries."""
    for rule_id, rule_cls in registry.items():
        canonical_id = str(rule_id or "").strip()
        if not canonical_id:
            raise ValueError("Rule registry contains an empty rule id key")
        if not isinstance(rule_cls, type) or not issubclass(rule_cls, Rule):
            raise ValueError(f"Rule registry entry '{canonical_id}' is not a Rule subclass")

        class_rule_id = str(getattr(rule_cls, "id", "") or "").strip()
        if not class_rule_id:
            raise ValueError(f"Rule class {rule_cls.__name__} has no `id`")

        category = getattr(rule_cls, "category", None)
        if isinstance(category, Category):
            pass
        elif isinstance(category, str):
            Category(category)
        else:
            raise ValueError(f"Rule class {rule_cls.__name__} has invalid category")

        severity = getattr(rule_cls, "default_severity", None)
        if isinstance(severity, Severity):
            pass
        elif isinstance(severity, str):
            Severity(severity)
        else:
            raise ValueError(f"Rule class {rule_cls.__name__} has invalid default severity")


DISCOVERED_RULES: dict[str, type[Rule]] = discover_rules()
REGISTERED_RULES: dict[str, type[Rule]] = build_rule_registry(ALL_RULES, DISCOVERED_RULES)
RUNTIME_RULES: dict[str, type[Rule]] = dict(ALL_RULES)
UNACCOUNTED_DISCOVERED_RULE_IDS: list[str] = get_unaccounted_discovered_rule_ids(
    discovered_registry=DISCOVERED_RULES,
    manual_registry=ALL_RULES,
)

for _rule_id in UNACCOUNTED_DISCOVERED_RULE_IDS:
    logger.debug(
        "Rule discovery found non-runtime rule id '%s' without explicit wrapper mapping",
        _rule_id,
    )


