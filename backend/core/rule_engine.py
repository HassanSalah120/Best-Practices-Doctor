"""
Rule Engine

Orchestrates rule loading, execution, and result collection.
"""
import logging
import os
import pkgutil
import re
from importlib import import_module
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Type

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from core.ruleset import Ruleset, RuleConfig
from rules.base import Rule, RuleResult
from core.path_utils import normalize_rel_path
from core.context_profiles import (
    ContextProfileMatrix,
    ContextSignalState,
    EffectiveContext,
    load_react_context_matrix,
)

# Import all rules
from rules.laravel import (
    FatControllerRule,
    MissingFormRequestRule,
    ServiceExtractionRule,
    EnumSuggestionRule,
    BladeQueriesRule,
    RepositorySuggestionRule,
    ContractSuggestionRule,
    CustomExceptionSuggestionRule,
    EagerLoadingRule,
    NPlusOneRiskRule,
    EnvOutsideConfigRule,
    IocInsteadOfNewRule,
    ControllerQueryDirectRule,
    ControllerBusinessLogicRule,
    ControllerInlineValidationRule,
    ControllerIndexFilterDuplicationRule,
    DtoSuggestionRule,
    MassAssignmentRiskRule,
    ActionClassSuggestionRule,
    ActionClassNamingConsistencyRule,
    MassiveModelRule,
    ModelCrossModelQueryRule,
    UnsafeFileUploadRule,
    NoJsonEncodeInControllersRule,
    ApiResourceUsageRule,
    NoLogDebugInAppRule,
    NoClosureRoutesRule,
    HeavyLogicInRoutesRule,
    DuplicateRouteDefinitionRule,
    MissingRateLimitingRule,
    MissingAuthOnMutatingApiRoutesRule,
    PolicyCoverageOnMutationsRule,
    AuthorizationBypassRiskRule,
    TransactionRequiredForMultiWriteRule,
    TenantScopeEnforcementRule,
    UnusedServiceClassRule,
    BladeXssRiskRule,
    UserModelMissingMustVerifyEmailRule,
    RegistrationMissingRegisteredEventRule,
    MissingForeignKeyInMigrationRule,
    MissingIndexOnLookupColumnsRule,
    DestructiveMigrationWithoutSafetyGuardRule,
    ModelHiddenSensitiveAttributesMissingRule,
    SensitiveModelAppendsRiskRule,
    SensitiveRoutesMissingVerifiedMiddlewareRule,
    TenantAccessMiddlewareMissingRule,
    SignedRoutesMissingSignatureMiddlewareRule,
    UnsafeRedirectRule,
    AuthorizationMissingOnSensitiveReadsRule,
    InsecureSessionCookieConfigRule,
    UnsafeCspPolicyRule,
    SsrfRiskHttpClientRule,
    PathTraversalFileAccessRule,
    InsecureFileDownloadResponseRule,
    WebhookSignatureMissingRule,
    IdorRiskMissingOwnershipCheckRule,
    SanctumTokenScopeMissingRule,
    SessionFixationRegenerateMissingRule,
    WeakPasswordPolicyValidationRule,
    UploadMimeExtensionMismatchRule,
    ArchiveUploadZipSlipRiskRule,
    UploadSizeLimitMissingRule,
    CsrfExceptionWildcardRiskRule,
    HostHeaderPoisoningRiskRule,
    XmlXxeRiskRule,
    ZipBombRiskRule,
    SensitiveResponseCacheControlMissingRule,
    PasswordResetTokenHardeningMissingRule,
    SecurityHeadersBaselineMissingRule,
    WebhookReplayProtectionMissingRule,
    JobMissingIdempotencyGuardRule,
    ComposerDependencyBelowSecureVersionRule,
    NpmDependencyBelowSecureVersionRule,
    InertiaSharedPropsSensitiveDataRule,
    InertiaSharedPropsEagerQueryRule,
    InertiaSharedPropsPayloadBudgetRule,
    JobMissingRetryPolicyRule,
    JobHttpCallMissingTimeoutRule,
    NotificationShouldQueueMissingRule,
    ListenerShouldQueueMissingForIoBoundHandlerRule,
    BroadcastChannelAuthorizationMissingRule,
    ObserverHeavyLogicRule,
    PublicApiVersioningMissingRule,
    # Security rules
    HardcodedSecretsRule,
    SensitiveDataLoggingRule,
    InsecureRandomForSecurityRule,
    MissingHstsHeaderRule,
    CookieSameSiteMissingRule,
    TimingAttackTokenComparisonRule,
    PasswordHashWeakAlgorithmRule,
    PlainTextSensitiveConfigRule,
    LivewirePublicPropMassAssignmentRule,
    MissingContentSecurityPolicyRule,
    DebugExposureRiskRule,
    MissingHttpsEnforcementRule,
    CorsMisconfigurationRule,
    MissingCsrfTokenVerificationRule,
    InsecureDeserializationRule,
    # Performance rules
    ColumnSelectionSuggestionRule,
    MissingCacheForReferenceDataRule,
    MissingPaginationRule,
    ErrorPagesMissingRule,
    NullFilteringSuggestionRule,
    AssetVersioningCheckRule,
    # Architecture rules
    ControllerReturningViewInApiRule,
    MissingApiResourceRule,
    SqlInjectionRiskRule,
)
from rules.php import (
    DryViolationRule,
    HighComplexityRule,
    LongMethodRule,
    GodClassRule,
    TooManyDependenciesRule,
    RawSqlRule,
    ConfigInLoopRule,
    StaticHelperAbuseRule,
    UnusedPrivateMethodRule,
    CircularDependencyRule,
    HighCouplingClassRule,
    PreferImportsRule,
    UnsafeEvalRule,
    UnsafeUnserializeRule,
    CommandInjectionRiskRule,
    SqlInjectionRiskRule,
    TestsMissingRule,
    LowCoverageFilesRule,
    PcreRedosRiskRule,
    UnsafeFileIncludeVariableRule,
)
from rules.react import (
    LargeComponentRule,
    InlineLogicRule,
    UseEffectDependencyArrayRule,
    NoArrayIndexKeyRule,
    HooksInConditionalOrLoopRule,
    MissingKeyOnListRenderRule,
    HardcodedUserFacingStringsRule,
    InteractiveElementA11yRule,
    FormLabelAssociationRule,
    NoNestedComponentsRule,
    NoDangerouslySetInnerHtmlRule,
    ImageAltMissingRule,
    SafeTargetBlankRule,
    NoInlineHooksRule,
    NoInlineTypesRule,
    NoInlineServicesRule,
    ReactParentChildSpacingOverlapRule,
    ReactProjectStructureConsistencyRule,
    InertiaPageMissingHeadRule,
    InertiaInternalLinkAnchorRule,
    InertiaFormUsesFetchRule,
    AnonymousDefaultExportComponentRule,
    MultipleExportedComponentsPerFileRule,
    ContextProviderInlineValueRule,
    UseEffectFetchWithoutAbortRule,
    NoDirectUseEffectRule,
    DerivedStateInEffectRule,
    StateUpdateInRenderRule,
    LargeCustomHookRule,
    CrossFeatureImportBoundaryRule,
    QueryKeyInstabilityRule,
    EffectEventRelaySmellRule,
    RouteShellMissingErrorBoundaryRule,
    UnsafeAsyncHandlerWithoutGuardRule,
    ReactNoRandomKeyRule,
    ReactNoPropsMutationRule,
    ReactNoStateMutationRule,
    ReactSideEffectsInRenderRule,
    ReactEventListenerCleanupRequiredRule,
    ReactTimerCleanupRequiredRule,
    InertiaReloadWithoutOnlyRule,
    InsecurePostMessageOriginWildcardRule,
    TokenStorageInsecureLocalStorageRule,
    ClientOpenRedirectUnvalidatedNavigationRule,
    ApiKeyInClientBundleRule,
    ClientSideAuthOnlyRule,
    PostMessageReceiverOriginNotVerifiedRule,
    DangerousHtmlSinkWithoutSanitizerRule,
    # Phase 1 React rules
    UseEffectCleanupMissingRule,
    # Phase 2 React performance rules
    MissingUseMemoForExpensiveCalcRule,
    MissingUseCallbackForEventHandlersRule,
    # Phase 3 React architecture rules
    MissingPropsTypeRule,
    # Phase 4 UX/A11y rules
    TouchTargetSizeRule,
    PlaceholderAsLabelRule,
    LinkTextVagueRule,
    ButtonTextVagueRule,
    AutocompleteMissingRule,
    HeadingOrderRule,
    FocusIndicatorMissingRule,
    SkipLinkMissingRule,
    ModalTrapFocusRule,
    ErrorMessageMissingRule,
    LongPageNoTocRule,
    ColorContrastRatioRule,
    # Phase 5 WCAG-based UX rules
    PageTitleMissingRule,
    LanguageAttributeMissingRule,
    StatusMessageAnnouncementRule,
    AutoplayMediaRule,
    RedundantEntryRule,
    AccessibleAuthenticationRule,
    FocusNotObscuredRule,
    CssFontSizePxRule,
    CssSpacingPxRule,
    CssFixedLayoutPxRule,
    TailwindArbitraryValueOveruseRule,
    TailwindArbitraryTextSizeRule,
    TailwindArbitrarySpacingRule,
    TailwindArbitraryLayoutSizeRule,
    TailwindArbitraryRadiusShadowRule,
    # CSS/Tailwind accessibility rules
    TailwindMotionReduceMissingRule,
    TailwindAppearanceNoneRiskRule,
    CssFocusOutlineWithoutReplacementRule,
    CssHoverOnlyInteractionRule,
    CssColorOnlyStateIndicatorRule,
    # WCAG/APG AST accessibility rules
    SemanticWrapperBreakageRule,
    InteractiveAccessibleNameRequiredRule,
    JsxAriaAttributeFormatRule,
    OutsideClickWithoutKeyboardFallbackRule,
    APGTabsKeyboardContractRule,
    APGAccordionDisclosureContractRule,
    APGMenuButtonContractRule,
    APGComboboxContractRule,
    DialogFocusRestoreMissingRule,
    # React gap expansion rules
    AvoidPropsToStateCopyRule,
    PropsStateSyncEffectSmellRule,
    ControlledUncontrolledInputMismatchRule,
    UseMemoOveruseRule,
    UseCallbackOveruseRule,
    ContextOversizedProviderRule,
    LazyWithoutSuspenseRule,
    SuspenseFallbackMissingRule,
    StaleClosureInTimerRule,
    StaleClosureInListenerRule,
    DuplicateKeySourceRule,
    MissingLoadingStateRule,
    MissingEmptyStateRule,
    RefAccessDuringRenderRule,
    RefUsedAsReactiveStateRule,
    # React SEO expansion rules
    MetaDescriptionMissingOrGenericRule,
    CanonicalMissingOrInvalidRule,
    RobotsDirectiveRiskRule,
    CrawlableInternalNavigationRequiredRule,
    JsonLdStructuredDataInvalidOrMismatchedRule,
    H1SingletonViolationRule,
    PageIndexabilityConflictRule,
    # AST-based rules (higher accuracy)
    UseCallbackASTRule,
    UseMemoASTRule,
    ExhaustiveDepsASTRule,
    # Process-based rules (external tools)
    TypeScriptTypeCheckRule,
)

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
ALL_RULES: dict[str, Type[Rule]] = {
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
    "webhook-replay-protection-missing": WebhookReplayProtectionMissingRule,
    "authorization-missing-on-sensitive-reads": AuthorizationMissingOnSensitiveReadsRule,
    "insecure-session-cookie-config": InsecureSessionCookieConfigRule,
    "unsafe-csp-policy": UnsafeCspPolicyRule,
    "job-missing-idempotency-guard": JobMissingIdempotencyGuardRule,
    "composer-dependency-below-secure-version": ComposerDependencyBelowSecureVersionRule,
    "npm-dependency-below-secure-version": NpmDependencyBelowSecureVersionRule,
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
    "sql-injection-risk": SqlInjectionRiskRule,

    # Quality gates
    "tests-missing": TestsMissingRule,
    "low-coverage-files": LowCoverageFilesRule,
    "pcre-redos-risk": PcreRedosRiskRule,
    "unsafe-file-include-variable": UnsafeFileIncludeVariableRule,
    
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
}

RULE_ALIASES: dict[str, str] = {
    "missing-throttle-on-auth-api-routes": "missing-rate-limiting",
    "sensitive-route-rate-limit-missing": "missing-rate-limiting",
    "rate-limit-public-forms": "missing-rate-limiting",
    "rate-limit-password-reset": "missing-rate-limiting",
    "debug-mode-exposure": "debug-exposure-risk",
    "api-debug-trace-leak": "debug-exposure-risk",
    "unsafe-external-redirect": "unsafe-redirect",
    "unvalidated-login-redirect": "unsafe-redirect",
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


def discover_rules() -> dict[str, Type[Rule]]:
    """Discover rules by importing modules and scanning loaded Rule subclasses."""
    _import_discovery_modules()
    discovered: dict[str, Type[Rule]] = {}
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
            logger.warning(
                "Rule discovery duplicate id '%s': keeping %s, skipping %s",
                rule_id,
                discovered[rule_id].__name__,
                rule_cls.__name__,
            )
            continue
        discovered[rule_id] = rule_cls
    return discovered


def build_rule_registry(
    manual_registry: dict[str, Type[Rule]] | None = None,
    discovered_registry: dict[str, Type[Rule]] | None = None,
) -> dict[str, Type[Rule]]:
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


def _validate_rule_registry(registry: dict[str, Type[Rule]]) -> None:
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


DISCOVERED_RULES: dict[str, Type[Rule]] = discover_rules()
REGISTERED_RULES: dict[str, Type[Rule]] = build_rule_registry(ALL_RULES, DISCOVERED_RULES)
RUNTIME_RULES: dict[str, Type[Rule]] = dict(ALL_RULES)


class RuleEngine:
    """
    Orchestrates rule execution.
    
    Loads rules based on ruleset configuration and executes
    them against the Facts/Metrics to produce Findings.
    """
    
    def __init__(self, ruleset: Ruleset, selected_rules: list[str] | None = None):
        self.ruleset = ruleset
        self.rules: list[Rule] = []
        self.selected_rules = (
            {resolve_rule_alias(rule_id) for rule_id in selected_rules}
            if selected_rules
            else None
        )
        self._context_matrices: dict[str, ContextProfileMatrix] = {}
        try:
            self._context_matrices["laravel"] = ContextProfileMatrix.load_default()
        except Exception:
            pass
        try:
            self._context_matrices["react"] = load_react_context_matrix()
        except Exception:
            pass
        self._load_rules()
    
    def _load_rules(self) -> None:
        """Load and configure rules from the runtime registry (manual source of truth)."""
        for rule_id, rule_class in RUNTIME_RULES.items():

            # If selected_rules is specified, only load those rules
            if self.selected_rules is not None and rule_id not in self.selected_rules:
                continue
            
            # Get config from ruleset (or use defaults)
            config = self._resolve_rule_config(rule_id)
            
            if config.enabled:
                try:
                    rule_instance = rule_class(config)
                    setattr(rule_instance, "_base_thresholds", dict(getattr(config, "thresholds", {}) or {}))
                    self.rules.append(rule_instance)
                    logger.debug(f"Loaded rule: {rule_id}")
                except Exception as e:
                    logger.warning(f"Failed to load rule {rule_id}: {e}")

    def _resolve_rule_config(self, rule_id: str) -> RuleConfig:
        """Resolve config by canonical id with legacy alias fallback."""
        config = self.ruleset.get_rule_config(rule_id)
        if config.enabled:
            return config

        for alias_id, canonical_id in RULE_ALIASES.items():
            if canonical_id != rule_id:
                continue
            alias_cfg = self.ruleset.get_rule_config(alias_id)
            if alias_cfg.enabled:
                return alias_cfg
        return config
    
    def run(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
        project_type: str = "",
        cancellation_check: Callable[[], bool] | None = None,
        differential_mode: bool = False,
        changed_files: set[str] | list[str] | tuple[str, ...] | None = None,
        progress_callback: Callable[[float, int, int], None] | None = None,
    ) -> EngineResult:
        """
        Execute all applicable rules against the codebase facts.
        
        Args:
            facts: Raw facts about the codebase
            metrics: Derived metrics (keyed by method_fqn)
            project_type: Detected project type for filtering
            cancellation_check: Optional callback to check for cancellation
        
        Returns:
            EngineResult with all findings and execution metadata
        """
        import time
        
        result = EngineResult()
        start = time.perf_counter()
        self._apply_context_calibration(facts)

        def _overrides(rule: Rule, method_name: str) -> bool:
            method = getattr(rule.__class__, method_name, None)
            base_method = getattr(Rule, method_name, None)
            return method is not None and method is not base_method

        facts_based_rules: list[Rule] = []
        file_based_ast_rules: list[Rule] = []
        process_rules: list[Rule] = []
        regex_rules: list[Rule] = []
        supplemental_regex_rules: list[Rule] = []

        for rule in self.rules:
            rule_type = str(getattr(rule, "type", "ast") or "ast").strip().lower()
            if rule_type == "regex":
                regex_rules.append(rule)
                continue
            if rule_type == "process":
                process_rules.append(rule)
            elif _overrides(rule, "analyze_ast"):
                file_based_ast_rules.append(rule)
            else:
                facts_based_rules.append(rule)

            if _overrides(rule, "analyze_regex"):
                supplemental_regex_rules.append(rule)

        call_once_rules = facts_based_rules + process_rules
        regex_scan_rules = regex_rules + supplemental_regex_rules

        def _run_call_once_rule(rule: Rule) -> tuple[str, RuleResult]:
            """Execute a single analyze()-based rule and return (rule_id, result)."""
            rule_result = rule.run(facts, project_type, metrics)
            return (rule.id, rule_result)

        max_workers = min(8, len(call_once_rules)) if call_once_rules else 1
        total_rules = len(call_once_rules) + len(file_based_ast_rules) + len(regex_scan_rules)
        rules_completed = 0

        if call_once_rules:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_rule = {
                    executor.submit(_run_call_once_rule, rule): rule
                    for rule in call_once_rules
                }

                # Collect results as they complete
                for future in as_completed(future_to_rule):
                    # Check for cancellation
                    if cancellation_check and cancellation_check():
                        logger.info("Rule engine cancelled")
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                    try:
                        rule_id, rule_result = future.result()
                        result.rule_results[rule_id] = rule_result

                        if rule_result.skipped:
                            result.rules_skipped += 1
                            logger.debug(f"Skipped rule {rule_id}: {rule_result.skip_reason}")
                        else:
                            result.rules_run += 1
                            result.findings.extend(rule_result.findings)
                            logger.debug(
                                f"Rule {rule_id}: {len(rule_result.findings)} findings "
                                f"({rule_result.execution_time_ms:.1f}ms)"
                            )
                    except Exception as e:
                        rule = future_to_rule[future]
                        logger.warning(f"Rule {rule.id} failed: {e}")
                        result.rules_skipped += 1
                    
                    # Update progress
                    rules_completed += 1
                    if progress_callback and total_rules > 0:
                        progress_callback(rules_completed / total_rules, rules_completed, total_rules)

        # Regex rules plus supplemental regex passes are lightweight and run directly on file contents.
        if not (cancellation_check and cancellation_check()) and regex_scan_rules:
            file_cache: dict[str, str] = {}

            def _read(rel_path: str) -> str:
                if rel_path in file_cache:
                    return file_cache[rel_path]
                try:
                    from pathlib import Path
                    root = Path(getattr(facts, "project_path", "")).resolve()
                    p = (root / rel_path).resolve()
                    txt = p.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    txt = ""
                file_cache[rel_path] = txt
                return txt

            import time as _time
            for rule in regex_scan_rules:
                if cancellation_check and cancellation_check():
                    logger.info("Rule engine cancelled")
                    break

                existing_rr = result.rule_results.get(rule.id)
                rr = existing_rr or RuleResult(rule_id=rule.id)
                if not rule.is_applicable(facts, project_type):
                    if existing_rr is None:
                        rr.skipped = True
                        rr.skip_reason = "Disabled" if not rule.enabled else "Not applicable to this project type"
                        result.rule_results[rule.id] = rr
                        result.rules_skipped += 1
                    rules_completed += 1
                    if progress_callback and total_rules > 0:
                        progress_callback(rules_completed / total_rules, rules_completed, total_rules)
                    continue

                t0 = _time.perf_counter()
                findings: list[Finding] = []
                try:
                    raw_exts = getattr(rule, "regex_file_extensions", [".php"]) or [".php"]
                    allowed_exts: set[str] = set()
                    for ext in raw_exts:
                        s = str(ext or "").strip().lower()
                        if not s:
                            continue
                        if not s.startswith("."):
                            s = "." + s
                        allowed_exts.add(s)
                    if not allowed_exts:
                        allowed_exts = {".php"}

                    # Use FactsBuilder's file list to respect ignore globs.
                    for rel_path in getattr(facts, "files", []) or []:
                        rel_path = normalize_rel_path(rel_path)
                        if not rel_path:
                            continue
                        rel_lower = rel_path.lower()
                        if not any(rel_lower.endswith(ext) for ext in allowed_exts):
                            continue
                        content = _read(rel_path)
                        if not content:
                            continue
                        findings.extend(rule.analyze_regex(rel_path, content, facts, metrics))
                except Exception as e:
                    if existing_rr is None:
                        rr.skipped = True
                        rr.skip_reason = f"Error: {str(e)}"
                    else:
                        logger.warning(f"Supplemental regex pass failed for {rule.id}: {e}")
                finally:
                    rr.execution_time_ms += (_time.perf_counter() - t0) * 1000

                if findings:
                    rr.findings.extend(findings)

                result.rule_results[rule.id] = rr
                if existing_rr is None:
                    if rr.skipped:
                        result.rules_skipped += 1
                        logger.debug(f"Skipped rule {rule.id}: {rr.skip_reason}")
                    else:
                        result.rules_run += 1
                if not rr.skipped:
                    result.findings.extend(findings)
                    logger.debug(
                        f"Rule {rule.id}: {len(findings)} regex finding(s) "
                        f"({rr.execution_time_ms:.1f}ms)"
                    )
                
                # Update progress after each regex rule
                rules_completed += 1
                if progress_callback and total_rules > 0:
                    progress_callback(rules_completed / total_rules, rules_completed, total_rules)

        # File-based AST rules (analyze_ast) - run on each file
        if not (cancellation_check and cancellation_check()) and file_based_ast_rules:
            # Reuse file cache from regex rules if available
            if 'file_cache' not in dir():
                file_cache = {}

            def _read_ast(rel_path: str) -> str:
                if rel_path in file_cache:
                    return file_cache[rel_path]
                try:
                    from pathlib import Path
                    root = Path(getattr(facts, "project_path", "")).resolve()
                    p = (root / rel_path).resolve()
                    txt = p.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    txt = ""
                file_cache[rel_path] = txt
                return txt

            import time as _time_ast
            for rule in file_based_ast_rules:
                if cancellation_check and cancellation_check():
                    logger.info("Rule engine cancelled")
                    break

                rr = RuleResult(rule_id=rule.id)
                if not rule.is_applicable(facts, project_type):
                    rr.skipped = True
                    rr.skip_reason = "Disabled" if not rule.enabled else "Not applicable to this project type"
                    result.rule_results[rule.id] = rr
                    result.rules_skipped += 1
                    rules_completed += 1
                    if progress_callback and total_rules > 0:
                        progress_callback(rules_completed / total_rules, rules_completed, total_rules)
                    continue

                t0 = _time_ast.perf_counter()
                try:
                    findings: list[Finding] = []
                    raw_exts = getattr(rule, "regex_file_extensions", [".tsx", ".ts", ".jsx", ".js"]) or [".tsx", ".ts", ".jsx", ".js"]
                    allowed_exts: set[str] = set()
                    for ext in raw_exts:
                        s = str(ext or "").strip().lower()
                        if not s:
                            continue
                        if not s.startswith("."):
                            s = "." + s
                        allowed_exts.add(s)
                    if not allowed_exts:
                        allowed_exts = {".tsx", ".ts", ".jsx", ".js"}

                    # Use FactsBuilder's file list to respect ignore globs.
                    for rel_path in getattr(facts, "files", []) or []:
                        rel_path = normalize_rel_path(rel_path)
                        if not rel_path:
                            continue
                        rel_lower = rel_path.lower()
                        if not any(rel_lower.endswith(ext) for ext in allowed_exts):
                            continue
                        content = _read_ast(rel_path)
                        if not content:
                            continue
                        findings.extend(rule.analyze_ast(rel_path, content, facts, metrics))
                    rr.findings = findings
                except Exception as e:
                    rr.skipped = True
                    rr.skip_reason = f"Error: {str(e)}"
                finally:
                    rr.execution_time_ms = (_time_ast.perf_counter() - t0) * 1000

                result.rule_results[rule.id] = rr
                if rr.skipped:
                    result.rules_skipped += 1
                    logger.debug(f"Skipped rule {rule.id}: {rr.skip_reason}")
                else:
                    result.rules_run += 1
                    result.findings.extend(rr.findings)
                    logger.debug(
                        f"Rule {rule.id}: {len(rr.findings)} findings "
                        f"({rr.execution_time_ms:.1f}ms)"
                    )
                
                # Update progress after each AST rule
                rules_completed += 1
                if progress_callback and total_rules > 0:
                    progress_callback(rules_completed / total_rules, rules_completed, total_rules)
        
        before_conf = len(result.findings)
        result.findings = self._apply_confidence_filter(result.findings)
        result.filtered_by_confidence = max(0, before_conf - len(result.findings))

        before_suppression = len(result.findings)
        result.findings = self._apply_suppressions(result.findings, facts)
        result.suppressed_count = max(0, before_suppression - len(result.findings))

        before_overlap = len(result.findings)
        result.findings = self._apply_overlap_dedupe(result.findings)
        result.deduped_overlap_count = max(0, before_overlap - len(result.findings))

        mode = differential_mode or (os.environ.get("BPD_DIFFERENTIAL_MODE", "").strip() == "1")
        if mode:
            changed = self._resolve_changed_files(changed_files)
            if changed:
                before_diff = len(result.findings)
                result.findings = self._apply_differential_filter(result.findings, changed)
                result.differential_filtered = max(0, before_diff - len(result.findings))

        result.execution_time_ms = (time.perf_counter() - start) * 1000
        
        logger.info(
            f"Rule engine complete: {result.rules_run} rules, "
            f"{len(result.findings)} findings, {result.execution_time_ms:.1f}ms"
        )
        
        return result

    def _apply_context_calibration(self, facts: Facts) -> None:
        if not self._context_matrices:
            return
        laravel_context = self._build_effective_context_from_facts(facts)
        react_context = self._build_react_effective_context_from_facts(facts)
        for rule in self.rules:
            self._reset_rule_runtime_state(rule)
            matrix, effective_context = self._matrix_and_context_for_rule(rule, laravel_context, react_context)
            if matrix is None:
                continue
            calibration = matrix.calibrate_rule(rule.id, effective_context)
            setattr(rule, "_context_calibration", calibration)
            setattr(rule, "_runtime_effective_context", effective_context)
            if calibration.get("enabled") is False:
                rule.enabled = False
                continue
            severity_raw = str(calibration.get("severity", "") or "").strip().lower()
            if severity_raw:
                try:
                    rule.severity = Severity(severity_raw)
                except Exception:
                    pass
            thresholds = calibration.get("thresholds")
            if isinstance(thresholds, dict) and thresholds:
                merged = dict(getattr(rule.config, "thresholds", {}) or {})
                merged.update({str(k): v for k, v in thresholds.items()})
                rule.config.thresholds = merged

    def _matrix_and_context_for_rule(
        self,
        rule: Rule,
        laravel_context: EffectiveContext,
        react_context: EffectiveContext,
    ) -> tuple[ContextProfileMatrix | None, EffectiveContext]:
        module_name = str(getattr(rule.__class__, "__module__", "") or "").lower()
        if ".react." in module_name:
            return self._context_matrices.get("react"), react_context
        if ".laravel." in module_name:
            return self._context_matrices.get("laravel"), laravel_context
        return self._context_matrices.get("laravel"), laravel_context

    def _reset_rule_runtime_state(self, rule: Rule) -> None:
        # Reset runtime state before applying context calibration so repeated runs remain deterministic.
        rule.enabled = bool(getattr(rule.config, "enabled", True))
        base_thresholds = getattr(rule, "_base_thresholds", None)
        if isinstance(base_thresholds, dict):
            rule.config.thresholds = dict(base_thresholds)
        if getattr(rule.config, "severity", None):
            try:
                rule.severity = Severity(str(rule.config.severity))
            except Exception:
                rule.severity = rule.default_severity
        else:
            rule.severity = rule.default_severity

    def _build_effective_context_from_facts(self, facts: Facts) -> EffectiveContext:
        project_context = getattr(facts, "project_context", None)
        if project_context is None:
            return EffectiveContext()

        effective = EffectiveContext(
            framework=str(getattr(project_context, "backend_framework", "laravel") or "laravel"),
            project_type=str(
                getattr(project_context, "project_type", None)
                or getattr(project_context, "project_business_context", "unknown")
                or "unknown"
            ),
            project_type_confidence=float(getattr(project_context, "project_business_confidence", 0.0) or 0.0),
            project_type_confidence_kind=str(getattr(project_context, "project_business_confidence_kind", "unknown") or "unknown"),
            project_type_source=str(getattr(project_context, "project_business_source", "default") or "default"),
            architecture_profile=str(
                getattr(project_context, "architecture_style", None)
                or getattr(project_context, "backend_architecture_profile", "unknown")
                or "unknown"
            ),
            architecture_profile_confidence=float(getattr(project_context, "backend_profile_confidence", 0.0) or 0.0),
            architecture_profile_confidence_kind=str(getattr(project_context, "backend_profile_confidence_kind", "unknown") or "unknown"),
            architecture_profile_source=str(getattr(project_context, "backend_profile_source", "default") or "default"),
        )

        capabilities_payload = (
            getattr(project_context, "capabilities", None)
            or getattr(project_context, "backend_capabilities", {})
            or {}
        )
        for key, payload in capabilities_payload.items():
            if not isinstance(payload, dict):
                continue
            effective.capabilities[str(key)] = ContextSignalState(
                enabled=bool(payload.get("enabled", False)),
                confidence=float(payload.get("confidence", 0.0) or 0.0),
                source=str(payload.get("source", "default") or "default"),
                evidence=list(payload.get("evidence", []) or []),
            )

        expectations_payload = (
            getattr(project_context, "team_expectations", None)
            or getattr(project_context, "backend_team_expectations", {})
            or {}
        )
        for key, payload in expectations_payload.items():
            if not isinstance(payload, dict):
                continue
            effective.team_expectations[str(key)] = ContextSignalState(
                enabled=bool(payload.get("enabled", False)),
                confidence=float(payload.get("confidence", 0.0) or 0.0),
                source=str(payload.get("source", "default") or "default"),
                evidence=list(payload.get("evidence", []) or []),
            )
        return effective

    def _build_react_effective_context_from_facts(self, facts: Facts) -> EffectiveContext:
        project_context = getattr(facts, "project_context", None)
        effective = EffectiveContext(
            framework="react",
            project_type="standalone",
            project_type_confidence=0.6,
            project_type_confidence_kind="heuristic",
            project_type_source="detected",
            architecture_profile="component-driven",
            architecture_profile_confidence=0.6,
            architecture_profile_confidence_kind="heuristic",
            architecture_profile_source="detected",
        )

        imports: list[str] = []
        provider_count = 0
        for component in getattr(facts, "react_components", []) or []:
            comp_imports = [str(item or "") for item in (getattr(component, "imports", []) or [])]
            imports.extend(comp_imports)
            if any("provider" in str(item or "").lower() for item in comp_imports) or "provider" in str(
                getattr(component, "name", "")
            ).lower():
                provider_count += 1

        imports_low = [item.lower() for item in imports]
        if any("@inertiajs" in item for item in imports_low):
            effective.project_type = "inertia_spa"
            effective.project_type_confidence = 0.9
            effective.project_type_confidence_kind = "structural"
        elif any("next/router" in item or "next/navigation" in item for item in imports_low):
            effective.project_type = "next_js"
            effective.project_type_confidence = 0.88
            effective.project_type_confidence_kind = "structural"

        has_design_system = any(
            marker in item
            for marker in ("@radix-ui", "@chakra-ui", "@mui", "shadcn", "@/components/ui")
            for item in imports_low
        )
        is_public_facing = False
        route_count = len(getattr(facts, "routes", []) or [])
        if route_count > 0:
            public_count = 0
            private_count = 0
            for route in getattr(facts, "routes", []) or []:
                middleware = " ".join(str(item or "").lower() for item in (getattr(route, "middleware", []) or []))
                if "auth" in middleware:
                    private_count += 1
                else:
                    public_count += 1
            is_public_facing = public_count > 0 and public_count >= private_count

        if route_count == 0:
            route_count = len(
                [
                    p
                    for p in (getattr(facts, "files", []) or [])
                    if "/pages/" in str(p or "").replace("\\", "/").lower()
                    or "/routes/" in str(p or "").replace("\\", "/").lower()
                ]
            )

        typescript_strict = False
        if project_context is not None:
            auto_ctx = dict(getattr(project_context, "auto_detected_context", {}) or {})
            cap_payload = dict(auto_ctx.get("capabilities", {}) or {})
            strict_payload = cap_payload.get("typescript_strict")
            if isinstance(strict_payload, dict):
                typescript_strict = bool(strict_payload.get("enabled", False))

        effective.capabilities["has_design_system"] = ContextSignalState(
            enabled=has_design_system,
            confidence=0.88 if has_design_system else 0.62,
            source="detected",
            evidence=["imports:design-system"],
        )
        effective.capabilities["is_public_facing"] = ContextSignalState(
            enabled=is_public_facing,
            confidence=0.82,
            source="detected",
            evidence=[f"route_count={route_count}"],
        )
        effective.capabilities["typescript_strict"] = ContextSignalState(
            enabled=typescript_strict,
            confidence=0.8 if typescript_strict else 0.6,
            source="detected",
            evidence=[f"typescript_strict={int(typescript_strict)}"],
        )
        effective.capabilities["context_provider_count_high"] = ContextSignalState(
            enabled=provider_count > 5,
            confidence=0.8,
            source="detected",
            evidence=[f"context_provider_count={provider_count}"],
        )
        effective.capabilities["route_count_large"] = ContextSignalState(
            enabled=route_count >= 10,
            confidence=0.84,
            source="detected",
            evidence=[f"route_count={route_count}"],
        )
        return effective

    def _profile_confidence_floor(self) -> float:
        name = str(getattr(self.ruleset, "name", "") or "").strip().lower()
        if name == "startup":
            return 0.65
        if name == "balanced":
            return 0.55
        if name == "strict":
            return 0.45
        return 0.55

    def _confidence_floor_for_rule(self, rule_id: str) -> float:
        cfg = self.ruleset.get_rule_config(rule_id)
        if cfg and isinstance(cfg.thresholds, dict):
            raw = cfg.thresholds.get("min_confidence")
            if raw is not None:
                try:
                    return max(0.0, min(1.0, float(raw)))
                except Exception:
                    pass
        return self._profile_confidence_floor()

    def _apply_confidence_filter(self, findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        for f in findings:
            floor = self._confidence_floor_for_rule(f.rule_id)
            floor += self._classification_confidence_adjustment(getattr(f, "classification", FindingClassification.ADVISORY))
            floor = max(0.0, min(1.0, floor))
            conf = float(getattr(f, "confidence", 1.0) or 0.0)
            if conf + 1e-9 >= floor:
                out.append(f)
        return out

    def _classification_confidence_adjustment(self, classification: FindingClassification | str) -> float:
        key = classification.value if isinstance(classification, FindingClassification) else str(classification or "").strip().lower()
        profile = str(getattr(self.ruleset, "name", "") or "").strip().lower()
        adjustments = {
            "startup": {"defect": 0.0, "risk": 0.02, "advisory": 0.05},
            "balanced": {"defect": 0.0, "risk": 0.01, "advisory": 0.03},
            "strict": {"defect": 0.0, "risk": 0.0, "advisory": 0.01},
        }
        return float(adjustments.get(profile, adjustments["balanced"]).get(key, 0.0))

    def _apply_suppressions(self, findings: list[Finding], facts: Facts) -> list[Finding]:
        root = Path(getattr(facts, "project_path", "") or ".").resolve()
        cache: dict[str, list[str]] = {}
        out: list[Finding] = []
        for f in findings:
            if self._is_suppressed(f, root, cache):
                continue
            out.append(f)
        return out

    def _apply_overlap_dedupe(self, findings: list[Finding]) -> list[Finding]:
        grouped: dict[tuple[str, str], list[Finding]] = {}
        primary_by_group: dict[tuple[str, str], Finding] = {}

        for finding in findings:
            metadata = getattr(finding, "metadata", {}) or {}
            group = str(metadata.get("overlap_group", "") or "").strip()
            scope = str(metadata.get("overlap_scope", "") or getattr(finding, "context", "") or "").strip()
            if not group or not scope:
                continue
            key = (group, scope)
            grouped.setdefault(key, []).append(finding)

        for key, items in grouped.items():
            if len(items) <= 1:
                continue
            primary = max(items, key=self._overlap_sort_key)
            primary_by_group[key] = self._merge_overlap_metadata(primary, [item for item in items if item is not primary])

        emitted_groups: set[tuple[str, str]] = set()
        out: list[Finding] = []
        for finding in findings:
            metadata = getattr(finding, "metadata", {}) or {}
            group = str(metadata.get("overlap_group", "") or "").strip()
            scope = str(metadata.get("overlap_scope", "") or getattr(finding, "context", "") or "").strip()
            if not group or not scope:
                out.append(finding)
                continue

            key = (group, scope)
            primary = primary_by_group.get(key)
            if primary is None:
                out.append(finding)
                continue
            if key in emitted_groups:
                continue
            emitted_groups.add(key)
            out.append(primary)
        return out

    def _overlap_sort_key(self, finding: Finding) -> tuple[int, int, int, float, int]:
        metadata = getattr(finding, "metadata", {}) or {}
        overlap_rank = int(metadata.get("overlap_rank", 0) or 0)
        classification_rank = {
            FindingClassification.DEFECT: 3,
            FindingClassification.RISK: 2,
            FindingClassification.ADVISORY: 1,
        }.get(getattr(finding, "classification", FindingClassification.ADVISORY), 0)
        severity_rank = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }.get(getattr(finding, "severity", Severity.LOW), 0)
        confidence = float(getattr(finding, "confidence", 0.0) or 0.0)
        score_impact = int(getattr(finding, "score_impact", 0) or 0)
        return (overlap_rank, classification_rank, severity_rank, confidence, score_impact)

    def _merge_overlap_metadata(self, finding: Finding, suppressed: list[Finding]) -> Finding:
        if not suppressed:
            return finding
        suppressed_rule_ids = sorted({item.rule_id for item in suppressed})
        metadata = dict(getattr(finding, "metadata", {}) or {})
        metadata["suppressed_overlap_rules"] = suppressed_rule_ids
        evidence = list(getattr(finding, "evidence_signals", []) or [])
        evidence.append(f"overlap_suppressed={','.join(suppressed_rule_ids)}")
        deduped = list(dict.fromkeys(evidence))
        return finding.model_copy(update={"metadata": metadata, "evidence_signals": deduped})

    def _is_suppressed(self, finding: Finding, root: Path, cache: dict[str, list[str]]) -> bool:
        rel = normalize_rel_path(str(getattr(finding, "file", "") or ""))
        if not rel:
            return False

        if rel in cache:
            lines = cache[rel]
        else:
            try:
                p = (root / rel).resolve()
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                lines = []
            cache[rel] = lines

        if not lines:
            return False

        line_no = int(getattr(finding, "line_start", 1) or 1)
        if line_no < 1:
            line_no = 1

        # Scan same line and up to two previous lines for inline suppression comments.
        for ln in range(max(1, line_no - 2), min(len(lines), line_no) + 1):
            if self._line_has_matching_suppression(lines[ln - 1], finding.rule_id, applies_to_next_line=False):
                return True

        # Scan previous line for next-line suppression.
        prev = line_no - 1
        if prev >= 1 and prev <= len(lines):
            if self._line_has_matching_suppression(lines[prev - 1], finding.rule_id, applies_to_next_line=True):
                return True

        return False

    def _line_has_matching_suppression(self, line: str, rule_id: str, applies_to_next_line: bool) -> bool:
        txt = str(line or "")
        if "@bpd-ignore" not in txt:
            return False

        m = re.search(
            r"@bpd-ignore(?P<next>-next-line)?\s+(?P<rule>[a-z0-9._*\-]+)(?P<rest>.*)$",
            txt,
            flags=re.IGNORECASE,
        )
        if not m:
            return False

        is_next = bool(m.group("next"))
        if applies_to_next_line != is_next:
            return False

        target_rule = (m.group("rule") or "").strip().lower()
        if target_rule not in {"*", rule_id.lower()}:
            return False

        rest = (m.group("rest") or "").strip()
        until_match = re.search(r"\buntil:(\d{4}-\d{2}-\d{2})\b", rest, flags=re.IGNORECASE)
        if until_match:
            try:
                until_date = date.fromisoformat(until_match.group(1))
                if date.today() > until_date:
                    return False
            except Exception:
                return False

        return True

    def _resolve_changed_files(
        self, changed_files: set[str] | list[str] | tuple[str, ...] | None
    ) -> set[str]:
        if changed_files:
            src = list(changed_files)
        else:
            src = []
            env_raw = os.environ.get("BPD_CHANGED_FILES", "")
            if env_raw:
                src.extend(re.split(r"[\r\n,;]+", env_raw))

            env_file = os.environ.get("BPD_CHANGED_FILES_FILE", "").strip()
            if env_file:
                try:
                    txt = Path(env_file).read_text(encoding="utf-8", errors="replace")
                    src.extend(re.split(r"[\r\n]+", txt))
                except Exception:
                    pass

        out: set[str] = set()
        for p in src:
            s = normalize_rel_path(str(p or "").strip())
            if not s:
                continue
            out.add(s)
        return out

    def _apply_differential_filter(self, findings: list[Finding], changed: set[str]) -> list[Finding]:
        out: list[Finding] = []
        for f in findings:
            main = normalize_rel_path(str(getattr(f, "file", "") or ""))
            if main in changed:
                out.append(f)
                continue

            related = [normalize_rel_path(str(p)) for p in (getattr(f, "related_files", []) or [])]
            if any(p in changed for p in related):
                out.append(f)
                continue
        return out
    
    def get_rule_ids(self) -> list[str]:
        """Get list of loaded rule IDs."""
        return [r.id for r in self.rules]
    
    def get_rule(self, rule_id: str) -> Rule | None:
        """Get a specific rule by ID."""
        return next((r for r in self.rules if r.id == rule_id), None)


def create_engine(
    ruleset: Ruleset | None = None,
    ruleset_path: str | None = None,
    selected_rules: list[str] | None = None,
) -> RuleEngine:
    """
    Factory function to create a RuleEngine.
    
    Args:
        ruleset_path: Optional path to custom ruleset.yaml
        selected_rules: Optional list of rule IDs to run (for advanced profile)
    
    Returns:
        Configured RuleEngine instance
    """
    if ruleset is None:
        if ruleset_path:
            ruleset = Ruleset.load_default(override_path=ruleset_path)
        else:
            ruleset = Ruleset.load_default()

    return RuleEngine(ruleset, selected_rules=selected_rules)
