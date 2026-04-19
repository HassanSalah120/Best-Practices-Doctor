"""React rules init."""
from .large_component import LargeComponentRule
from .inline_logic import InlineLogicRule
from .useeffect_dependency_array import UseEffectDependencyArrayRule
from .no_array_index_key import NoArrayIndexKeyRule
from .hooks_in_conditional_or_loop import HooksInConditionalOrLoopRule
from .missing_key_on_list_render import MissingKeyOnListRenderRule
from .hardcoded_user_facing_strings import HardcodedUserFacingStringsRule
from .interactive_element_a11y import InteractiveElementA11yRule
from .form_label_association import FormLabelAssociationRule
from .no_nested_components import NoNestedComponentsRule
from .no_dangerously_set_inner_html import NoDangerouslySetInnerHtmlRule
from .img_alt_missing import ImageAltMissingRule
from .safe_target_blank import SafeTargetBlankRule
from .no_inline_hooks import NoInlineHooksRule
from .no_inline_types import NoInlineTypesRule
from .no_inline_services import NoInlineServicesRule
from .react_parent_child_spacing_overlap import ReactParentChildSpacingOverlapRule
from .project_structure_consistency import ReactProjectStructureConsistencyRule
from .inertia_page_missing_head import InertiaPageMissingHeadRule
from .inertia_internal_link_anchor import InertiaInternalLinkAnchorRule
from .inertia_form_uses_fetch import InertiaFormUsesFetchRule
from .anonymous_default_export_component import AnonymousDefaultExportComponentRule
from .multiple_exported_components_per_file import MultipleExportedComponentsPerFileRule
from .context_provider_inline_value import ContextProviderInlineValueRule
from .useeffect_fetch_without_abort import UseEffectFetchWithoutAbortRule
from .no_direct_useeffect import NoDirectUseEffectRule
from .derived_state_in_effect import DerivedStateInEffectRule
from .state_update_in_render import StateUpdateInRenderRule
from .large_custom_hook import LargeCustomHookRule
from .cross_feature_import_boundary import CrossFeatureImportBoundaryRule
from .query_key_instability import QueryKeyInstabilityRule
from .effect_event_relay_smell import EffectEventRelaySmellRule
from .route_shell_missing_error_boundary import RouteShellMissingErrorBoundaryRule
from .unsafe_async_handler_without_guard import UnsafeAsyncHandlerWithoutGuardRule
from .react_no_random_key import ReactNoRandomKeyRule
from .react_no_props_mutation import ReactNoPropsMutationRule
from .react_no_state_mutation import ReactNoStateMutationRule
from .react_side_effects_in_render import ReactSideEffectsInRenderRule
from .react_event_listener_cleanup_required import ReactEventListenerCleanupRequiredRule
from .react_timer_cleanup_required import ReactTimerCleanupRequiredRule
from .inertia_reload_without_only import InertiaReloadWithoutOnlyRule
from .insecure_postmessage_origin_wildcard import InsecurePostMessageOriginWildcardRule
from .token_storage_insecure_localstorage import TokenStorageInsecureLocalStorageRule
from .client_open_redirect_unvalidated_navigation import ClientOpenRedirectUnvalidatedNavigationRule
from .postmessage_receiver_origin_not_verified import PostMessageReceiverOriginNotVerifiedRule
from .dangerous_html_sink_without_sanitizer import DangerousHtmlSinkWithoutSanitizerRule
# Phase 1 React rules
from .useeffect_cleanup_missing import UseEffectCleanupMissingRule
# Phase 2 React performance rules
from .missing_usememo_for_expensive_calc import MissingUseMemoForExpensiveCalcRule
from .missing_usecallback_for_event_handlers import MissingUseCallbackForEventHandlersRule
# Phase 3 React architecture rules
from .missing_props_type import MissingPropsTypeRule
# Phase 4 UX/A11y rules
from .touch_target_size import TouchTargetSizeRule
from .placeholder_as_label import PlaceholderAsLabelRule
from .link_text_vague import LinkTextVagueRule
from .button_text_vague import ButtonTextVagueRule
from .autocomplete_missing import AutocompleteMissingRule
from .heading_order import HeadingOrderRule
from .focus_indicator_missing import FocusIndicatorMissingRule
from .skip_link_missing import SkipLinkMissingRule
from .modal_trap_focus import ModalTrapFocusRule
from .error_message_missing import ErrorMessageMissingRule
from .long_page_no_toc import LongPageNoTocRule
from .color_contrast_ratio import ColorContrastRatioRule
# Phase 5 WCAG-based UX rules
from .page_title_missing import PageTitleMissingRule
from .language_attribute_missing import LanguageAttributeMissingRule
from .status_message_announcement import StatusMessageAnnouncementRule
from .autoplay_media import AutoplayMediaRule
from .redundant_entry import RedundantEntryRule
from .accessible_authentication import AccessibleAuthenticationRule
from .focus_not_obscured import FocusNotObscuredRule
# CSS/Tailwind discipline rules
from .css_tailwind_best_practice_rules import (
    CssFontSizePxRule,
    CssSpacingPxRule,
    CssFixedLayoutPxRule,
    TailwindArbitraryValueOveruseRule,
    TailwindArbitraryTextSizeRule,
    TailwindArbitrarySpacingRule,
    TailwindArbitraryLayoutSizeRule,
    TailwindArbitraryRadiusShadowRule,
)
# CSS/Tailwind accessibility rules
from .css_tailwind_accessibility_rules import (
    TailwindMotionReduceMissingRule,
    TailwindAppearanceNoneRiskRule,
    CssFocusOutlineWithoutReplacementRule,
    CssHoverOnlyInteractionRule,
    CssColorOnlyStateIndicatorRule,
)
# WCAG/APG AST accessibility rules
from .wcag_apg_ast_rules import (
    SemanticWrapperBreakageRule,
    InteractiveAccessibleNameRequiredRule,
    JsxAriaAttributeFormatRule,
    OutsideClickWithoutKeyboardFallbackRule,
    APGTabsKeyboardContractRule,
    APGAccordionDisclosureContractRule,
    APGMenuButtonContractRule,
    APGComboboxContractRule,
    DialogFocusRestoreMissingRule,
)
# React gap expansion rules
from .react_gap_expansion_rules import (
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
)
# React SEO expansion rules
from .react_seo_expansion_rules import (
    MetaDescriptionMissingOrGenericRule,
    CanonicalMissingOrInvalidRule,
    RobotsDirectiveRiskRule,
    CrawlableInternalNavigationRequiredRule,
    JsonLdStructuredDataInvalidOrMismatchedRule,
    H1SingletonViolationRule,
    PageIndexabilityConflictRule,
)
# AST-based rules (higher accuracy)
from .usecallback_ast import UseCallbackASTRule
from .usememo_ast import UseMemoASTRule
from .exhaustive_deps_ast import ExhaustiveDepsASTRule
# Process-based rules (external tools)
from .typescript_type_check import TypeScriptTypeCheckRule

__all__ = [
    "LargeComponentRule",
    "InlineLogicRule",
    "UseEffectDependencyArrayRule",
    "NoArrayIndexKeyRule",
    "HooksInConditionalOrLoopRule",
    "MissingKeyOnListRenderRule",
    "HardcodedUserFacingStringsRule",
    "InteractiveElementA11yRule",
    "FormLabelAssociationRule",
    "NoNestedComponentsRule",
    "NoDangerouslySetInnerHtmlRule",
    "ImageAltMissingRule",
    "SafeTargetBlankRule",
    "NoInlineHooksRule",
    "NoInlineTypesRule",
    "NoInlineServicesRule",
    "ReactParentChildSpacingOverlapRule",
    "ReactProjectStructureConsistencyRule",
    "InertiaPageMissingHeadRule",
    "InertiaInternalLinkAnchorRule",
    "InertiaFormUsesFetchRule",
    "AnonymousDefaultExportComponentRule",
    "MultipleExportedComponentsPerFileRule",
    "ContextProviderInlineValueRule",
    "UseEffectFetchWithoutAbortRule",
    "NoDirectUseEffectRule",
    "DerivedStateInEffectRule",
    "StateUpdateInRenderRule",
    "LargeCustomHookRule",
    "CrossFeatureImportBoundaryRule",
    "QueryKeyInstabilityRule",
    "EffectEventRelaySmellRule",
    "RouteShellMissingErrorBoundaryRule",
    "UnsafeAsyncHandlerWithoutGuardRule",
    "ReactNoRandomKeyRule",
    "ReactNoPropsMutationRule",
    "ReactNoStateMutationRule",
    "ReactSideEffectsInRenderRule",
    "ReactEventListenerCleanupRequiredRule",
    "ReactTimerCleanupRequiredRule",
    "InertiaReloadWithoutOnlyRule",
    "InsecurePostMessageOriginWildcardRule",
    "TokenStorageInsecureLocalStorageRule",
    "ClientOpenRedirectUnvalidatedNavigationRule",
    "PostMessageReceiverOriginNotVerifiedRule",
    "DangerousHtmlSinkWithoutSanitizerRule",
    # Phase 1 React rules
    "UseEffectCleanupMissingRule",
    # Phase 2 React performance rules
    "MissingUseMemoForExpensiveCalcRule",
    "MissingUseCallbackForEventHandlersRule",
    # Phase 3 React architecture rules
    "MissingPropsTypeRule",
    # Phase 4 UX/A11y rules
    "TouchTargetSizeRule",
    "PlaceholderAsLabelRule",
    "LinkTextVagueRule",
    "ButtonTextVagueRule",
    "AutocompleteMissingRule",
    "HeadingOrderRule",
    "FocusIndicatorMissingRule",
    "SkipLinkMissingRule",
    "ModalTrapFocusRule",
    "ErrorMessageMissingRule",
    "LongPageNoTocRule",
    "ColorContrastRatioRule",
    # Phase 5 WCAG-based UX rules
    "PageTitleMissingRule",
    "LanguageAttributeMissingRule",
    "StatusMessageAnnouncementRule",
    "AutoplayMediaRule",
    "RedundantEntryRule",
    "AccessibleAuthenticationRule",
    "FocusNotObscuredRule",
    # CSS/Tailwind discipline rules
    "CssFontSizePxRule",
    "CssSpacingPxRule",
    "CssFixedLayoutPxRule",
    "TailwindArbitraryValueOveruseRule",
    "TailwindArbitraryTextSizeRule",
    "TailwindArbitrarySpacingRule",
    "TailwindArbitraryLayoutSizeRule",
    "TailwindArbitraryRadiusShadowRule",
    # CSS/Tailwind accessibility rules
    "TailwindMotionReduceMissingRule",
    "TailwindAppearanceNoneRiskRule",
    "CssFocusOutlineWithoutReplacementRule",
    "CssHoverOnlyInteractionRule",
    "CssColorOnlyStateIndicatorRule",
    # WCAG/APG AST accessibility rules
    "SemanticWrapperBreakageRule",
    "InteractiveAccessibleNameRequiredRule",
    "JsxAriaAttributeFormatRule",
    "OutsideClickWithoutKeyboardFallbackRule",
    "APGTabsKeyboardContractRule",
    "APGAccordionDisclosureContractRule",
    "APGMenuButtonContractRule",
    "APGComboboxContractRule",
    "DialogFocusRestoreMissingRule",
    # React gap expansion rules
    "AvoidPropsToStateCopyRule",
    "PropsStateSyncEffectSmellRule",
    "ControlledUncontrolledInputMismatchRule",
    "UseMemoOveruseRule",
    "UseCallbackOveruseRule",
    "ContextOversizedProviderRule",
    "LazyWithoutSuspenseRule",
    "SuspenseFallbackMissingRule",
    "StaleClosureInTimerRule",
    "StaleClosureInListenerRule",
    "DuplicateKeySourceRule",
    "MissingLoadingStateRule",
    "MissingEmptyStateRule",
    "RefAccessDuringRenderRule",
    "RefUsedAsReactiveStateRule",
    # React SEO expansion rules
    "MetaDescriptionMissingOrGenericRule",
    "CanonicalMissingOrInvalidRule",
    "RobotsDirectiveRiskRule",
    "CrawlableInternalNavigationRequiredRule",
    "JsonLdStructuredDataInvalidOrMismatchedRule",
    "H1SingletonViolationRule",
    "PageIndexabilityConflictRule",
    # AST-based rules (higher accuracy)
    "UseCallbackASTRule",
    "UseMemoASTRule",
    "ExhaustiveDepsASTRule",
    # Process-based rules (external tools)
    "TypeScriptTypeCheckRule",
]
