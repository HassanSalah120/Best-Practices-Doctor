"""React rules init."""
from .accessible_authentication import AccessibleAuthenticationRule
from .advanced_frontend_props import (
    InlinePropObjectArrayRule,
    LooseDefaultObjectPropRule,
    UnstableReactKeyRule,
)
from .animation_no_pause_control import AnimationNoPauseControlRule
from .anonymous_default_export_component import AnonymousDefaultExportComponentRule
from .apgaccordion_disclosure_contract import APGAccordionDisclosureContractRule
from .apgcombobox_contract import APGComboboxContractRule
from .apgmenu_button_contract import APGMenuButtonContractRule
from .apgtabs_keyboard_contract import APGTabsKeyboardContractRule
from .api_key_in_client_bundle import ApiKeyInClientBundleRule
from .autocomplete_missing import AutocompleteMissingRule
from .autoplay_media import AutoplayMediaRule

# React gap expansion rules
from .avoid_props_to_state_copy import AvoidPropsToStateCopyRule
from .button_text_vague import ButtonTextVagueRule
from .canonical_missing_or_invalid import CanonicalMissingOrInvalidRule
from .client_open_redirect_unvalidated_navigation import ClientOpenRedirectUnvalidatedNavigationRule
from .client_side_auth_only import ClientSideAuthOnlyRule
from .color_contrast_ratio import ColorContrastRatioRule
from .console_log_in_production_code import ConsoleLogInProductionCodeRule
from .context_oversized_provider import ContextOversizedProviderRule
from .context_provider_inline_value import ContextProviderInlineValueRule
from .controlled_uncontrolled_input_mismatch import ControlledUncontrolledInputMismatchRule
from .crawlable_internal_navigation_required import CrawlableInternalNavigationRequiredRule
from .cross_feature_import_boundary import CrossFeatureImportBoundaryRule
from .css_color_only_state_indicator import CssColorOnlyStateIndicatorRule
from .css_fixed_layout_px import CssFixedLayoutPxRule
from .css_focus_outline_without_replacement import CssFocusOutlineWithoutReplacementRule

# CSS/Tailwind discipline rules
from .css_font_size_px import CssFontSizePxRule
from .css_hover_only_interaction import CssHoverOnlyInteractionRule
from .css_spacing_px import CssSpacingPxRule
from .dangerous_html_sink_without_sanitizer import DangerousHtmlSinkWithoutSanitizerRule
from .derived_state_in_effect import DerivedStateInEffectRule
from .dialog_focus_restore_missing import DialogFocusRestoreMissingRule
from .duplicate_key_source import DuplicateKeySourceRule
from .effect_event_relay_smell import EffectEventRelaySmellRule
from .error_message_missing import ErrorMessageMissingRule
from .exhaustive_deps_ast import ExhaustiveDepsASTRule
from .focus_indicator_missing import FocusIndicatorMissingRule
from .focus_lost_on_route_change import FocusLostOnRouteChangeRule
from .focus_not_obscured import FocusNotObscuredRule
from .form_double_submit import FormDoubleSubmitRule
from .form_label_association import FormLabelAssociationRule
from .h1_singleton_violation import H1SingletonViolationRule
from .hardcoded_user_facing_strings import HardcodedUserFacingStringsRule
from .heading_order import HeadingOrderRule
from .hooks_in_conditional_or_loop import HooksInConditionalOrLoopRule
from .img_alt_missing import ImageAltMissingRule
from .inertia_form_uses_fetch import InertiaFormUsesFetchRule
from .inertia_internal_link_anchor import InertiaInternalLinkAnchorRule
from .inertia_page_missing_error_boundary import InertiaPageMissingErrorBoundaryRule
from .inertia_page_missing_head import InertiaPageMissingHeadRule
from .inertia_reload_without_only import InertiaReloadWithoutOnlyRule
from .inline_logic import InlineLogicRule
from .input_debounce_missing import InputDebounceMissingRule
from .insecure_postmessage_origin_wildcard import InsecurePostMessageOriginWildcardRule
from .interactive_accessible_name_required import InteractiveAccessibleNameRequiredRule
from .interactive_element_a11y import InteractiveElementA11yRule
from .json_ld_structured_data_invalid_or_mismatched import (
    JsonLdStructuredDataInvalidOrMismatchedRule,
)
from .jsx_aria_attribute_format import JsxAriaAttributeFormatRule
from .language_attribute_missing import LanguageAttributeMissingRule
from .large_component import LargeComponentRule
from .large_custom_hook import LargeCustomHookRule
from .lazy_without_suspense import LazyWithoutSuspenseRule
from .link_text_vague import LinkTextVagueRule
from .long_page_no_toc import LongPageNoTocRule

# React SEO expansion rules
from .meta_description_missing_or_generic import MetaDescriptionMissingOrGenericRule
from .missing_empty_state import MissingEmptyStateRule
from .missing_error_boundary_general import MissingErrorBoundaryGeneralRule
from .missing_fieldset_legend import MissingFieldsetLegendRule
from .missing_key_on_list_render import MissingKeyOnListRenderRule
from .missing_list_virtualization import MissingListVirtualizationRule
from .missing_loading_state import MissingLoadingStateRule

# Phase 3 React architecture rules
from .missing_props_type import MissingPropsTypeRule
from .missing_route_code_splitting import MissingRouteCodeSplittingRule
from .missing_usecallback_for_event_handlers import MissingUseCallbackForEventHandlersRule

# Phase 2 React performance rules
from .missing_usememo_for_expensive_calc import MissingUseMemoForExpensiveCalcRule
from .modal_trap_focus import ModalTrapFocusRule
from .multiple_exported_components_per_file import MultipleExportedComponentsPerFileRule
from .no_array_index_key import NoArrayIndexKeyRule
from .no_dangerously_set_inner_html import NoDangerouslySetInnerHtmlRule
from .no_direct_useeffect import NoDirectUseEffectRule
from .no_inline_hooks import NoInlineHooksRule
from .no_inline_services import NoInlineServicesRule
from .no_inline_types import NoInlineTypesRule
from .no_nested_components import NoNestedComponentsRule
from .outside_click_without_keyboard_fallback import OutsideClickWithoutKeyboardFallbackRule
from .page_indexability_conflict import PageIndexabilityConflictRule

# Phase 5 WCAG-based UX rules
from .page_title_missing import PageTitleMissingRule
from .placeholder_as_label import PlaceholderAsLabelRule
from .postmessage_receiver_origin_not_verified import PostMessageReceiverOriginNotVerifiedRule
from .project_structure_consistency import ReactProjectStructureConsistencyRule
from .props_state_sync_effect_smell import PropsStateSyncEffectSmellRule
from .query_key_instability import QueryKeyInstabilityRule
from .react_event_listener_cleanup_required import ReactEventListenerCleanupRequiredRule
from .react_no_props_mutation import ReactNoPropsMutationRule
from .react_no_random_key import ReactNoRandomKeyRule
from .react_no_state_mutation import ReactNoStateMutationRule
from .react_parent_child_spacing_overlap import ReactParentChildSpacingOverlapRule
from .react_side_effects_in_render import ReactSideEffectsInRenderRule
from .react_timer_cleanup_required import ReactTimerCleanupRequiredRule
from .redundant_entry import RedundantEntryRule
from .ref_access_during_render import RefAccessDuringRenderRule
from .ref_used_as_reactive_state import RefUsedAsReactiveStateRule
from .robots_directive_risk import RobotsDirectiveRiskRule
from .route_shell_missing_error_boundary import RouteShellMissingErrorBoundaryRule
from .safe_target_blank import SafeTargetBlankRule

# WCAG/APG AST accessibility rules
from .semantic_wrapper_breakage import SemanticWrapperBreakageRule
from .skip_link_missing import SkipLinkMissingRule
from .stale_closure_in_listener import StaleClosureInListenerRule
from .stale_closure_in_timer import StaleClosureInTimerRule
from .state_update_in_render import StateUpdateInRenderRule
from .status_message_announcement import StatusMessageAnnouncementRule
from .suspense_fallback_missing import SuspenseFallbackMissingRule
from .table_missing_headers import TableMissingHeadersRule
from .tailwind_appearance_none_risk import TailwindAppearanceNoneRiskRule
from .tailwind_arbitrary_layout_size import TailwindArbitraryLayoutSizeRule
from .tailwind_arbitrary_radius_shadow import TailwindArbitraryRadiusShadowRule
from .tailwind_arbitrary_spacing import TailwindArbitrarySpacingRule
from .tailwind_arbitrary_text_size import TailwindArbitraryTextSizeRule
from .tailwind_arbitrary_value_overuse import TailwindArbitraryValueOveruseRule

# CSS/Tailwind accessibility rules
from .tailwind_motion_reduce_missing import TailwindMotionReduceMissingRule
from .token_storage_insecure_localstorage import TokenStorageInsecureLocalStorageRule

# Phase 4 UX/A11y rules
from .touch_target_size import TouchTargetSizeRule

# Process-based rules (external tools)
from .typescript_type_check import TypeScriptTypeCheckRule
from .unhandled_promise_in_handler import UnhandledPromiseInHandlerRule
from .unsafe_async_handler_without_guard import UnsafeAsyncHandlerWithoutGuardRule
from .unthrottled_scroll_resize_handler import UnthrottledScrollResizeHandlerRule
from .use_callback_overuse import UseCallbackOveruseRule
from .use_memo_overuse import UseMemoOveruseRule

# Other standalone React rules
from .vite_chunk_config_missing import ViteChunkConfigMissingRule
from .window_any_typing import WindowAnyTypingRule

# AST-based rules (higher accuracy)
from .usecallback_ast import UseCallbackASTRule

# Phase 1 React rules
from .useeffect_cleanup_missing import UseEffectCleanupMissingRule
from .useeffect_dependency_array import UseEffectDependencyArrayRule
from .useeffect_fetch_without_abort import UseEffectFetchWithoutAbortRule
from .useless_suspense_boundary import UselessSuspenseBoundaryRule
from .usememo_ast import UseMemoASTRule
from .video_missing_captions import VideoMissingCaptionsRule

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
    "ApiKeyInClientBundleRule",
    "ClientSideAuthOnlyRule",
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
    "UnthrottledScrollResizeHandlerRule",
    "MissingListVirtualizationRule",
    "InputDebounceMissingRule",
    "MissingRouteCodeSplittingRule",
    "MissingErrorBoundaryGeneralRule",
    "UnhandledPromiseInHandlerRule",
    "FormDoubleSubmitRule",
    "FocusLostOnRouteChangeRule",
    "TableMissingHeadersRule",
    "MissingFieldsetLegendRule",
    "VideoMissingCaptionsRule",
    "AnimationNoPauseControlRule",
    "InlinePropObjectArrayRule",
    "UnstableReactKeyRule",
    "LooseDefaultObjectPropRule",
    "ConsoleLogInProductionCodeRule",
    "InertiaPageMissingErrorBoundaryRule",
    "UselessSuspenseBoundaryRule",
    "WindowAnyTypingRule",
]
