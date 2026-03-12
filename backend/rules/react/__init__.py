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
from .inertia_page_missing_head import InertiaPageMissingHeadRule
from .inertia_internal_link_anchor import InertiaInternalLinkAnchorRule
from .inertia_form_uses_fetch import InertiaFormUsesFetchRule
from .anonymous_default_export_component import AnonymousDefaultExportComponentRule
from .multiple_exported_components_per_file import MultipleExportedComponentsPerFileRule
from .context_provider_inline_value import ContextProviderInlineValueRule
from .useeffect_fetch_without_abort import UseEffectFetchWithoutAbortRule
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
    "InertiaPageMissingHeadRule",
    "InertiaInternalLinkAnchorRule",
    "InertiaFormUsesFetchRule",
    "AnonymousDefaultExportComponentRule",
    "MultipleExportedComponentsPerFileRule",
    "ContextProviderInlineValueRule",
    "UseEffectFetchWithoutAbortRule",
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
]
