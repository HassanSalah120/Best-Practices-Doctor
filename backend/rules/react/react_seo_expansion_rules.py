from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TypedDict

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

_TEST_PATH_MARKERS = ("tests", "test", "__tests__", "stories", "storybook", "fixtures")
_PAGE_PATH_MARKERS = ("pages", "screens", "views")
_NON_RENDER_PATH_MARKERS = ("hooks", "utils", "helpers", "lib", "services", "types")
_NON_INDEXABLE_TEMPLATE_MARKERS = ("/views/pdf/", "/views/vendor/mail/", "/mail/", "/emails/")

# Internal markers that suggest a page is not public-facing
_INTERNAL_APP_PATH_MARKERS = (
    "admin",
    "dashboard",
    "settings",
    "account",
    "profile",
    "manage",
    "internal",
    "config",
    "setup",
    "clinic",
    "appointments",
    "patients",
    "encounters",
    "financials",
    "reports",
    "error",
    "errors",
    "404",
    "500",
)

_AUTHENTICATED_LAYOUT_MARKERS = (
    "AuthenticatedLayout",
    "AppLayout",
    "AdminLayout",
    "DashboardLayout",
    "ClinicLayout",
    "PatientPortalLayout",
    "PortalLayout",
)

_PUBLIC_LAYOUT_MARKERS = (
    "GuestLayout",
    "PublicLayout",
    "MarketingLayout",
    "LandingLayout",
)

_CHILD_COMPONENT_PATH_MARKERS = ("components", "fragments", "partials", "utils", "hooks", "services")

# Suffixes that suggest a file is a sub-component/section, not a full page
_CHILD_COMPONENT_NAME_HINTS = (
    "content",
    "section",
    "list",
    "grid",
    "card",
    "cards",
    "item",
    "items",
    "widget",
    "panel",
    "header",
    "footer",
    "banner",
    "hero",
    "modal",
    "dialog",
    "table",
    "row",
    "column",
    "noise",
    "background",
    "benefits",
    "navbar",
    "form",
    "drawer",
    "view",
    "sidebar",
    "wizard",
    "step",
    "steps",
    "proof",
    "preview",
    "skeleton",
    "overlay",
    "wrapper",
    "faq",
    "features",
    "pricing",
    "security",
    "contact",
    "contactsales",
    "socialproof",
    "screenspreview",
    "screenspreviewcontent",
    "welcomefooter",
    "welcomenavbar",
    "successview",
    "identitysection",
    "assetitem",
    "sidebarcontent",
)


class PageClassification(TypedDict):
    """Signals used to determine if a module is an indexable page."""
    is_page_like: bool
    is_internal: bool
    is_child: bool
    is_wrapper: bool
    is_public_project: bool
    has_explicit_seo: bool
    has_public_layout: bool
    has_auth_layout: bool


class _SeoRuleBase(Rule):
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx", ".html", ".blade.php"]

    # Centralized Regex Definitions
    _ROBOTS = re.compile(
        r"<meta[^>]*name=['\"]robots['\"][^>]*content=['\"](?P<value>[^'\"]+)['\"][^>]*>",
        re.IGNORECASE,
    )
    _CANONICAL = re.compile(
        r"<link[^>]*rel=['\"]canonical['\"][^>]*href=(?:['\"](?P<href>[^'\"]+)['\"]|\{(?P<expr>[^}]+)\})[^>]*>",
        re.IGNORECASE,
    )
    _BLADE_CANONICAL_URL_GENERATOR = re.compile(
        r"<link[^>]*rel=['\"]canonical['\"][^>]*href=['\"]\s*\{\{\s*(?:url|secure_url|route)\s*\([^}]+?\)\s*\}\}\s*['\"][^>]*>",
        re.IGNORECASE | re.DOTALL,
    )
    _BLADE_ECHO = re.compile(r"\{\{\s*(?P<expr>.*?)\s*\}\}", re.DOTALL)
    _BLADE_JSONLD_SERIALIZER = re.compile(
        r"(?:json_encode\s*\(|Js::from\s*\(|@json\s*\()",
        re.IGNORECASE,
    )
    _META_DESC_PRESENT = re.compile(
        r"<meta[^>]*name\s*=\s*['\"]description['\"][^>]*content\s*=\s*(?:['\"][^'\"]*['\"]|\{[^}]+\})[^>]*>",
        re.IGNORECASE | re.DOTALL,
    )
    _JSX_ELEMENT = re.compile(r"<[A-Z][A-Za-z0-9_.:-]*(?:\s|/?>)")  # More restrictive: PascalCase components
    _HTML_TAG = re.compile(r"<(?:html|body|main|section|article|div|h1|title|meta|link|button|a|p|ul|ol|li|span|svg|form|input|label|textarea|select|table|tr|td|th|thead|tbody|footer|header|nav|aside|details|summary|canvas|video|audio|picture|figure|figcaption)\b", re.IGNORECASE)

    # Common route entry basenames
    _ROUTE_ENTRIES = {
        "index", "show", "edit", "create", "new",
        "home", "landing", "welcome", "dashboard",
        "login", "register", "signin", "signup",
        "about", "pricing", "contact", "features", "security",
        "profile", "account", "settings", "search", "results",
        "badpage",
    }

    _ALWAYS_INDEXABLE_FOLDERS = {"welcome", "public", "marketing", "auth"}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def _get_path_segments(self, file_path: str) -> list[str]:
        return [s for s in (file_path or "").replace("\\", "/").lower().split("/") if s]

    def _skip_file(self, file_path: str) -> bool:
        segments = self._get_path_segments(file_path)
        return any(marker in segments for marker in _TEST_PATH_MARKERS)

    def _is_page_like(self, file_path: str) -> bool:
        low = (file_path or "").lower()
        # Page components are usually .tsx, .jsx or .blade.php
        if not low.endswith((".tsx", ".jsx", ".blade.php")):
            return False
        if low.endswith((".d.ts", ".types.ts", ".types.tsx")):
            return False
        segments = self._get_path_segments(file_path)
        return any(marker in segments for marker in _PAGE_PATH_MARKERS)

    def _is_inertia_shell_template(self, file_path: str, content: str) -> bool:
        if not (file_path or "").lower().endswith(".blade.php"):
            return False
        text = content or ""
        return "@inertia" in text or "@inertiaHead" in text or 'id="app"' in text or "id='app'" in text

    def _line_for_offset(self, content: str, offset: int) -> int:
        """Calculate line number for a given character offset."""
        if not content:
            return 1
        # count() is O(N), but we only do it once per finding
        return content.count("\n", 0, max(0, offset)) + 1

    def _blade_variable_assigned_from_url_generator(self, content: str, expression: str) -> bool:
        variable_match = re.search(r"\$[A-Za-z_][A-Za-z0-9_]*", expression or "")
        if not variable_match:
            return False
        variable = re.escape(variable_match.group(0))
        return bool(
            re.search(
                rf"{variable}\s*=\s*(?:[^;]*\b)?(?:url|secure_url|route)\s*\(",
                content or "",
                re.IGNORECASE | re.DOTALL,
            ),
        )

    def _blade_echo_resolves_to_url(self, content: str, value: str) -> bool:
        match = self._BLADE_ECHO.search(value or "")
        if not match:
            return False
        expression = str(match.group("expr") or "")
        if re.search(r"\b(?:url|secure_url|route)\s*\(", expression, re.IGNORECASE):
            return True
        return self._blade_variable_assigned_from_url_generator(content, expression)

    def _is_blade_dynamic_value(self, value: str) -> bool:
        return bool(self._BLADE_ECHO.search(value or ""))

    def _project_is_public_surface(self, facts: Facts) -> bool:
        ctx = getattr(facts, "project_context", None)
        if ctx is None:
            return False

        # Use project_type and capabilities to determine if this project has public surfaces
        p_type = str(getattr(ctx, "project_type", "") or "").strip().lower()
        if p_type in {"public_website_with_dashboard", "portal_based_business_app", "saas_platform"}:
            return True

        capabilities = getattr(ctx, "capabilities", {}) or {}
        for key in ("mixed_public_dashboard", "public_marketing_site"):
            payload = capabilities.get(key)
            if isinstance(payload, dict) and payload.get("enabled"):
                return True
        return False

    def _explicit_indexability_signal(self, content: str) -> bool:
        text = content or ""
        return bool(
            re.search(r"<(?:Head|Helmet)\b", text)
            or re.search(r"<title\b", text, re.IGNORECASE)
            or re.search(r"document\.title\s*=", text)
            or self._ROBOTS.search(text),
        )

    def _looks_like_render_module(self, file_path: str, content: str) -> bool:
        segments = self._get_path_segments(file_path)
        if any(marker in segments for marker in _NON_RENDER_PATH_MARKERS):
            return False

        text = content or ""
        if (file_path or "").lower().endswith(".blade.php"):
            return bool(self._HTML_TAG.search(text))

        # Look for JSX-like elements or common React patterns
        return bool(self._JSX_ELEMENT.search(text) or self._HTML_TAG.search(text))

    def _is_non_indexable_template(self, file_path: str) -> bool:
        low = (file_path or "").replace("\\", "/").lower()
        return low.endswith(".blade.php") and any(marker in low for marker in _NON_INDEXABLE_TEMPLATE_MARKERS)

    def _is_internal_app_surface(self, file_path: str) -> bool:
        segments = self._get_path_segments(file_path)

        # Portal and Auth pages are often public-facing (e.g. patient portal, login)
        # BUT specific sensitive auth pages or clearly internal segments should be skipped.
        if "auth" in segments:
            # Skip highly sensitive or intermediate auth states that don't need SEO
            sensitive_auth = {"confirmpassword", "twofactorchallenge", "verifyemail", "roleselection", "onboarding"}
            if any(s in segments for s in sensitive_auth):
                return True
            return False

        if "portal" in segments or "patientportal" in segments:
            return False

        return any(marker in segments for marker in _INTERNAL_APP_PATH_MARKERS)

    def _is_thin_wrapper_module(self, content: str) -> bool:
        text = content or ""
        # If it has explicit SEO tags, it's not just a thin wrapper for SEO purposes
        if re.search(r"<(?:h1|link\b[^>]*rel=['\"]canonical['\"])", text, re.IGNORECASE) or self._META_DESC_PRESENT.search(text):
            return False

        return bool(
            re.search(
                r"return\s*(?:\(\s*)?<(?P<tag>[A-Z][A-Za-z0-9_]*(?:View|Page|Screen))\b[\s\S]*?(?:/?>)",
                text,
                re.IGNORECASE,
            ),
        )

    def _has_heading_proxy(self, content: str) -> bool:
        text = content or ""
        return bool(re.search(r"<(?:PageHeader|ScreenHeader|EntityPageHeader|AppPageHeader)\b", text, re.IGNORECASE))

    def _looks_like_child_composition(self, file_path: str, content: str) -> bool:
        text = content or ""
        # If it has explicit indexability signals (Head/Helmet/Title) or Layouts, it's a page.
        if self._explicit_indexability_signal(text) or \
           any(marker in text for marker in _AUTHENTICATED_LAYOUT_MARKERS) or \
           any(marker in text for marker in _PUBLIC_LAYOUT_MARKERS):
            return False

        segments = self._get_path_segments(file_path)
        if any(marker in segments for marker in _CHILD_COMPONENT_PATH_MARKERS):
            return True

        full_name = Path(file_path or "").name.lower()
        if ".components." in full_name or ".utils." in full_name:
            return True

        stem = Path(file_path or "").stem
        low_stem = stem.lower()

        # New heuristic: If it's in a subdirectory of pages/ but not a known route entry,
        # and has no layout/head, it's likely a section component.
        if low_stem not in self._ROUTE_ENTRIES:
            if "pages" in segments:
                pages_idx = segments.index("pages")
                # e.g. resources/js/pages/Welcome/Features.tsx -> len=4, pages_idx=1 -> 4 > 1+2 is True
                # e.g. resources/js/pages/Home.tsx -> len=3, pages_idx=1 -> 3 > 1+2 is False
                # BUT if it's "Pages" (capital P), segments will have "pages" (lowercase) due to _get_path_segments
                if len(segments) > (pages_idx + 2):
                    return True

        # Use segment-based hint matching to avoid "cardboard.tsx" matching "card"
        for hint in _CHILD_COMPONENT_NAME_HINTS:
            if low_stem == hint or low_stem.endswith(f"_{hint}") or low_stem.endswith(f"-{hint}"):
                return True

            if low_stem.endswith(hint):
                # Check if the character before hint is uppercase (PascalCase) or a separator
                prefix_idx = len(stem) - len(hint)
                if prefix_idx <= 0:
                    return True
                if stem[prefix_idx].isupper() or stem[prefix_idx-1] in "_-":
                    return True
        return False

    def _is_probably_indexable_page(self, file_path: str, content: str, facts: Facts) -> bool:
        """
        Determines if a file is a page that should be indexed by search engines.
        Uses a hierarchical decision model to reduce false positives.
        """
        text = content or ""

        # 1. Hard exclusions (Non-indexable templates, shell templates, non-render modules)
        if self._is_non_indexable_template(file_path) or self._is_inertia_shell_template(file_path, text):
            return False
        if not self._looks_like_render_module(file_path, text):
            return False

        # 2. Explicit layout signals (Strongest indicators of intent)
        # If it uses a layout, it's definitely a page.
        if any(marker in text for marker in _AUTHENTICATED_LAYOUT_MARKERS):
            return False
        if any(marker in text for marker in _PUBLIC_LAYOUT_MARKERS):
            return True

        # 3. Structural signals (Thin wrappers, child components)
        if self._is_thin_wrapper_module(text) or self._looks_like_child_composition(file_path, text):
            return False

        # 4. Path-based heuristics (Internal markers like /admin/)
        if self._is_internal_app_surface(file_path):
            return False

        # 5. Fallback: Project-wide context OR explicit SEO signals
        # If the project is a public-facing app, we assume pages are indexable IF they look like pages.
        if self._project_is_public_surface(facts):
            # If it has Head or Layout, it's definitely a page.
            if self._explicit_indexability_signal(text):
                return True

            # If it's a standard route entry name, it's a page.
            stem = Path(file_path).stem.lower()
            if stem in self._ROUTE_ENTRIES:
                return True

            # If it's in a known "always public" folder, it's indexable if it's the leaf.
            segments = self._get_path_segments(file_path)
            if any(f in segments for f in self._ALWAYS_INDEXABLE_FOLDERS):
                # If it's not a child composition (already checked), we assume it's indexable.
                return True

            # Otherwise, if it has no Head/Layout and is not a standard name,
            # we don't assume it's an indexable page even in a public project.
            return False

        return self._explicit_indexability_signal(text)


class MetaDescriptionMissingOrGenericRule(_SeoRuleBase):
    id = "meta-description-missing-or-generic"
    name = "Meta Description Missing or Generic"
    description = "Detects missing or generic page-level meta descriptions on indexable/public surfaces"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY

    _META_DESC_LITERAL = re.compile(
        r"<meta[^>]*name\s*=\s*['\"]description['\"][^>]*content\s*=\s*['\"](?P<value>[^'\"]*)['\"][^>]*>",
        re.IGNORECASE | re.DOTALL,
    )
    _GENERIC = {
        "website",
        "default description",
        "lorem ipsum",
        "page description",
        "description",
    }
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Refactor the component code to remove the meta description missing or generic pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 4
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'meta-description-or'}

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        if not self._is_page_like(file_path):
            return []
        if not self._is_probably_indexable_page(file_path, text, facts):
            return []

        present_match = self._META_DESC_PRESENT.search(text)
        if not present_match:
            return [
                self.create_finding(
                    title="Meta description is missing on indexable page surface",
                    context=f"{file_path}:meta-description",
                    file=file_path,
                    line_start=1,
                    description="No explicit meta description was found for this page module.",
                    why_it_matters="Descriptions improve snippet quality and search result clarity for public-facing pages. Internal pages do not require SEO meta descriptions.",
                    suggested_fix="Add a route-specific meta description via `Head`/`Helmet`. If this is an internal page, ensure it uses `AuthenticatedLayout` or is located in an internal folder.",
                    confidence=0.85,
                    tags=["seo", "meta", "react"],
                    evidence_signals=["seo_head_signal_missing=description"],
                    metadata={
                        "overlap_group": "seo-head",
                        "overlap_rank": 60,
                        "overlap_scope": file_path,
                        "decision_profile": {"seo_head_signal_missing": "meta_description"},
                    },
                ),
            ]

        literal_match = self._META_DESC_LITERAL.search(text)
        if not literal_match:
            return []

        raw_value = str(literal_match.group("value") or "").strip()
        if self._is_blade_dynamic_value(raw_value):
            return []

        value = raw_value.lower()
        if len(value) < 35 or value in self._GENERIC:
            line = self._line_for_offset(text, literal_match.start())
            return [
                self.create_finding(
                    title="Meta description appears generic",
                    context=f"{file_path}:{line}:meta-description",
                    file=file_path,
                    line_start=line,
                    description="Meta description exists but appears too short or generic.",
                    why_it_matters="Low-quality descriptions reduce snippet usefulness and click confidence.",
                    suggested_fix="Use a specific, page-intent description (typically 50-160 characters).",
                    confidence=0.82,
                    tags=["seo", "meta"],
                    evidence_signals=[f"meta_description_value={value[:40]}"],
                    metadata={
                        "overlap_group": "seo-head",
                        "overlap_rank": 55,
                        "overlap_scope": file_path,
                    },
                ),
            ]
        return []


class CanonicalMissingOrInvalidRule(_SeoRuleBase):
    id = "canonical-missing-or-invalid"
    name = "Canonical Missing or Invalid"
    description = "Detects missing or malformed canonical metadata on public/indexable pages"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    severity_weight = 0
    confidence = 'high'
    fix_suggestion = 'Refactor the component code to remove the canonical missing or invalid pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component', 'page']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'canonical-or-invalid'}

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        if not self._is_page_like(file_path):
            return []
        if not self._is_probably_indexable_page(file_path, text, facts):
            return []

        if self._BLADE_CANONICAL_URL_GENERATOR.search(text):
            return []

        match = self._CANONICAL.search(text)
        if not match:
            return [
                self.create_finding(
                    title="Canonical link is missing on indexable page",
                    context=f"{file_path}:canonical",
                    file=file_path,
                    line_start=1,
                    description="No canonical link was detected for this page module.",
                    why_it_matters="Canonical URLs help consolidate duplicate routes and avoid split indexing. Only public-facing indexable pages require canonical links.",
                    suggested_fix="Add a `<link rel='canonical' href='...' />` tag. If this is an internal or authenticated page that should not be indexed, ensure it uses `AuthenticatedLayout` or is located in an internal folder (e.g., /admin, /dashboard).",
                    confidence=0.84,
                    tags=["seo", "canonical"],
                    evidence_signals=["canonical_signal=missing"],
                    metadata={
                        "overlap_group": "seo-indexability",
                        "overlap_rank": 70,
                        "overlap_scope": file_path,
                        "decision_profile": {"canonical_signal": "missing"},
                    },
                ),
            ]

        # If it's a dynamic expression (e.g. href={route('...')}), we skip validation
        if match.group("expr"):
            return []

        href = str(match.group("href") or "").strip()
        if self._blade_echo_resolves_to_url(text, href):
            return []
        if not (href.startswith("http://") or href.startswith("https://") or href.startswith("/")):
            line = self._line_for_offset(text, match.start())
            return [
                self.create_finding(
                    title="Canonical URL looks invalid",
                    context=f"{file_path}:{line}:canonical",
                    file=file_path,
                    line_start=line,
                    description=f"Canonical href `{href}` does not appear absolute or rooted.",
                    why_it_matters="Invalid canonicals can confuse indexing and duplicate handling.",
                    suggested_fix="Use an absolute canonical URL (or root-relative path when supported by your rendering strategy).",
                    confidence=0.9,
                    tags=["seo", "canonical"],
                    evidence_signals=[f"canonical_signal=invalid:{href}"],
                    metadata={
                        "overlap_group": "seo-indexability",
                        "overlap_rank": 75,
                        "overlap_scope": file_path,
                        "decision_profile": {"canonical_signal": "invalid"},
                    },
                ),
            ]
        return []


class RobotsDirectiveRiskRule(_SeoRuleBase):
    id = "robots-directive-risk"
    name = "Robots Directive Risk"
    description = "Detects risky robots directives on likely public/indexable pages"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the robots directive risk pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component', 'page']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'robots-directive'}

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        if not self._is_page_like(file_path):
            return []
        match = self._ROBOTS.search(text)
        if not match:
            return []

        value = str(match.group("value") or "").strip().lower()
        if "noindex" not in value and "none" not in value:
            return []
        if not self._project_is_public_surface(facts):
            return []

        line = self._line_for_offset(text, match.start())
        return [
            self.create_finding(
                title="Robots directive may de-index public page",
                context=f"{file_path}:{line}:robots",
                file=file_path,
                line_start=line,
                description=f"Robots directive includes `{value}` on a public/indexable surface.",
                why_it_matters="Accidental noindex directives can suppress critical public pages from search results.",
                suggested_fix="Use `index,follow` for intended public pages and keep `noindex` for private/utility routes only.",
                confidence=0.9,
                tags=["seo", "robots", "indexing"],
                evidence_signals=[f"robots_signal={value}"],
                metadata={
                    "overlap_group": "seo-indexability",
                    "overlap_rank": 90,
                    "overlap_scope": file_path,
                    "decision_profile": {"robots_signal": value},
                },
            ),
        ]


class CrawlableInternalNavigationRequiredRule(_SeoRuleBase):
    id = "crawlable-internal-navigation-required"
    name = "Crawlable Internal Navigation Required"
    description = "Detects internal navigation implemented without crawlable anchor/link semantics"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY

    _JS_NAV_SIGNAL = re.compile(
        r"(router\.visit\(|navigate\(|window\.location(?:\.href)?\s*=|history\.push\()",
        re.IGNORECASE,
    )
    _ANCHOR_SIGNAL = re.compile(r"<a\s+[^>]*href=|<Link\b[^>]*href=", re.IGNORECASE)
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the crawlable internal navigation required pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'crawlable-internal-navigation'}

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        if not self._is_page_like(file_path):
            return []
        text = content or ""
        if not self._is_probably_indexable_page(file_path, text, facts):
            return []
        if not self._JS_NAV_SIGNAL.search(text):
            return []
        if self._ANCHOR_SIGNAL.search(text):
            return []
        return [
            self.create_finding(
                title="Internal navigation may not be crawlable",
                context=f"{file_path}:crawlable-nav",
                file=file_path,
                line_start=1,
                description="Navigation logic was detected without anchor/link semantics that expose crawlable `href` targets.",
                why_it_matters="Important pages should remain discoverable via real links for crawlers and non-JS fallbacks.",
                suggested_fix="Use anchor/Link components with concrete `href` values for indexable internal routes.",
                confidence=0.82,
                tags=["seo", "navigation", "crawlability"],
                evidence_signals=["seo_head_signal_missing=crawlable_link"],
                metadata={"decision_profile": {"seo_head_signal_missing": "crawlable_link"}},
            ),
        ]


class JsonLdStructuredDataInvalidOrMismatchedRule(_SeoRuleBase):
    id = "jsonld-structured-data-invalid-or-mismatched"
    name = "JSON-LD Structured Data Invalid or Mismatched"
    description = "Detects invalid or weakly-formed JSON-LD structured data blocks"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY

    _JSONLD_BLOCK = re.compile(
        r"<script[^>]*type=['\"]application/ld\+json['\"][^>]*>\s*(?P<body>.*?)\s*</script>",
        re.IGNORECASE | re.DOTALL,
    )
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the json-ld structured data invalid or mismatched pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'jsonld-structured-data'}

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        findings: list[Finding] = []
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        for match in self._JSONLD_BLOCK.finditer(text):
            body = str(match.group("body") or "").strip()
            line = self._line_for_offset(text, match.start())
            if self._BLADE_JSONLD_SERIALIZER.search(body):
                continue
            parse_error = ""
            data = None
            try:
                data = json.loads(body)
            except Exception as exc:
                parse_error = str(exc)

            if parse_error:
                findings.append(
                    self.create_finding(
                        title="JSON-LD block is not valid JSON",
                        context=f"{file_path}:{line}:jsonld",
                        file=file_path,
                        line_start=line,
                        description="Structured data block could not be parsed as valid JSON.",
                        why_it_matters="Invalid JSON-LD is ignored by search engines and can silently fail rich-result eligibility.",
                        suggested_fix="Generate JSON-LD from typed objects and serialize with `JSON.stringify` to avoid syntax drift.",
                        confidence=0.94,
                        tags=["seo", "jsonld", "structured-data"],
                        evidence_signals=[f"jsonld_signal=parse_error:{parse_error[:80]}"],
                        metadata={"decision_profile": {"jsonld_signal": "parse_error"}},
                    ),
                )
            elif isinstance(data, dict):
                missing = []
                if "@context" not in data:
                    missing.append("@context")
                if "@type" not in data:
                    missing.append("@type")
                if missing:
                    findings.append(
                        self.create_finding(
                            title="JSON-LD block is missing required core fields",
                            context=f"{file_path}:{line}:jsonld",
                            file=file_path,
                            line_start=line,
                            description=f"Structured data object is missing: {', '.join(missing)}.",
                            why_it_matters="Incomplete JSON-LD reduces machine readability and rich-result processing quality.",
                            suggested_fix="Include at least `@context` and `@type` and keep schema fields aligned to visible content.",
                            confidence=0.88,
                            tags=["seo", "jsonld", "schema"],
                            evidence_signals=[f"jsonld_signal=missing:{','.join(missing)}"],
                            metadata={"decision_profile": {"jsonld_signal": "missing_core_fields"}},
                        ),
                    )
            if len(findings) >= max_findings:
                break
        return findings


class H1SingletonViolationRule(_SeoRuleBase):
    id = "h1-singleton-violation"
    name = "H1 Singleton Violation"
    description = "Detects missing or multiple H1 headings on page surfaces"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY

    _H1 = re.compile(r"<h1\b", re.IGNORECASE)
    _H2_TO_H6 = re.compile(r"<h[2-6]\b", re.IGNORECASE)
    _LAYOUT_TITLE = re.compile(
        r"<(?:AdminLayout|SiteLayout|PortalLayout|DashboardLayout|AppLayout)\b[^>]*\btitle\s*=",
        re.IGNORECASE | re.DOTALL,
    )
    _NON_INDEXABLE_PATH = ("admin", "auth", "errors", "layouts", "components")
    _UTILITY_FILE_PATTERNS = ("utils.ts", "utils.tsx", "helpers.ts", "helpers.tsx", ".d.ts", ".types.ts", ".types.tsx")
    _HOOK_FILE_PATTERN = re.compile(r"^use[A-Z].*\.ts$", re.IGNORECASE)

    # Export pattern detection (improved: arrow exports, no PascalCase assumption)
    _DEFAULT_EXPORT = re.compile(r"\bexport\s+default\b", re.IGNORECASE)
    _NAMED_EXPORT = re.compile(r"\bexport\s+(?:function|class|const|let|var)\b", re.IGNORECASE)
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the h1 singleton violation pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 3
    group = 'Code Quality'
    applies_to = ['react-component', 'page']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'h1-singleton-violation'}

    def _is_utility_or_hook_file(self, file_path: str) -> bool:
        """Check if file is a utility or hook file that shouldn't be analyzed for h1."""
        segments = self._get_path_segments(file_path)
        if any(marker in segments for marker in ("utils", "helpers", "hooks")):
            return True

        low = (file_path or "").lower()
        if low.endswith((".d.ts", ".types.ts", ".types.tsx")):
            return True

        basename = Path(file_path).name
        if self._HOOK_FILE_PATTERN.match(basename):
            return True
        return False

    def _is_route_entry_file(self, file_path: str) -> bool:
        """Check if this file itself is a route entry (Index, Show, Edit, Create)."""
        stem = Path(file_path).stem.lower()
        return stem in self._ROUTE_ENTRIES

    def _has_sibling_route_entry(self, file_path: str, facts: Facts) -> bool:
        """
        Check if file has a sibling route entry file (Index, Show, Edit, Create).
        Uses facts.files for deterministic environment-independent behavior.
        """
        if self._is_route_entry_file(file_path):
            return False

        parent_dir = str(Path(file_path).parent).replace("\\", "/")
        if parent_dir == ".":
            parent_dir = ""
        else:
            parent_dir = parent_dir.rstrip("/") + "/"

        route_entries = ("index.tsx", "index.jsx", "show.tsx", "show.jsx",
                        "edit.tsx", "edit.jsx", "create.tsx", "create.jsx")

        # Check against facts.files instead of real filesystem
        for entry in route_entries:
            sibling_path = parent_dir + entry
            if sibling_path in facts.files:
                return True
        return False

    def _extract_heading_signals(self, content: str) -> dict[str, bool]:
        """Extract heading-related signals from content."""
        text = content or ""
        return {
            "has_h1": bool(self._H1.search(text)),
            "has_h2_to_h6": bool(self._H2_TO_H6.search(text)),
        }

    def _extract_export_signals(self, content: str) -> dict[str, bool]:
        """Extract export pattern signals from content."""
        text = content or ""
        return {
            "has_default_export": bool(self._DEFAULT_EXPORT.search(text)),
            "has_named_export": bool(self._NAMED_EXPORT.search(text)),
        }

    def _classify_file_type(self, file_path: str, content: str, facts: Facts, h1_count: int = 0) -> dict:
        """
        Multi-signal classification system to determine if file is a page or section component.
        """
        signals = {
            "has_sibling_route": False,
            "is_route_entry": False,
            "has_h2_no_h1": False,
            "has_h1": False,
            "default_export": False,
            "named_export_no_default": False,
            "in_pages_folder": False,
        }

        section_score = 0
        page_score = 0

        # Signal 1: Sibling route entry (strong: +2 section, -1 page)
        if self._has_sibling_route_entry(file_path, facts):
            signals["has_sibling_route"] = True
            section_score += 2
            page_score = max(0, page_score - 1)

        # Signal 1b: This file IS a route entry (+2 page)
        if self._is_route_entry_file(file_path):
            signals["is_route_entry"] = True
            page_score += 2

        # Signal 2: Heading structure
        heading_signals = self._extract_heading_signals(content)
        if heading_signals["has_h2_to_h6"] and not heading_signals["has_h1"]:
            signals["has_h2_no_h1"] = True
            section_score += 1
        if h1_count > 0 or heading_signals["has_h1"]:
            signals["has_h1"] = True
            page_score += 2

        # Signal 3: Export pattern
        export_signals = self._extract_export_signals(content)
        if export_signals["has_named_export"] and not export_signals["has_default_export"]:
            signals["named_export_no_default"] = True
            section_score += 1
        if export_signals["has_default_export"]:
            signals["default_export"] = True
            page_score += 1

        # Signal 4: Page folder location
        if self._is_page_like(file_path):
            signals["in_pages_folder"] = True
            page_score += 1

        return {
            "section_score": section_score,
            "page_score": page_score,
            "signals": signals,
            "heading_signals": heading_signals,
            "export_signals": export_signals,
        }

    def _calculate_confidence(self, page_score: int, section_score: int, has_h1: bool) -> float:
        """Calculate dynamic confidence based on signal strength."""
        base_confidence = 0.70
        page_boost = min(page_score * 0.08, 0.15)
        section_penalty = min(section_score * 0.03, 0.08)

        confidence = base_confidence + page_boost - section_penalty
        return min(0.95, max(0.60, confidence))

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        if self._is_utility_or_hook_file(file_path):
            return []

        text = content or ""
        if self._is_non_indexable_template(file_path) or self._is_inertia_shell_template(file_path, text):
            return []

        if not self._is_page_like(file_path) and not self._looks_like_render_module(file_path, text):
            return []

        if self._looks_like_child_composition(file_path, text):
            return []

        h1_count = len(list(self._H1.finditer(text)))

        if h1_count > 1:
            return [
                self.create_finding(
                    title="Page heading structure should contain exactly one H1",
                    context=f"{file_path}:h1-count={h1_count}",
                    file=file_path,
                    line_start=1,
                    description=f"Detected {h1_count} `<h1>` tags in this page module.",
                    why_it_matters="A clear single H1 helps content hierarchy for users and search indexing.",
                    suggested_fix="Ensure each indexable page has one primary `<h1>` and move secondary headings to `<h2+>`.",
                    confidence=0.86,
                    tags=["seo", "headings", "content-structure"],
                    evidence_signals=["indexability_conflict_signal=h1_multiple"],
                    metadata={
                        "decision_profile": {"indexability_conflict_signal": "h1_multiple"},
                        "classification": {
                            "h1_count": h1_count,
                            "reason": "multiple_h1_hard_rule",
                        },
                    },
                ),
            ]

        if h1_count == 1:
            return []

        # h1_count == 0: Apply multi-signal classification
        segments = self._get_path_segments(file_path)
        if self._LAYOUT_TITLE.search(text):
            return []
        if self._has_heading_proxy(text):
            return []
        if any(marker in segments for marker in self._NON_INDEXABLE_PATH):
            return []

        # Multi-signal classification
        classification = self._classify_file_type(file_path, text, facts, h1_count)
        section_score = classification["section_score"]
        page_score = classification["page_score"]
        signals = classification["signals"]
        heading_signals = classification["heading_signals"]

        if not heading_signals["has_h1"] and not heading_signals["has_h2_to_h6"]:
            return []

        should_skip = section_score >= 2 and section_score > page_score
        if should_skip:
            return []

        confidence = self._calculate_confidence(page_score, section_score, False)
        decision = "skipped" if should_skip else "enforced"
        classification_meta = {
            "section_score": section_score,
            "page_score": page_score,
            "signals": {k: v for k, v in signals.items() if v},
            "h1_count": h1_count,
            "decision": decision,
            "confidence": round(confidence, 2),
        }

        return [
            self.create_finding(
                title="Page heading structure should contain exactly one H1",
                context=f"{file_path}:h1-count={h1_count}",
                file=file_path,
                line_start=1,
                description=f"Detected {h1_count} `<h1>` tags in this page module.",
                why_it_matters="A clear single H1 helps content hierarchy for users and search indexing.",
                suggested_fix="Ensure each indexable page has one primary `<h1>` and move secondary headings to `<h2+>`.",
                confidence=confidence,
                tags=["seo", "headings", "content-structure"],
                evidence_signals=["indexability_conflict_signal=h1_missing"],
                metadata={
                    "decision_profile": {"indexability_conflict_signal": "h1_missing"},
                    "classification": classification_meta,
                },
            ),
        ]


class PageIndexabilityConflictRule(_SeoRuleBase):
    id = "page-indexability-conflict"
    name = "Page Indexability Conflict"
    description = "Detects conflicting indexability metadata signals on the same page"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK

    _INDEX_HINT = re.compile(r"(pricing|features|blog|docs|about|contact|product)", re.IGNORECASE)
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Refactor the component code to remove the page indexability conflict pattern while preserving the public UI behavior. Prefer explicit state, props, and lifecycle boundaries over implicit side effects.'
    examples = {}
    priority = 2
    group = 'Data Access'
    applies_to = ['react-component', 'page']
    references = []
    related_rules = []
    false_positive_notes = ''
    detection_type = 'regex'
    analysis_cost = 'low'
    auto_fixable = False
    tags = {'domain': 'react', 'type': 'quality', 'concern': 'page-indexability-conflict'}

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path):
            return []
        text = content or ""
        if not self._is_page_like(file_path):
            return []

        robots = self._ROBOTS.search(text)
        canonical = self._CANONICAL.search(text)
        if not robots or not canonical:
            return []

        robots_value = str(robots.group("value") or "").lower()
        if "noindex" not in robots_value and "none" not in robots_value:
            return []

        file_hint = self._INDEX_HINT.search((file_path or "").replace("\\", "/"))
        if not (self._project_is_public_surface(facts) or file_hint):
            return []

        line = self._line_for_offset(text, robots.start())
        return [
            self.create_finding(
                title="Page metadata has indexability conflict",
                context=f"{file_path}:{line}:indexability-conflict",
                file=file_path,
                line_start=line,
                description="Robots directive de-indexes the page while canonical suggests a preferred index target.",
                why_it_matters="Conflicting indexability metadata can produce unstable or unintended search visibility.",
                suggested_fix="Align robots and canonical intent. Public canonical pages should usually not be `noindex`.",
                confidence=0.93,
                tags=["seo", "indexing", "canonical", "robots"],
                evidence_signals=["indexability_conflict_signal=robots_noindex_with_canonical"],
                metadata={
                    "overlap_group": "seo-indexability",
                    "overlap_rank": 100,
                    "overlap_scope": file_path,
                    "decision_profile": {"indexability_conflict_signal": "robots_noindex_with_canonical"},
                },
            ),
        ]
