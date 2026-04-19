"""
React SEO expansion rules (conservative, project-aware).
"""

from __future__ import annotations

import json
import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Severity, Finding, FindingClassification
from rules.base import Rule


_TEST_PATH_MARKERS = ("/tests/", "/test/", "/__tests__/", "/stories/", "/storybook/", "/fixtures/")
_PAGE_PATH_MARKERS = ("/pages/", "/screens/", "/views/")


class _SeoRuleBase(Rule):
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx", ".html", ".blade.php"]

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def _skip_file(self, file_path: str) -> bool:
        low = (file_path or "").replace("\\", "/").lower()
        return any(marker in low for marker in _TEST_PATH_MARKERS)

    def _is_page_like(self, file_path: str) -> bool:
        low = (file_path or "").replace("\\", "/").lower()
        if low.endswith(".d.ts") or low.endswith(".types.ts") or low.endswith(".types.tsx"):
            return False
        return any(marker in low for marker in _PAGE_PATH_MARKERS)

    def _is_inertia_shell_template(self, file_path: str, content: str) -> bool:
        low = (file_path or "").replace("\\", "/").lower()
        if not low.endswith(".blade.php"):
            return False
        text = content or ""
        return "@inertia" in text or 'id="app"' in text or "id='app'" in text

    def _line_for_offset(self, content: str, offset: int) -> int:
        return (content or "").count("\n", 0, max(0, offset)) + 1

    def _project_is_public_surface(self, facts: Facts) -> bool:
        ctx = getattr(facts, "project_context", None)
        if ctx is None:
            return False
        project_type = str(
            getattr(ctx, "project_type", "")
            or getattr(ctx, "project_business_context", "")
            or ""
        ).strip().lower()
        if project_type in {"public_website_with_dashboard", "portal_based_business_app", "saas_platform"}:
            return True
        capabilities = (
            getattr(ctx, "capabilities", None)
            or getattr(ctx, "backend_capabilities", None)
            or {}
        )
        for key in ("mixed_public_dashboard", "public_marketing_site"):
            payload = capabilities.get(key)
            if isinstance(payload, dict) and bool(payload.get("enabled", False)):
                return True
        return False

    def _explicit_indexability_signal(self, content: str) -> bool:
        text = content or ""
        return bool(
            re.search(r"<(?:Head|Helmet)\b", text)
            or re.search(r"<title\b", text, re.IGNORECASE)
            or re.search(r"document\.title\s*=", text)
            or re.search(r"<meta\s+name=['\"]robots['\"]", text, re.IGNORECASE)
        )


class MetaDescriptionMissingOrGenericRule(_SeoRuleBase):
    id = "meta-description-missing-or-generic"
    name = "Meta Description Missing or Generic"
    description = "Detects missing or generic page-level meta descriptions on indexable/public surfaces"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY

    _META_DESC_PRESENT = re.compile(
        r"<meta[^>]*name\s*=\s*['\"]description['\"][^>]*content\s*=\s*(?:['\"][^'\"]*['\"]|\{[^}]+\})[^>]*>",
        re.IGNORECASE | re.DOTALL,
    )
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

        public_surface = self._project_is_public_surface(facts)
        if not public_surface and not self._explicit_indexability_signal(text):
            return []
        if not self._explicit_indexability_signal(text):
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
                    why_it_matters="Descriptions improve snippet quality and search result clarity for public-facing pages.",
                    suggested_fix="Add a route-specific meta description via `Head`/`Helmet`.",
                    confidence=0.85,
                    tags=["seo", "meta", "react"],
                    evidence_signals=["seo_head_signal_missing=description"],
                    metadata={
                        "overlap_group": "seo-head",
                        "overlap_rank": 60,
                        "overlap_scope": file_path,
                        "decision_profile": {"seo_head_signal_missing": "meta_description"},
                    },
                )
            ]

        literal_match = self._META_DESC_LITERAL.search(text)
        if not literal_match:
            # Dynamic expression content (e.g., content={t('...')}) is present and
            # cannot be quality-scored statically with confidence.
            return []

        value = str(literal_match.group("value") or "").strip().lower()
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
                )
            ]
        return []


class CanonicalMissingOrInvalidRule(_SeoRuleBase):
    id = "canonical-missing-or-invalid"
    name = "Canonical Missing or Invalid"
    description = "Detects missing or malformed canonical metadata on public/indexable pages"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY

    _CANONICAL = re.compile(
        r"<link[^>]*rel=['\"]canonical['\"][^>]*href=['\"](?P<href>[^'\"]+)['\"][^>]*>",
        re.IGNORECASE,
    )

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

        public_surface = self._project_is_public_surface(facts)
        if not public_surface and not self._explicit_indexability_signal(text):
            return []
        if not self._explicit_indexability_signal(text):
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
                    why_it_matters="Canonical URLs help consolidate duplicate routes and avoid split indexing.",
                    suggested_fix="Set a canonical URL in page metadata for indexable public pages.",
                    confidence=0.84,
                    tags=["seo", "canonical"],
                    evidence_signals=["canonical_signal=missing"],
                    metadata={
                        "overlap_group": "seo-indexability",
                        "overlap_rank": 70,
                        "overlap_scope": file_path,
                        "decision_profile": {"canonical_signal": "missing"},
                    },
                )
            ]

        href = str(match.group("href") or "").strip()
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
                )
            ]
        return []


class RobotsDirectiveRiskRule(_SeoRuleBase):
    id = "robots-directive-risk"
    name = "Robots Directive Risk"
    description = "Detects risky robots directives on likely public/indexable pages"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY

    _ROBOTS = re.compile(
        r"<meta[^>]*name=['\"]robots['\"][^>]*content=['\"](?P<value>[^'\"]+)['\"][^>]*>",
        re.IGNORECASE,
    )

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
            )
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
        if not self._JS_NAV_SIGNAL.search(text):
            return []
        if self._ANCHOR_SIGNAL.search(text):
            return []
        if not self._project_is_public_surface(facts):
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
            )
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
                    )
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
                        )
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
    _LAYOUT_TITLE = re.compile(
        r"<(?:AdminLayout|SiteLayout|PortalLayout|DashboardLayout|AppLayout)\b[^>]*\btitle\s*=",
        re.IGNORECASE | re.DOTALL,
    )
    _NON_INDEXABLE_PATH = ("/admin/", "/auth/", "/errors/", "/layouts/", "/components/")

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._skip_file(file_path) or not self._is_page_like(file_path):
            return []
        text = content or ""
        if self._is_inertia_shell_template(file_path, text):
            return []
        h1_count = len(list(self._H1.finditer(text)))
        if h1_count == 1:
            return []

        if h1_count == 0:
            low_path = (file_path or "").replace("\\", "/").lower()
            if self._LAYOUT_TITLE.search(text):
                return []
            if any(marker in low_path for marker in self._NON_INDEXABLE_PATH):
                return []
            if not self._explicit_indexability_signal(text):
                return []
            if not self._project_is_public_surface(facts):
                return []

        signal = "missing" if h1_count == 0 else "multiple"
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
                evidence_signals=[f"indexability_conflict_signal=h1_{signal}"],
                metadata={"decision_profile": {"indexability_conflict_signal": f"h1_{signal}"}},
            )
        ]


class PageIndexabilityConflictRule(_SeoRuleBase):
    id = "page-indexability-conflict"
    name = "Page Indexability Conflict"
    description = "Detects conflicting indexability metadata signals on the same page"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK

    _ROBOTS = re.compile(
        r"<meta[^>]*name=['\"]robots['\"][^>]*content=['\"](?P<value>[^'\"]+)['\"][^>]*>",
        re.IGNORECASE,
    )
    _CANONICAL = re.compile(
        r"<link[^>]*rel=['\"]canonical['\"][^>]*href=['\"](?P<href>[^'\"]+)['\"][^>]*>",
        re.IGNORECASE,
    )
    _INDEX_HINT = re.compile(r"(pricing|features|blog|docs|about|contact|product)", re.IGNORECASE)

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
            )
        ]
