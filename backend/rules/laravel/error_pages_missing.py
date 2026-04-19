"""
Laravel Error Pages Missing Rule

Checks for existence of 4xx/5xx error pages (Blade or Inertia pages).
"""

from __future__ import annotations

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule


class ErrorPagesMissingRule(Rule):
    id = "error-pages-missing"
    name = "Missing Laravel Error Pages"
    description = "Detects missing 4xx/5xx error pages in Blade or Inertia error surfaces"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    applicable_project_types = []

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._should_skip_for_api_only(facts):
            return []

        files = {str(path or "").replace("\\", "/").lower() for path in (facts.files or [])}
        if not files:
            return []
        inertia_mode = self._is_inertia_project(files, facts)

        core_4xx = self._threshold_codes("core_4xx_codes", ["404"])
        core_5xx = self._threshold_codes("core_5xx_codes", ["500"])
        rec_4xx = self._threshold_codes("recommended_4xx_codes", ["403", "419", "429"])
        rec_5xx = self._threshold_codes("recommended_5xx_codes", ["503"])
        flag_recommended = bool(self.get_threshold("flag_recommended", True))
        flag_recommended_inertia = bool(self.get_threshold("flag_recommended_inertia", False))
        min_recommended_missing = max(1, int(self.get_threshold("min_recommended_missing", 2)))

        missing_core_4xx = [code for code in core_4xx if not self._has_error_page(files, code, inertia_mode)]
        missing_core_5xx = [code for code in core_5xx if not self._has_error_page(files, code, inertia_mode)]
        missing_rec_4xx = [code for code in rec_4xx if not self._has_error_page(files, code, inertia_mode)]
        missing_rec_5xx = [code for code in rec_5xx if not self._has_error_page(files, code, inertia_mode)]
        preferred_surface = "inertia" if inertia_mode else "blade"
        surface_context = (
            "resources/js/pages/errors (Inertia) or resources/views/errors"
            if inertia_mode
            else "resources/views/errors"
        )

        findings: list[Finding] = []
        missing_core = missing_core_4xx + missing_core_5xx
        if missing_core:
            severity = Severity.HIGH if missing_core_4xx and missing_core_5xx else Severity.MEDIUM
            findings.append(
                self.create_finding(
                    title="Missing core 4xx/5xx error pages",
                    context=surface_context,
                    file="resources/js/pages/errors" if inertia_mode else "resources/views/errors",
                    line_start=1,
                    description=(
                        "Core Laravel error pages are missing: "
                        f"{', '.join(missing_core)}."
                    ),
                    why_it_matters=(
                        "Missing core error pages can produce inconsistent UX and weak incident messaging "
                        "when user-facing errors occur."
                    ),
                    suggested_fix=(
                        "Add error pages for these HTTP codes "
                        f"({', '.join(missing_core)}). "
                        "For React/Inertia projects, create `resources/js/Pages/Errors/*` "
                        "(or a generic `resources/js/Pages/ErrorPage.tsx`); "
                        "Blade templates in `resources/views/errors/*` are only an alternative."
                    ),
                    severity=severity,
                    confidence=0.92,
                    tags=["laravel", "errors", "ux", "resilience"],
                    evidence_signals=[
                        f"missing_core_4xx={','.join(missing_core_4xx) or 'none'}",
                        f"missing_core_5xx={','.join(missing_core_5xx) or 'none'}",
                        f"preferred_error_surface={preferred_surface}",
                    ],
                    metadata={
                        "decision_profile": {
                            "missing_core_4xx": missing_core_4xx,
                            "missing_core_5xx": missing_core_5xx,
                        }
                    },
                )
            )

        missing_recommended = missing_rec_4xx + missing_rec_5xx
        if (
            flag_recommended
            and not missing_core
            and len(missing_recommended) >= min_recommended_missing
            and (not inertia_mode or flag_recommended_inertia)
        ):
            findings.append(
                self.create_finding(
                    title="Recommended error pages are missing",
                    context=surface_context,
                    file="resources/js/pages/errors" if inertia_mode else "resources/views/errors",
                    line_start=1,
                    description=(
                        "Recommended error pages are missing: "
                        f"{', '.join(missing_recommended)}."
                    ),
                    why_it_matters=(
                        "Providing additional error pages improves user guidance and operational consistency "
                        "for common authorization/session/rate-limit scenarios."
                    ),
                    suggested_fix=(
                        "Consider adding these error pages. "
                        "For React/Inertia, prefer `resources/js/Pages/Errors/*`: "
                        f"{', '.join(missing_recommended)}."
                    ),
                    severity=Severity.LOW,
                    confidence=0.82,
                    tags=["laravel", "errors", "ux"],
                    evidence_signals=[f"missing_recommended={','.join(missing_recommended)}"],
                    metadata={"decision_profile": {"missing_recommended": missing_recommended}},
                )
            )

        return findings

    def _threshold_codes(self, key: str, default: list[str]) -> list[str]:
        raw = self.get_threshold(key, default)
        if isinstance(raw, str):
            values = [v.strip() for v in raw.split(",") if v.strip()]
            return values or default
        if isinstance(raw, list):
            values = [str(v).strip() for v in raw if str(v).strip()]
            return values or default
        return default

    def _has_error_page(self, files: set[str], code: str, inertia_mode: bool) -> bool:
        if self._has_blade_error_page(files, code):
            return True
        if not inertia_mode:
            return False
        return self._has_inertia_error_page(files, code)

    def _has_blade_error_page(self, files: set[str], code: str) -> bool:
        normalized = str(code).strip()
        candidates = {
            f"resources/views/errors/{normalized}.blade.php",
            f"resources/views/errors/{normalized}.php",
            f"resources/views/errors/{normalized}/index.blade.php",
        }
        return any(candidate in files for candidate in candidates)

    def _has_inertia_error_page(self, files: set[str], code: str) -> bool:
        normalized = str(code).strip()
        code_candidates = {
            f"resources/js/pages/errors/{normalized}.tsx",
            f"resources/js/pages/errors/{normalized}.jsx",
            f"resources/js/pages/errors/{normalized}.ts",
            f"resources/js/pages/errors/{normalized}.js",
            f"resources/js/pages/errors/error{normalized}.tsx",
            f"resources/js/pages/errors/error{normalized}.jsx",
            f"resources/js/pages/errors/error{normalized}.ts",
            f"resources/js/pages/errors/error{normalized}.js",
            f"resources/js/pages/errors/error-{normalized}.tsx",
            f"resources/js/pages/errors/error-{normalized}.jsx",
            f"resources/js/pages/errors/error-{normalized}.ts",
            f"resources/js/pages/errors/error-{normalized}.js",
            f"resources/js/pages/errors/{normalized}/index.tsx",
            f"resources/js/pages/errors/{normalized}/index.jsx",
            f"resources/js/pages/errors/{normalized}/index.ts",
            f"resources/js/pages/errors/{normalized}/index.js",
            f"resources/js/components/errors/{normalized}.tsx",
            f"resources/js/components/errors/{normalized}.jsx",
            f"resources/js/components/errors/error{normalized}.tsx",
            f"resources/js/components/errors/error{normalized}.jsx",
            f"resources/js/components/errors/error-{normalized}.tsx",
            f"resources/js/components/errors/error-{normalized}.jsx",
        }
        if any(candidate in files for candidate in code_candidates):
            return True
        generic_candidates = {
            "resources/js/pages/error.tsx",
            "resources/js/pages/error.jsx",
            "resources/js/pages/error.ts",
            "resources/js/pages/error.js",
            "resources/js/pages/errorpage.tsx",
            "resources/js/pages/errorpage.jsx",
            "resources/js/pages/errors/index.tsx",
            "resources/js/pages/errors/index.jsx",
            "resources/js/components/errors/error.tsx",
            "resources/js/components/errors/error.jsx",
            "resources/js/components/errors/errorpage.tsx",
            "resources/js/components/errors/errorpage.jsx",
        }
        return any(candidate in files for candidate in generic_candidates)

    def _is_inertia_project(self, files: set[str], facts: Facts) -> bool:
        context = getattr(facts, "project_context", None)
        if context is not None:
            profile = str(getattr(context, "project_type", "") or "").lower()
            if profile in {"laravel_inertia_react", "laravel_inertia_vue"}:
                return True
        return any(
            marker in files
            for marker in (
                "app/http/middleware/handleinertiarequests.php",
                "resources/js/app.tsx",
                "resources/js/app.jsx",
            )
        ) or any(path.startswith("resources/js/pages/") for path in files)

    def _should_skip_for_api_only(self, facts: Facts) -> bool:
        context = getattr(facts, "project_context", None)
        if context is None:
            return False

        project_type = str(
            getattr(context, "project_type", None) or getattr(context, "project_business_context", "unknown")
        ).lower()
        if project_type != "api_backend":
            return False

        # Keep rule active for mixed public/dashboard projects even if API-first is detected.
        capabilities = (
            getattr(context, "capabilities", None)
            or getattr(context, "backend_capabilities", None)
            or {}
        )
        for cap_key in ("mixed_public_dashboard", "public_marketing_site"):
            payload = capabilities.get(cap_key)
            if isinstance(payload, dict) and bool(payload.get("enabled")):
                return False
        return True
