"""
Laravel Error Pages Missing Rule

Checks for existence of 4xx/5xx error pages (Blade or Inertia pages).
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class ErrorPagesMissingRule(Rule):
    id = "error-pages-missing"
    name = "Missing Laravel Error Pages"
    description = "Detects missing 4xx/5xx error pages in Blade or Inertia error surfaces"
    category = Category.LARAVEL_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_livewire",
    ]
    severity_weight = 0
    confidence = 'medium'
    fix_suggestion = 'Move the missing laravel error pages responsibility into the appropriate service, action, repository, or boundary object. Keep controllers and UI components focused on orchestration only.'
    examples = {}
    priority = 3
    group = 'Architecture Integrity'
    applies_to = ['global']
    references = []
    related_rules = []
    false_positive_notes = 'React SPA projects with a React Router catch-all NotFound route are accepted as handling user-facing 404s outside Blade.'
    detection_type = 'cross-file'
    analysis_cost = 'high'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'architecture', 'concern': 'error-pages'}

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._should_skip_for_api_only(facts):
            return []

        file_map = {
            str(path or "").replace("\\", "/").lower(): str(path or "").replace("\\", "/")
            for path in (facts.files or [])
        }
        files = set(file_map)
        if not files:
            return []
        if self._has_spa_not_found_route(files, facts, file_map):
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
                    file="",
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
                        },
                    },
                ),
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
                    file="",
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
                ),
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
        if any(candidate in files for candidate in candidates):
            return True
        return any(
            path.endswith(f"/{normalized}.blade.php")
            or path.endswith(f"/{normalized}/index.blade.php")
            for path in files
        )

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
        if any(candidate in files for candidate in generic_candidates):
            return True
        extensions = (".tsx", ".jsx", ".ts", ".js")
        stems = {normalized, f"error{normalized}", f"error-{normalized}"}
        for path in files:
            if not path.endswith(extensions):
                continue
            filename = PurePosixPath(path).stem.lower()
            parent = PurePosixPath(path).parent.name.lower()
            if filename in stems or (filename == "index" and parent in stems | {"errors"}):
                return True
        return False

    def _has_spa_not_found_route(
        self,
        files: set[str],
        facts: Facts,
        file_map: dict[str, str],
    ) -> bool:
        not_found_symbols = self._not_found_component_symbols(files)
        if not not_found_symbols:
            return False

        for rel_path in sorted(files):
            if not self._is_js_module(rel_path):
                continue
            text = self._read_project_file(facts, file_map.get(rel_path, rel_path))
            if not text:
                continue
            if not self._has_catch_all_route(text):
                continue
            low_text = text.lower()
            if any(symbol.lower() in low_text for symbol in not_found_symbols):
                return True
        return False

    def _not_found_component_symbols(self, files: set[str]) -> set[str]:
        symbols: set[str] = set()
        for rel_path in files:
            if not self._is_js_module(rel_path):
                continue
            stem = PurePosixPath(rel_path).stem
            compact = re.sub(r"[^a-z0-9]", "", stem.lower())
            if compact not in {"404", "notfound", "notfoundpage", "error404", "fourohfour"}:
                continue
            pascal = "".join(part[:1].upper() + part[1:] for part in re.split(r"[^A-Za-z0-9]+", stem) if part)
            if pascal:
                symbols.add(pascal)
            symbols.add(stem)
        return symbols

    def _has_catch_all_route(self, text: str) -> bool:
        return bool(
            re.search(r"\bpath\s*=\s*['\"]\*['\"]", text or "")
            or re.search(r"\bpath\s*:\s*['\"]\*['\"]", text or ""),
        )

    def _is_js_module(self, rel_path: str) -> bool:
        low = str(rel_path or "").lower()
        return low.endswith((".js", ".jsx", ".ts", ".tsx"))

    def _read_project_file(self, facts: Facts, rel_path: str) -> str:
        from pathlib import Path

        project_path = getattr(facts, "project_path", None)
        if not project_path:
            return ""
        try:
            base = Path(str(project_path)).resolve()
            path = (base / rel_path).resolve()
            if not path.is_relative_to(base):
                return ""
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

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
            getattr(context, "project_type", None) or getattr(context, "project_business_context", "unknown"),
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
