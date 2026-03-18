"""
No Inline Services Rule

Flags helper functions or service-like utility definitions inside React
component files. Non-hook, non-component logic should live in dedicated
service/utility modules.

Detection strategy:
  PRIMARY   — Tree-sitter AST via facts.react_components.has_inline_helper_fns
              (populated by FactsBuilder._parse_react_treesitter)
  FALLBACK  — Regex for files where Tree-sitter was unavailable. Narrower
              pattern, lower confidence score to reduce false positives.
"""
import re
import os
from pathlib import Path
from core.path_utils import normalize_rel_path
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class NoInlineServicesRule(Rule):
    """
    Detects service/utility function or class definitions inside component files.

    Acceptable in a UI file:
    - React Component functions (PascalCase)
    - Custom hooks (use-prefixed)
    - Inline arrow functions used directly as JSX prop values

    NOT acceptable in a UI file:
    - Named camelCase helper functions
    - Classes that are not React class components
    """

    id = "no-inline-services"
    name = "No Inline Service/Helper Definitions"
    description = "Detects helper functions or service classes defined inside UI component files"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
    # AST path (analyze) is primary; regex path is fallback only.
    type = "ast"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]
    applicable_project_types: list[str] = []

    # ------------------------------------------------------------------ regex fallback
    # Narrow: only match top-level function declarations (not inside other functions).
    # Arrow functions inside JSX event props are excluded by requiring line-start position.
    _HELPER_FN_STRICT = re.compile(
        r"^(?:export\s+)?(?:async\s+)?function\s+([a-z][a-zA-Z0-9_]*)\s*\(",
        re.MULTILINE,
    )
    _ARROW_HELPER_STRICT = re.compile(
        r"^(?:export\s+)?const\s+([a-z][a-zA-Z0-9_]*)\s*=\s*(?:async\s*)?\(",
        re.MULTILINE,
    )

    # Files that are service/utility modules — never flag these
    _SERVICE_FILE_MARKERS = (
        "services/", "services\\", "utils/", "utils\\",
        "helpers/", "helpers\\", "lib/", "lib\\", "api/", "api\\",
    )
    _SERVICE_FILENAMES = (
        "service", "services", "helper", "helpers",
        "util", "utils", "api", "client", "repository",
    )
    _TEST_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")
    _NON_COMPONENT_MARKERS = (
        ".utils.",
        ".helpers.",
        ".hooks.",
        "/hooks/",
        "/utils/",
        "/helpers/",
        "/i18n/",
        "/scripts/",
        "/app/app.tsx",
    )
    _COMPONENT_EXTS = {".tsx", ".jsx"}
    _TRIVIAL_UI_PREFIXES = (
        "handle",
        "on",
        "set",
        "toggle",
        "open",
        "close",
        "reset",
        "focus",
        "blur",
        "submit",
        "select",
        "scroll",
        "show",
        "hide",
        "emit",
        "delete",
        "expand",
        "collapse",
        "activate",
        "deactivate",
    )
    _TRIVIAL_UI_NAMES = {
        "render",
        "cleanup",
        "mount",
        "unmount",
        "next",
        "prev",
        "previous",
        "go",
        "back",
        "forward",
    }
    _PURE_LOCAL_HELPER_PREFIXES = (
        "get",
        "build",
        "format",
        "map",
        "normalize",
        "group",
        "sort",
        "filter",
        "derive",
        "compute",
        "parse",
        "is",
        "has",
        "to",
    )
    _SERVICE_LIKE_PREFIXES = (
        "fetch",
        "load",
        "save",
        "persist",
        "submit",
        "send",
        "sync",
        "request",
        "upload",
        "download",
        "notify",
        "post",
        "put",
        "patch",
        "delete",
        "remove",
        "refresh",
    )
    _SERVICE_LIKE_SUFFIXES = (
        "service",
        "client",
        "repository",
        "request",
        "mutation",
        "query",
        "payload",
    )
    _PAGE_OR_SHELL_PATH_MARKERS = (
        "/pages/",
        "/page/",
        "/screens/",
        "/screen/",
        "/views/",
        "/view/",
        "/routes/",
        "/route/",
    )
    _LOCAL_UI_IMPORT_MARKERS = (
        "./",
        "../",
        "/components/",
        "/component/",
        "/widgets/",
        "/widget/",
        "/modals/",
        "/panels/",
        "/views/",
        "/screens/",
        "@/components",
        "@/widgets",
        "@/pages",
        "@/screens",
        "@/views",
        "@/features",
    )
    _FORM_HANDLER_PREFIXES = (
        "submit",
        "delete",
        "destroy",
        "save",
        "store",
        "create",
        "update",
        "reset",
        "clear",
        "cancel",
        "close",
    )

    # ------------------------------------------------------------------ AST path (primary)

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        """Primary analysis — reads AST-extracted flags from facts.react_components."""
        findings: list[Finding] = []
        seen_files: set[str] = set()

        for comp in facts.react_components:
            if not comp.has_inline_helper_fns:
                continue
            if comp.file_path in seen_files:
                continue
            if self._is_service_file(comp.file_path):
                continue
            if not self._looks_like_component_file(comp.file_path):
                continue
            if self._uses_standard_form_hook(comp, facts) and self._all_helpers_are_form_handlers(comp.inline_helper_names or []):
                continue

            helper_names = self._filter_service_like_helpers(comp.inline_helper_names or [])
            if not helper_names:
                continue
            helper_profile = self._helper_profile(comp, helper_names, facts)
            if helper_profile["suppressed_as_local_glue"]:
                continue

            seen_files.add(comp.file_path)
            count = len(helper_names)
            names_str = ", ".join(f"`{n}`" for n in helper_names[:4])
            if count > 4:
                names_str += f", and {count - 4} more"

            target_dir = self._suggest_target(comp.file_path)

            findings.append(
                self.create_finding(
                    title=f"Inline helper/service definition(s) in component file ({count})",
                    context=f"file:{comp.file_path}",
                    file=comp.file_path,
                    line_start=comp.line_start,
                    description=(
                        f"Found {count} helper function(s) defined in this component file: {names_str}. "
                        "Non-component, non-hook logic should be extracted to a dedicated module."
                    ),
                    why_it_matters=(
                        "Defining service or utility functions inside UI files blurs the boundary "
                        "between presentation and business logic, violating the Single Responsibility "
                        "Principle and making components harder to test in isolation."
                    ),
                    suggested_fix=(
                        f"Move helpers to `{target_dir}` and import them.\n"
                        "If a helper uses React state or effects, convert it to a custom hook "
                        f"(e.g. `use{helper_names[0][0].upper() + helper_names[0][1:]}` if applicable)."
                    ),
                    tags=["react", "srp", "services", "utils", "separation-of-concerns"],
                    confidence=0.90,
                    evidence_signals=helper_profile["evidence_signals"],
                    metadata={"decision_profile": helper_profile},
                )
            )

        return findings

    # ------------------------------------------------------------------ regex fallback path

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        """Fallback: only runs when Tree-sitter was unavailable for this file."""
        # Skip if AST already produced facts for this file
        if any(c.file_path == file_path for c in facts.react_components):
            return []
        if self._is_service_file(file_path):
            return []
        if not self._looks_like_component_file(file_path):
            return []

        # Hooks file (file is named useXxx.ts)
        basename = os.path.basename(file_path).lower()
        if basename.startswith("use"):
            return []
        if any(m in file_path.lower() for m in self._TEST_MARKERS):
            return []

        helper_names: list[str] = []
        for m in self._HELPER_FN_STRICT.finditer(content):
            n = m.group(1)
            if not n.startswith("use") and n not in helper_names:
                helper_names.append(n)
        for m in self._ARROW_HELPER_STRICT.finditer(content):
            n = m.group(1)
            if not n.startswith("use") and n not in helper_names:
                helper_names.append(n)

        helper_names = self._filter_service_like_helpers(helper_names)
        if not helper_names:
            return []
        if "useform(" in content.lower() and self._all_helpers_are_form_handlers(helper_names):
            return []

        count = len(helper_names)
        names_str = ", ".join(f"`{n}`" for n in helper_names[:4])
        if count > 4:
            names_str += f", and {count - 4} more"

        return [
            self.create_finding(
                title=f"Inline helper/service definition(s) in component file ({count})",
                context=f"file:{file_path}",
                file=file_path,
                line_start=1,
                description=(
                    f"Found {count} helper function(s) in this component file: {names_str}. "
                    "Non-component, non-hook logic should be extracted."
                ),
                why_it_matters=(
                    "Defining utility functions inside UI files mixes presentation "
                    "with business logic, violating the Single Responsibility Principle."
                ),
                suggested_fix=(
                    f"Move helpers to `{self._suggest_target(file_path)}` "
                    "or convert them to custom hooks if they use React APIs."
                ),
                tags=["react", "srp", "services", "separation-of-concerns"],
                confidence=0.72,  # Lower: regex fallback has higher FP risk
            )
        ]

    # ------------------------------------------------------------------ helpers

    def _is_service_file(self, file_path: str) -> bool:
        low = file_path.lower().replace("\\", "/")
        if any(m in low for m in self._SERVICE_FILE_MARKERS):
            return True
        base = os.path.basename(low).split(".")[0]
        return any(base.endswith(s) or base.startswith(s) for s in self._SERVICE_FILENAMES)

    def _looks_like_component_file(self, file_path: str) -> bool:
        low = file_path.lower().replace("\\", "/")
        if any(marker in low for marker in self._NON_COMPONENT_MARKERS):
            return False
        basename = os.path.basename(low)
        if basename.startswith("use"):
            return False
        return Path(low).suffix in self._COMPONENT_EXTS

    def _imports_from_utils(self, comp, facts: Facts) -> bool:
        """Check if component imports from utility/hook files (.utils, .hooks, etc.)."""
        for imp in self._component_imports(comp, facts):
            imp_lower = imp.lower().replace("\\", "/")
            # Check for imports from utility files
            if any(marker in imp_lower for marker in [
                ".utils", ".hooks", "/utils/", "/hooks/", 
                "/services/", "/helpers/", "/lib/"
            ]):
                return True
        return False

    def _helper_profile(self, comp, helper_names: list[str], facts: Facts) -> dict[str, object]:
        imports = self._component_imports(comp, facts)
        file_path = str(getattr(comp, "file_path", "") or "").lower().replace("\\", "/")
        imports_from_extracted_modules = self._imports_from_utils(comp, facts)
        helper_count = len(helper_names)
        has_custom_hook_import = any("/hooks/" in str(imp or "").lower().replace("\\", "/") or "/use" in str(imp or "").lower() for imp in imports)
        local_component_imports = sum(
            1
            for imp in imports
            if any(marker in str(imp or "").lower().replace("\\", "/") for marker in self._LOCAL_UI_IMPORT_MARKERS)
        )
        name_low = str(getattr(comp, "name", "") or "").lower()
        shell_like_name = any(token in name_low for token in ("dashboard", "portal", "panel", "modal", "board", "workspace", "shell", "layout"))
        layered_page_or_shell = (
            any(marker in file_path for marker in self._PAGE_OR_SHELL_PATH_MARKERS)
            or ("/components/" in file_path and (local_component_imports >= 2 or shell_like_name))
            or (has_custom_hook_import and local_component_imports >= 2)
        )
        strong_service_helpers = sum(
            1 for name in helper_names if any(name.lower().startswith(prefix) for prefix in self._SERVICE_LIKE_PREFIXES)
        )
        suppressed_as_local_glue = (
            bool(imports)
            and (imports_from_extracted_modules or has_custom_hook_import)
            and layered_page_or_shell
            and helper_count <= 1
            and local_component_imports >= 1
            and strong_service_helpers <= 1
        )

        return {
            "suppressed_as_local_glue": suppressed_as_local_glue,
            "helper_count": helper_count,
            "imports_from_extracted_modules": imports_from_extracted_modules,
            "has_custom_hook_import": has_custom_hook_import,
            "local_component_imports": local_component_imports,
            "layered_page_or_shell": layered_page_or_shell,
            "strong_service_helpers": strong_service_helpers,
            "evidence_signals": [
                f"helpers={helper_count}",
                f"imports_from_utils={int(imports_from_extracted_modules)}",
                f"hooks={int(has_custom_hook_import)}",
                f"local_components={local_component_imports}",
                f"suppressed={int(suppressed_as_local_glue)}",
            ],
        }

    @staticmethod
    def _component_imports(comp, facts: Facts) -> list[str]:
        imports = [str(imp or "") for imp in (getattr(comp, "imports", None) or []) if str(imp or "").strip()]
        if imports:
            return imports

        graph = getattr(facts, "_frontend_symbol_graph", None)
        files_map = graph.get("files", {}) if isinstance(graph, dict) else {}
        payload = files_map.get(normalize_rel_path(str(getattr(comp, "file_path", "") or "")))
        if not isinstance(payload, dict):
            return []
        return [str(imp or "") for imp in (payload.get("imports", []) or []) if str(imp or "").strip()]

    def _uses_standard_form_hook(self, comp, facts: Facts) -> bool:
        hooks_used = [str(h or "").lower() for h in (comp.hooks_used or [])]
        if "useform" in hooks_used:
            return True
        for imp in self._component_imports(comp, facts):
            low = str(imp or "").lower()
            if "useform" in low or "@inertiajs/react" in low:
                return True
        return False

    def _all_helpers_are_form_handlers(self, helper_names: list[str]) -> bool:
        names = [str(name or "").strip().lower() for name in helper_names if str(name or "").strip()]
        if not names:
            return False
        return all(any(name.startswith(prefix) for prefix in self._FORM_HANDLER_PREFIXES) for name in names)

    def _filter_service_like_helpers(self, helper_names: list[str]) -> list[str]:
        return [
            name
            for name in helper_names
            if self._looks_service_like_helper(name) and not self._looks_trivial_ui_helper(name)
        ]

    def _looks_service_like_helper(self, helper_name: str) -> bool:
        low = str(helper_name or "").strip().lower()
        if not low:
            return False
        if any(low.startswith(prefix) for prefix in self._SERVICE_LIKE_PREFIXES):
            return True
        return any(low.endswith(suffix) for suffix in self._SERVICE_LIKE_SUFFIXES)

    def _looks_trivial_ui_helper(self, helper_name: str) -> bool:
        low = str(helper_name or "").strip().lower()
        if not low:
            return True
        if low in self._TRIVIAL_UI_NAMES:
            return True
        if any(low.startswith(prefix) for prefix in self._PURE_LOCAL_HELPER_PREFIXES):
            return True
        return any(low.startswith(prefix) for prefix in self._TRIVIAL_UI_PREFIXES)

    @staticmethod
    def _suggest_target(file_path: str) -> str:
        dirname = os.path.dirname(file_path).replace("\\", "/")
        return f"{dirname}/utils/"
