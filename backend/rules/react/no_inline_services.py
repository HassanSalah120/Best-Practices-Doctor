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
            
            # Skip if the component already imports from utility/hook files
            if self._imports_from_utils(comp):
                continue
            
            seen_files.add(comp.file_path)

            helper_names = self._filter_service_like_helpers(comp.inline_helper_names or [])
            if not helper_names:
                continue
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
                    evidence_signals=[f"count={count}", f"names={','.join(helper_names[:5])}"],
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

    def _imports_from_utils(self, comp) -> bool:
        """Check if component imports from utility/hook files (.utils, .hooks, etc.)."""
        for imp in comp.imports or []:
            imp_lower = imp.lower().replace("\\", "/")
            # Check for imports from utility files
            if any(marker in imp_lower for marker in [
                ".utils", ".hooks", "/utils/", "/hooks/", 
                "/services/", "/helpers/", "/lib/"
            ]):
                return True
        return False

    def _filter_service_like_helpers(self, helper_names: list[str]) -> list[str]:
        return [name for name in helper_names if not self._looks_trivial_ui_helper(name)]

    def _looks_trivial_ui_helper(self, helper_name: str) -> bool:
        low = str(helper_name or "").strip().lower()
        if not low:
            return True
        if low in self._TRIVIAL_UI_NAMES:
            return True
        return any(low.startswith(prefix) for prefix in self._TRIVIAL_UI_PREFIXES)

    @staticmethod
    def _suggest_target(file_path: str) -> str:
        dirname = os.path.dirname(file_path).replace("\\", "/")
        return f"{dirname}/utils/"
