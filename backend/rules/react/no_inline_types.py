"""
No Inline Types Rule

Enforces that TypeScript type and interface definitions are extracted to
separate type files, not defined inside UI component files.

Detection strategy:
  PRIMARY   — Tree-sitter AST via facts.react_components.has_inline_type_defs
              (populated by FactsBuilder._parse_react_treesitter)
  FALLBACK  — Regex for files where Tree-sitter was unavailable (parser absent
              or parse error). Regex is deliberately narrower to avoid FPs.
"""
import re
import os
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class NoInlineTypesRule(Rule):
    """
    Detects TypeScript `type` and `interface` definitions inside component files.

    Shared types should live in:
    - A co-located `<ComponentName>.types.ts` file
    - A shared `types/` directory
    - A feature-level `types.ts`
    """

    id = "no-inline-types"
    name = "No Inline Type/Interface Definitions"
    description = "Detects TypeScript types/interfaces defined inside UI component files"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
    # AST path (analyze) is primary; regex path is fallback only.
    type = "ast"
    regex_file_extensions = [".ts", ".tsx"]
    applicable_project_types: list[str] = []

    # ------------------------------------------------------------------ regex fallback
    # Narrow intentionally: require the keyword at column 0 to avoid matching
    # types inside function bodies (generic params, mapped types, etc.)
    _TYPE_DEF_STRICT = re.compile(
        r"^(?:export\s+)?(?:type|interface)\s+([A-Z][a-zA-Z0-9_]*)\s*",
        re.MULTILINE,
    )

    # Files that ARE type-definition files — never flag these
    _TYPE_FILE_MARKERS = (
        "types/", "types\\", ".types.", ".d.ts",
        "/interfaces/", "\\interfaces\\",
        "/models/", "\\models\\", "/schemas/", "\\schemas\\",
    )
    _TYPE_FILENAMES = {"types", "interfaces", "models", "schemas", "dto", "entity", "enums"}
    _TEST_MARKERS = (".test.", ".spec.", "__tests__", ".stories.")

    # ------------------------------------------------------------------ AST path (primary)

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        """Primary analysis — reads AST-extracted flags from facts.react_components."""
        findings: list[Finding] = []
        # De-duplicate per file (multiple components can share the same file-level flags)
        seen_files: set[str] = set()

        for comp in facts.react_components:
            if not comp.has_inline_type_defs:
                continue
            if comp.file_path in seen_files:
                continue
            if self._is_type_file(comp.file_path):
                continue
            seen_files.add(comp.file_path)

            type_names = comp.inline_type_names or []
            # Filter out Props/State interfaces - standard React pattern
            type_names = [n for n in type_names if not (n.endswith("Props") or n.endswith("State"))]
            if not type_names:
                continue
            count = len(type_names)
            names_str = ", ".join(f"`{n}`" for n in type_names[:4])
            if count > 4:
                names_str += f", and {count - 4} more"

            findings.append(
                self.create_finding(
                    title=f"Inline type/interface definition(s) in component file ({count})",
                    context=f"file:{comp.file_path}",
                    file=comp.file_path,
                    line_start=comp.line_start,
                    description=(
                        f"Found {count} type/interface definition(s) in this component file: {names_str}. "
                        "These should be extracted to a dedicated types file."
                    ),
                    why_it_matters=(
                        "Mixing TypeScript types with component rendering logic violates the "
                        "Single Responsibility Principle and Separation of Concerns. "
                        "Extracted type files are easier to reuse, test, and maintain independently."
                    ),
                    suggested_fix=(
                        f"Extract all types to `{self._sibling_types_file(comp.file_path)}` "
                        "or a shared `src/types/` directory.\n"
                        "Then import: `import type { " + (type_names[0] if type_names else "...") + " } from './types';`"
                    ),
                    tags=["react", "typescript", "types", "separation-of-concerns", "srp"],
                    confidence=0.92,
                    evidence_signals=[f"count={count}", f"names={','.join(type_names[:5])}"],
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
        # Skip if AST already produced facts for this file (avoid double-reporting)
        if any(c.file_path == file_path for c in facts.react_components):
            return []
        if self._is_type_file(file_path):
            return []
        if any(m in file_path.lower() for m in self._TEST_MARKERS):
            return []

        type_names = []
        for m in self._TYPE_DEF_STRICT.finditer(content):
            name = m.group(1)
            # Skip React built-in types and Props/State interfaces (standard React pattern)
            if name in {"FC", "ReactNode", "ReactElement"}:
                continue
            if name.endswith("Props") or name.endswith("State"):
                continue
            type_names.append(name)
        if not type_names:
            return []

        count = len(type_names)
        names_str = ", ".join(f"`{n}`" for n in type_names[:4])
        if count > 4:
            names_str += f", and {count - 4} more"

        return [
            self.create_finding(
                title=f"Inline type/interface definition(s) in component file ({count})",
                context=f"file:{file_path}",
                file=file_path,
                line_start=1,
                description=(
                    f"Found {count} type/interface definition(s) in this component file: {names_str}. "
                    "These should be extracted to a dedicated types file."
                ),
                why_it_matters=(
                    "Mixing TypeScript types with component rendering logic violates the "
                    "Single Responsibility Principle and Separation of Concerns."
                ),
                suggested_fix=(
                    f"Extract all types to `{self._sibling_types_file(file_path)}` "
                    "or a shared `src/types/` directory."
                ),
                tags=["react", "typescript", "types", "separation-of-concerns", "srp"],
                confidence=0.78,  # Lower: regex fallback has higher FP risk
            )
        ]

    # ------------------------------------------------------------------ helpers

    def _is_type_file(self, file_path: str) -> bool:
        low = file_path.lower().replace("\\", "/")
        if any(m in low for m in self._TYPE_FILE_MARKERS):
            return True
        basename = os.path.basename(low).split(".")[0]
        return basename in self._TYPE_FILENAMES

    @staticmethod
    def _sibling_types_file(file_path: str) -> str:
        dirname = os.path.dirname(file_path)
        basename = os.path.splitext(os.path.basename(file_path))[0]
        return os.path.join(dirname, f"{basename}.types.ts").replace("\\", "/")
