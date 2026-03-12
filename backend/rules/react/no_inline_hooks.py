"""
No Inline Hooks Rule

Enforces that custom hooks are defined in separate files, not inside UI component files.
"""
import re
import os
from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule

class NoInlineHooksRule(Rule):
    id = "no-inline-hooks"
    name = "No Inline Hook Definitions"
    description = "Enforces extraction of custom hooks to separate files"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
    type = "regex"
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    # Match top-level function definitions starting with 'use'
    # strict regex to match `function useName` or `const useName =`
    # We want to avoid matching *calls* to hooks, only *definitions*.
    _HOOK_DEF = re.compile(
        r"^(export\s+)?(function\s+use[A-Z][a-zA-Z0-9]*|const\s+use[A-Z][a-zA-Z0-9]*\s*=\s*(\(|async))",
        re.MULTILINE
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        
        # 1. Skip if the file itself is a hook file (starts with `use` or is in a `hooks` dir)
        filename = os.path.basename(file_path).lower()
        if filename.startswith("use"):
            return []
        
        # 2. Skip test files
        if any(x in file_path.lower() for x in [".test.", ".spec.", "__tests__"]):
            return []

        # 3. Check for hook definitions
        for m in self._HOOK_DEF.finditer(content):
            # If we find a hook definition in a non-hook file, flag it.
            # We assume a file is a "UI Component file" if it's not a hook file.
            # Even if it's a utility file, defining a hook there is suspicious if it's not named `use...`.
            
            hook_name = m.group(0).split()[-1].split("(")[0].split("=")[0]
            # Clean up name from regex match
            if "function" in m.group(0):
                 hook_name = m.group(0).split("function")[1].strip().split("(")[0]
            elif "const" in m.group(0):
                 hook_name = m.group(0).split("const")[1].strip().split("=")[0].strip()

            line = content.count("\n", 0, m.start()) + 1
            
            findings.append(
                self.create_finding(
                    title="Inline custom hook definition detected",
                    context=f"{file_path}:{line}:{hook_name}",
                    file=file_path,
                    line_start=line,
                    description=(
                        f"Custom hook `{hook_name}` is defined inside a component file/module. "
                        "Hooks should be extracted to their own files (e.g. `hooks/{hook_name}.ts`)."
                    ),
                    why_it_matters=(
                        "Defining hooks inside UI files mixes concerns (Logic vs Presentation). "
                        "Extracting them improves reusability, testability, and keeps components clean."
                    ),
                    suggested_fix=(
                        f"Move `{hook_name}` to a new file named `{hook_name}.ts` or `{hook_name}.tsx`."
                    ),
                    tags=["react", "hooks", "separation-of-concerns", "structure"],
                    confidence=0.95,
                )
            )

        return findings
