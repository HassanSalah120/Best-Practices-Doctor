"""
Missing Props Type Rule

Detects React components without TypeScript props type definitions.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class MissingPropsTypeRule(Rule):
    id = "missing-props-type"
    name = "Missing Props Type"
    description = "Detects React components without TypeScript props type definitions"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.LOW
    type = "regex"
    regex_file_extensions = [".tsx", ".ts"]

    # Patterns for function components with props
    _COMPONENT_PROPS_PATTERNS = [
        # function Component({ prop1, prop2 })
        re.compile(r"function\s+[A-Z][a-zA-Z0-9]*\s*\(\s*\{[^}]*\}\s*\)", re.IGNORECASE),
        # const Component = ({ prop1, prop2 }) => 
        re.compile(r"const\s+[A-Z][a-zA-Z0-9]*\s*=\s*\(\s*\{[^}]*\}\s*\)\s*=>", re.IGNORECASE),
        # const Component: FC<Props> = ({ ... })
        re.compile(r"const\s+[A-Z][a-zA-Z0-9]*\s*:\s*FC", re.IGNORECASE),
        # const Component: React.FC<Props> = ({ ... })
        re.compile(r"const\s+[A-Z][a-zA-Z0-9]*\s*:\s*React\.FC", re.IGNORECASE),
    ]

    # Patterns that indicate type definition exists
    _TYPE_DEFINED_PATTERNS = [
        # Props type/interface defined
        re.compile(r"(interface|type)\s+[A-Z][a-zA-Z]*Props", re.IGNORECASE),
        # Props inline with FC
        re.compile(r"FC<\s*[A-Z][a-zA-Z]*Props", re.IGNORECASE),
        re.compile(r"React\.FC<\s*[A-Z][a-zA-Z]*Props", re.IGNORECASE),
        # Props destructured with type
        re.compile(r"\(\s*\{\s*[^}]*\}\s*:\s*[A-Z][a-zA-Z]*Props", re.IGNORECASE),
    ]

    # Pattern to extract component name
    _COMPONENT_NAME_PATTERN = re.compile(
        r"(?:function|const)\s+([A-Z][a-zA-Z0-9]*)\s*(?:=|<|\()"
    )

    _ALLOWLIST_PATHS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/node_modules/",
        ".test.tsx",
        ".spec.tsx",
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
        findings: list[Finding] = []

        # Skip allowlisted paths
        norm_path = (file_path or "").replace("\\", "/").lower()
        if any(allow in norm_path for allow in self._ALLOWLIST_PATHS):
            return findings

        # Only check .tsx files (not .js or .jsx)
        if not norm_path.endswith(".tsx") and not norm_path.endswith(".ts"):
            return findings

        text = content or ""

        # Check if this is a React component file
        has_jsx = "return <" in text or "return (" in text
        has_component = any(pattern.search(text) for pattern in self._COMPONENT_PROPS_PATTERNS)

        if not has_component:
            return findings

        # Check if props type is defined
        has_props_type = any(pattern.search(text) for pattern in self._TYPE_DEFINED_PATTERNS)

        if has_props_type:
            return findings

        # Find component names
        component_names = []
        for match in self._COMPONENT_NAME_PATTERN.finditer(text):
            component_names.append(match.group(1))

        if not component_names:
            return findings

        for comp_name in component_names:
            # Check if this component uses destructured props
            props_pattern = re.compile(
                rf"(?:function|const)\s+{comp_name}\s*(?:<[^>]+>)?\s*\(\s*\{{[^}}]*\}}",
                re.IGNORECASE
            )
            if not props_pattern.search(text):
                continue

            findings.append(
                self.create_finding(
                    title="Component missing props type definition",
                    context=f"Component: {comp_name}",
                    file=file_path,
                    line_start=1,
                    description=(
                        f"Component `{comp_name}` uses destructured props without a TypeScript type definition. "
                        "This reduces type safety and IDE support."
                    ),
                    why_it_matters=(
                        "Without props type definitions:\n"
                        "- No IDE autocomplete for props\n"
                        "- No compile-time prop validation\n"
                        "- Props can be any type (loses TypeScript benefits)\n"
                        "- Harder to understand component API\n"
                        "- No prop documentation in code\n"
                        "- Risk of runtime errors from wrong prop types"
                    ),
                    suggested_fix=(
                        "1. Define a Props interface:\n"
                        "   interface ComponentNameProps {\n"
                        "       id: string;\n"
                        "       name: string;\n"
                        "       onClick?: () => void;\n"
                        "   }\n\n"
                        "2. Use the Props type:\n"
                        "   function ComponentName({ id, name }: ComponentNameProps) { ... }\n\n"
                        "3. Or use inline type (for simple components):\n"
                        "   const Component = ({ id, name }: { id: string; name: string }) => ..."
                    ),
                    code_example=(
                        "// Before (no type - loses TypeScript benefits)\n"
                        "function UserCard({ name, email, isActive }) {\n"
                        "    return <div>{name}</div>;\n"
                        "}\n\n"
                        "// After (with Props interface)\n"
                        "interface UserCardProps {\n"
                        "    name: string;\n"
                        "    email: string;\n"
                        "    isActive?: boolean; // Optional\n"
                        "}\n"
                        "\n"
                        "function UserCard({ name, email, isActive = false }: UserCardProps) {\n"
                        "    return <div>{name} ({email})</div>;\n"
                        "}\n\n"
                        "// Alternative: Inline type for simple components\n"
                        "const Button = ({ label, onClick }: { label: string; onClick: () => void }) => (\n"
                        "    <button onClick={onClick}>{label}</button>\n"
                        ");"
                    ),
                    confidence=0.70,
                    tags=["typescript", "react", "props", "type-safety"],
                )
            )

        return findings
