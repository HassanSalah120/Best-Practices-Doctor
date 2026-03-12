"""
Insecure Deserialization Rule

Detects unsafe use of unserialize() on untrusted input.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class InsecureDeserializationRule(Rule):
    id = "insecure-deserialization"
    name = "Insecure Deserialization"
    description = "Detects unsafe use of unserialize() on potentially untrusted input"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
        "php_mvc",
        "php_native",
    ]
    regex_file_extensions = [".php"]

    # Patterns for unsafe unserialize
    _UNSERIALIZE_PATTERNS = [
        re.compile(r"\bunserialize\s*\(\s*\$", re.IGNORECASE),  # unserialize($var)
        re.compile(r"\bunserialize\s*\(\s*\$[a-zA-Z_]+\s*\)", re.IGNORECASE),  # unserialize($input)
        re.compile(r"\bunserialize\s*\(\s*\$[a-zA-Z_]+->", re.IGNORECASE),  # unserialize($request->input)
        re.compile(r"\bunserialize\s*\(\s*\$[a-zA-Z_]+\[", re.IGNORECASE),  # unserialize($_GET['x'])
        re.compile(r"\bunserialize\s*\(\s*file_get_contents", re.IGNORECASE),  # unserialize(file_get_contents())
        re.compile(r"\bunserialize\s*\(\s*file\s*\(", re.IGNORECASE),  # unserialize(file())
    ]

    # Patterns for user input sources
    _USER_INPUT_PATTERNS = [
        re.compile(r"\$_GET", re.IGNORECASE),
        re.compile(r"\$_POST", re.IGNORECASE),
        re.compile(r"\$_REQUEST", re.IGNORECASE),
        re.compile(r"\$_COOKIE", re.IGNORECASE),
        re.compile(r"\$request->", re.IGNORECASE),
        re.compile(r"request\s*\(", re.IGNORECASE),
        re.compile(r"input\s*\(", re.IGNORECASE),
        re.compile(r"\$_FILES", re.IGNORECASE),
    ]

    # Safe patterns (allowed_classes)
    _SAFE_PATTERN = re.compile(r"['\"]allowed_classes['\"]\s*=>\s*\[", re.IGNORECASE)

    _ALLOWLIST_PATHS = (
        "tests/",
        "/tests/",
        "test/",
        "/test/",
        "vendor/",
        "/vendor/",
        "database/migrations/",
        "/database/migrations/",
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

        text = content or ""
        lines = text.split("\n")

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            # Check for unserialize pattern
            has_unserialize = any(pattern.search(line) for pattern in self._UNSERIALIZE_PATTERNS)
            if not has_unserialize:
                continue

            # Check if it has safe allowed_classes option
            if self._SAFE_PATTERN.search(line):
                continue

            # Determine risk level based on context
            is_user_input = any(pattern.search(line) for pattern in self._USER_INPUT_PATTERNS)

            context = line.strip()[:80]
            confidence = 0.90 if is_user_input else 0.75

            findings.append(
                self.create_finding(
                    title="Insecure deserialization detected",
                    context=context,
                    file=file_path,
                    line_start=i,
                    description=(
                        f"Detected `unserialize()` on potentially untrusted input. "
                        f"{'This appears to be user input, which is extremely dangerous.' if is_user_input else 'Ensure the input source is trusted.'}"
                    ),
                    why_it_matters=(
                        "Insecure deserialization is a critical security vulnerability:\n"
                        "- OWASP Top 10 #8: Software and Data Integrity Failures\n"
                        "- Can lead to Remote Code Execution (RCE)\n"
                        "- Allows object injection attacks\n"
                        "- Can bypass authentication and authorization\n"
                        "- May enable denial of service attacks"
                    ),
                    suggested_fix=(
                        "1. Use JSON instead of serialized PHP:\n"
                        "   $data = json_decode($input, true);\n\n"
                        "2. If you must use unserialize, restrict allowed classes:\n"
                        "   $data = unserialize($input, ['allowed_classes' => [MyClass::class]]);\n\n"
                        "3. Never unserialize user input directly\n"
                        "4. Validate and sanitize input before any deserialization\n"
                        "5. Consider using Laravel's encrypted serialization for sensitive data"
                    ),
                    code_example=(
                        "// Before (vulnerable)\n"
                        "$data = unserialize($request->input('data'));\n"
                        "$data = unserialize($_GET['payload']);\n\n"
                        "// After (safe - use JSON)\n"
                        "$data = json_decode($request->input('data'), true);\n\n"
                        "// After (safer - with allowed_classes)\n"
                        "$data = unserialize($trustedData, [\n"
                        "    'allowed_classes' => [User::class, Order::class]\n"
                        "]);"
                    ),
                    confidence=confidence,
                    tags=["security", "deserialization", "rce", "owasp-a8", "object-injection"],
                )
            )

        return findings
