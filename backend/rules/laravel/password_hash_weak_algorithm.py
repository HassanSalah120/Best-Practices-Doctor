"""
Weak password hashing algorithm rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class PasswordHashWeakAlgorithmRule(Rule):
    id = "password-hash-weak-algorithm"
    name = "Password Hash Uses Weak Algorithm"
    description = "Detects md5/sha1 usage for password hashing flows"
    category = Category.SECURITY
    default_severity = Severity.CRITICAL
    type = "regex"
    regex_file_extensions = [".php"]

    _WEAK_HASH = re.compile(
        r"\b(?P<algo>md5|sha1)\s*\(\s*(?P<arg>[^)]+)\)",
        re.IGNORECASE,
    )
    _PASSWORD_HINT = re.compile(r"(password|pass|pwd)", re.IGNORECASE)

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
        for i, line in enumerate((content or "").splitlines(), start=1):
            match = self._WEAK_HASH.search(line)
            if not match:
                continue
            arg = str(match.groupdict().get("arg") or "")
            if not self._PASSWORD_HINT.search(arg):
                continue
            algo = str(match.groupdict().get("algo") or "").lower()
            findings.append(
                self.create_finding(
                    title="Weak password hashing algorithm detected",
                    context=line.strip()[:90],
                    file=file_path,
                    line_start=i,
                    description=f"Detected `{algo}()` applied to password-like input.",
                    why_it_matters=(
                        "MD5/SHA1 are not suitable for password hashing and are vulnerable to fast offline cracking."
                    ),
                    suggested_fix="Use Laravel `Hash::make()` (bcrypt/argon2) for password storage.",
                    confidence=0.96,
                    tags=["laravel", "security", "password", "hashing"],
                    evidence_signals=[f"weak_hash_algo={algo}", "password_hint_in_argument=true"],
                )
            )
        return findings
