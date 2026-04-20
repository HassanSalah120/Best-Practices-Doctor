"""
Livewire public property mass-assignment risk rule.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class LivewirePublicPropMassAssignmentRule(Rule):
    id = "livewire-public-prop-mass-assignment"
    name = "Livewire Public Property Mass Assignment Risk"
    description = "Detects mutable public Livewire properties without #[Locked] attribute"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    type = "regex"
    regex_file_extensions = [".php"]

    _LIVEWIRE_CLASS = re.compile(r"extends\s+Component\b|Livewire\\Component", re.IGNORECASE)
    _PUBLIC_PROP = re.compile(
        r"public\s+(?:string|int|array|float|bool|mixed)?\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        re.IGNORECASE,
    )
    _LOCKED_ATTR = re.compile(r"#\[\s*Locked\s*\]", re.IGNORECASE)
    _INTERNAL_SKIP = {"listeners", "rules", "validationattributes"}

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
        if not self._LIVEWIRE_CLASS.search(content or ""):
            return []
        lines = (content or "").splitlines()
        findings: list[Finding] = []
        for idx, line in enumerate(lines, start=1):
            match = self._PUBLIC_PROP.search(line)
            if not match:
                continue
            prop_name = str(match.groupdict().get("name") or "")
            if prop_name.lower() in self._INTERNAL_SKIP:
                continue
            window = "\n".join(lines[max(0, idx - 3):idx])
            if self._LOCKED_ATTR.search(window):
                continue

            findings.append(
                self.create_finding(
                    title="Livewire public property is not locked",
                    context=f"${prop_name}",
                    file=file_path,
                    line_start=idx,
                    description=(
                        f"Detected Livewire public property `${prop_name}` without `#[Locked]` protection."
                    ),
                    why_it_matters=(
                        "Mutable public component properties can be user-controlled and may cause unauthorized state changes."
                    ),
                    suggested_fix="Mark sensitive public properties with `#[Locked]` or make them protected/private.",
                    confidence=0.86,
                    tags=["laravel", "security", "livewire", "mass-assignment"],
                    evidence_signals=["livewire_public_prop_unlocked=true"],
                )
            )
        return findings
