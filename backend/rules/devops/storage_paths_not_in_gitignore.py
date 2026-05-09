from __future__ import annotations

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

from ._helpers import is_laravel_project, read_project_file


class StoragePathsNotInGitignoreRule(Rule):
    id = "storage-paths-not-in-gitignore"
    name = "Storage Paths Not In Gitignore"
    description = "Detects generated Laravel storage/cache paths missing from .gitignore"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"
    severity_weight = 8
    confidence = "high"
    fix_suggestion = "Add /storage/*.key and /bootstrap/cache/ to .gitignore. These paths contain sensitive generated files that must not be version controlled."
    examples = {"bad": ".gitignore omits /bootstrap/cache/", "good": ".gitignore includes /storage/*.key and /bootstrap/cache/"}
    priority = 1
    group = "DevOps"
    applies_to = ["global"]
    references = ["OWASP A02:2021 - Cryptographic Failures"]
    related_rules = ["env-committed-to-git"]
    false_positive_notes = "Non-Laravel projects may not have all of these paths; this rule is intended for Laravel repositories."
    detection_type = "cross-file"
    analysis_cost = "low"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "security", "concern": "generated-path-gitignore"}

    _REQUIRED = {
        "/storage/*.key": {"storage/*.key", "/storage/*.key"},
        "/bootstrap/cache/": {"bootstrap/cache/", "/bootstrap/cache/", "bootstrap/cache/*", "/bootstrap/cache/*"},
        "/public/storage": {"public/storage", "/public/storage", "public/storage/", "/public/storage/"},
        "/storage/app/public": {"storage/app/public", "/storage/app/public", "storage/app/public/", "/storage/app/public/"},
    }

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        if not is_laravel_project(facts):
            return []
        lines = self._normalized_lines(read_project_file(facts, ".gitignore"))
        missing = [required for required, accepted in self._REQUIRED.items() if not (lines & accepted)]
        if not missing:
            return []
        return [
            self.create_finding(
                title="Generated Laravel paths are missing from .gitignore",
                file=".gitignore",
                line_start=1,
                context="project:.gitignore:storage-paths",
                description=f".gitignore is missing required generated/sensitive paths: {', '.join(missing)}.",
                why_it_matters="Generated keys, cached configs, and uploaded user files should not be committed.",
                suggested_fix=self.fix_suggestion,
                confidence=0.93,
                tags=["devops", "gitignore", "storage"],
                evidence_signals=[f"missing_gitignore_paths={','.join(missing)}"],
                metadata={"missing_paths": missing},
            ),
        ]

    def _normalized_lines(self, content: str) -> set[str]:
        out: set[str] = set()
        for line in (content or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("!"):
                continue
            out.add(stripped.rstrip())
        return out
