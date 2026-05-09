from __future__ import annotations

import json
import re
from pathlib import Path

from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule


class MissingFeatureFlagPatternRule(Rule):
    id = "missing-feature-flag-pattern"
    name = "Missing Feature Flag Pattern"
    description = "Suggests a feature flag mechanism for larger Laravel apps with many routes"
    category = Category.ARCHITECTURE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    type = "ast"
    severity_weight = 2
    confidence = "low"
    fix_suggestion = "Consider adopting Laravel Pennant for feature flags. Even simple environment-variable flags (FEATURE_NEW_DASHBOARD=false) allow safer deployments and instant rollback without code changes."
    examples = {"good": "laravel/pennant installed, config/features.php exists, or FEATURE_ keys are documented."}
    priority = 4
    group = "Architecture Integrity"
    applies_to = ["global"]
    references = ["Laravel Pennant"]
    related_rules = []
    false_positive_notes = "LOW confidence advisory only. Many teams ship without feature flags successfully. This is a suggestion for teams ready to improve deployment safety."
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "feature-flags"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        route_count = len(getattr(facts, "routes", []) or []) or self._route_count_from_files(facts)
        if route_count <= 10 or self._has_feature_flag_mechanism(facts):
            return []
        return [
            self.create_finding(
                title="Larger app has no visible feature flag pattern",
                file="routes/web.php",
                line_start=1,
                context="project:feature-flags",
                description=f"The project has {route_count} route definitions but no visible feature flag mechanism.",
                why_it_matters="Feature flags let teams deploy safely, roll out gradually, and disable risky features without redeploying.",
                suggested_fix=self.fix_suggestion,
                confidence=0.46,
                tags=["laravel", "architecture", "deployment"],
                evidence_signals=[f"route_count={route_count}", "feature_flag_signal=false"],
            )
        ]

    def _has_feature_flag_mechanism(self, facts: Facts) -> bool:
        root = Path(getattr(facts, "project_path", "") or ".")
        if (root / "config" / "features.php").exists():
            return True
        try:
            composer = json.loads((root / "composer.json").read_text(encoding="utf-8", errors="replace") or "{}")
        except Exception:
            composer = {}
        packages = {}
        if isinstance(composer, dict):
            packages.update(composer.get("require", {}) or {})
            packages.update(composer.get("require-dev", {}) or {})
        if "laravel/pennant" in {str(key).lower() for key in packages}:
            return True
        try:
            env_example = (root / ".env.example").read_text(encoding="utf-8", errors="replace")
        except Exception:
            env_example = ""
        return bool(re.search(r"^FEATURE_[A-Za-z0-9_]+\s*=", env_example, re.M))

    def _route_count_from_files(self, facts: Facts) -> int:
        root = Path(getattr(facts, "project_path", "") or ".")
        count = 0
        for rel in ("routes/web.php", "routes/api.php"):
            try:
                text = (root / rel).read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            count += len(re.findall(r"\bRoute::(?:get|post|put|patch|delete|apiResource|resource|match|any)\s*\(", text))
        return count
