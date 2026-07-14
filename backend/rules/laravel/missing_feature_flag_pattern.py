from __future__ import annotations

import json
import re
from pathlib import Path

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class MissingFeatureFlagPatternRule(Rule):
    id = "missing-feature-flag-pattern"
    name = "Missing Feature Flag Pattern"
    description = "Suggests a feature flag mechanism when the project explicitly expects staged rollout support"
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
    false_positive_notes = "Disabled as an absence-only inference unless project policy or rule configuration explicitly expects feature flags."
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "feature-flags"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        route_count = len(getattr(facts, "routes", []) or []) or self._route_count_from_files(facts)
        if not self._adoption_expected(facts):
            return []
        min_routes = int(self.get_threshold("min_routes", 10) or 10)
        if route_count <= min_routes or self._has_feature_flag_mechanism(facts):
            return []
        root = Path(getattr(facts, "project_path", "") or ".")
        anchor = "composer.json" if (root / "composer.json").exists() else "."
        return [
            self.create_finding(
                title="Larger app has no visible feature flag pattern",
                file=anchor,
                line_start=1,
                context="project:feature-flags",
                description=f"The project has {route_count} route definitions but no visible feature flag mechanism.",
                why_it_matters="Feature flags let teams deploy safely, roll out gradually, and disable risky features without redeploying.",
                suggested_fix=self.fix_suggestion,
                confidence=0.46,
                tags=["laravel", "architecture", "deployment"],
                evidence_signals=[
                    f"route_count={route_count}",
                    "feature_flag_signal=false",
                    "feature_flags_expected=true",
                ],
            ),
        ]

    def _adoption_expected(self, facts: Facts) -> bool:
        if not bool(self.get_threshold("require_explicit_adoption_signal", True)):
            return True
        context = getattr(facts, "project_context", None)
        expectations = (
            getattr(context, "backend_team_expectations", None)
            or getattr(context, "team_expectations", None)
            or {}
        )
        if not isinstance(expectations, dict):
            return False
        payload = expectations.get("feature_flags_expected", {})
        if isinstance(payload, bool):
            return payload
        return bool(isinstance(payload, dict) and payload.get("enabled", False))

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
        route_dirs = [root / "routes"]
        # Check alternative route directories
        for alt in ("src/routes", "app/routes"):
            alt_path = root / alt
            if alt_path.is_dir():
                route_dirs.append(alt_path)
        for rd in route_dirs:
            if not rd.is_dir():
                continue
            try:
                for php_file in rd.rglob("*.php"):
                    text = php_file.read_text(encoding="utf-8", errors="replace")
                    count += len(re.findall(r"\bRoute::(?:get|post|put|patch|delete|apiResource|resource|match|any)\s*\(", text))
            except Exception:
                continue
        return count
