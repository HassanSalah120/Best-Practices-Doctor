"""Missing model factory rule."""
from __future__ import annotations

from pathlib import Path

from schemas.facts import Facts
from schemas.finding import Category, Finding, Severity
from schemas.metrics import MethodMetrics
from rules.base import Rule

class MissingModelFactoryRule(Rule):
    id = "missing-model-factory"
    name = "Missing Model Factory"
    description = "Detects Eloquent models without corresponding Factory classes"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
    type = "ast"
    severity_weight = 5
    confidence = "high"
    fix_suggestion = "Create a factory for every model using php artisan make:factory. Factories are essential for clean test setup."
    examples = {"bad": "class Product extends Model { } // no ProductFactory.php", "good": "class ProductFactory extends Factory { public function definition(): array { ... } }"}
    priority = 3
    group = "Testing"
    applies_to = ["model"]
    references = []
    related_rules = ["tests-missing", "low-coverage-files"]
    false_positive_notes = "Pivot models and abstract base models are skipped because they often do not need factories."
    detection_type = "cross-file"
    analysis_cost = "high"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "testing", "concern": "factories"}

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        files = {self._normalize_path(p) for p in facts.files}
        findings: list[Finding] = []
        for model in facts.models:
            if model.is_abstract or (model.extends or "").endswith("Pivot") or model.name.endswith("Pivot"):
                continue
            expected = f"database/factories/{model.name}Factory.php"
            if expected in files or self._factory_exists(facts.project_path, model.name):
                continue
            findings.append(self.create_finding("Eloquent model is missing a factory", model.file_path, model.line_start or 1, f"Model `{model.name}` does not have `{expected}`.", "Factories keep tests expressive and prevent brittle hand-built model fixtures.", self.fix_suggestion, context=model.fqcn or model.name, confidence=0.9, tags=["laravel", "testing", "factory"]))
        return findings

    @staticmethod
    def _normalize_path(path: str) -> str:
        normalized = str(path or "").replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        return normalized

    @classmethod
    def _factory_exists(cls, project_path: str, model_name: str) -> bool:
        if not project_path:
            return False
        root = Path(project_path)
        expected_name = f"{model_name}Factory.php"
        direct = root / "database" / "factories" / expected_name
        if direct.exists():
            return True
        factories_root = root / "database" / "factories"
        if not factories_root.exists():
            return False
        try:
            return any(path.name == expected_name for path in factories_root.rglob(expected_name))
        except OSError:
            return False
