from __future__ import annotations

import re
from pathlib import Path

from rules.base import Rule
from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class MissingModelObserverRegistrationRule(Rule):
    id = "missing-model-observer-registration"
    name = "Missing Model Observer Registration"
    description = "Detects Laravel Observer classes that are never registered in a ServiceProvider"
    category = Category.ARCHITECTURE
    default_severity = Severity.HIGH
    default_classification = FindingClassification.RISK
    type = "ast"
    severity_weight = 8
    confidence = "medium"
    fix_suggestion = "Register the Observer in a ServiceProvider boot() method: Model::observe(ObserverClass::class). Unregistered Observers silently do nothing."
    examples = {
        "bad": "app/Observers/OrderObserver.php exists, but Order::observe(OrderObserver::class) is absent.",
        "good": "Order::observe(OrderObserver::class);",
    }
    priority = 2
    group = "Architecture Integrity"
    applies_to = ["observer", "provider"]
    references = ["Laravel Eloquent Observers"]
    related_rules = ["observer-heavy-logic"]
    false_positive_notes = "May be intentional if observers are registered dynamically by a package or test bootstrap."
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "architecture", "concern": "observer-registration"}

    _OBSERVER_METHODS = ("created", "updated", "deleted", "saving", "saved", "creating", "deleting")

    def analyze(self, facts: Facts, metrics: dict[str, MethodMetrics] | None = None) -> list[Finding]:
        root = Path(getattr(facts, "project_path", "") or ".")
        observers = self._observer_files(root)
        if not observers:
            return []
        provider_text = self._provider_text(root)
        findings: list[Finding] = []
        for path, class_name, line in observers:
            if self._is_registered(class_name, provider_text):
                continue
            rel = path.relative_to(root).as_posix()
            findings.append(
                self.create_finding(
                    title="Observer class is not registered",
                    file=rel,
                    line_start=line,
                    context=f"observer:{class_name}",
                    description=f"{class_name} defines observer methods, but no ServiceProvider registration was found.",
                    why_it_matters="An unregistered Observer class never receives model lifecycle events, so its side effects silently do nothing.",
                    suggested_fix=self.fix_suggestion,
                    confidence=0.78,
                    tags=["laravel", "observer", "service-provider"],
                    evidence_signals=["observer_class_exists=true", "observer_registration_missing=true"],
                ),
            )
        return findings

    def _observer_files(self, root: Path) -> list[tuple[Path, str, int]]:
        out: list[tuple[Path, str, int]] = []
        base = root / "app" / "Observers"
        if not base.exists():
            return out
        for path in base.rglob("*.php"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if not any(re.search(rf"\bfunction\s+{name}\s*\(", text) for name in self._OBSERVER_METHODS):
                continue
            match = re.search(r"\bclass\s+([A-Za-z0-9_]+)", text)
            if not match:
                continue
            out.append((path, match.group(1), text.count("\n", 0, match.start()) + 1))
        return out

    def _provider_text(self, root: Path) -> str:
        provider_root = root / "app" / "Providers"
        chunks: list[str] = []
        if provider_root.exists():
            for path in provider_root.rglob("*.php"):
                try:
                    chunks.append(path.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    continue
        return "\n".join(chunks)

    def _is_registered(self, class_name: str, provider_text: str) -> bool:
        if not provider_text:
            return False
        escaped = re.escape(class_name)
        return bool(
            re.search(rf"\b{escaped}::class\b", provider_text)
            and (re.search(r"::observe\s*\(", provider_text) or "$observers" in provider_text),
        )
