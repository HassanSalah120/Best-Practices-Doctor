"""Context-aware data-object boundary suggestion rule."""

from __future__ import annotations

import re

from rules.base import Rule
from schemas.facts import AssocArrayLiteral, Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class DtoSuggestionRule(Rule):
    """Suggest data objects only for proven cross-object array transfers.

    Array size alone is not architectural evidence. A finding requires an
    established DTO/data-object convention and an AST-observed consumer call
    that moves the array outside the method's local implementation.
    """

    id = "dto-suggestion"
    name = "Data Object Boundary Suggestion"
    description = "Suggests a DTO/data object for large arrays proven to cross object boundaries"
    category = Category.MAINTAINABILITY
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
        "native_php",
        "php_mvc",
    ]
    severity_weight = 0
    confidence = "medium"
    fix_suggestion = (
        "Use the project's existing DTO/data-object pattern at this boundary, preserving framework-native arrays "
        "for views, responses, persistence attributes, and configuration."
    )
    examples = {
        "bad": "$payload = [/* 10+ fields */]; $this->orders->createFromPayload($payload);",
        "good": "$command = CreateOrderData::from($request->validated()); $this->orders->create($command);",
    }
    priority = 4
    group = "Code Quality"
    applies_to = ["controller", "service", "php-class"]
    references = []
    related_rules = []
    false_positive_notes = (
        "Runs only when DTO/data objects are an established project convention and a large array crosses an object boundary."
    )
    detection_type = "cross-file"
    analysis_cost = "medium"
    auto_fixable = False
    tags = {"domain": "laravel", "type": "quality", "concern": "dto-suggestion"}
    context_policy = "adaptive"

    _DATA_OBJECT_NAME = re.compile(r"(?:DTO|Data|Payload|ValueObject|TransferObject)$", re.IGNORECASE)
    _FRAMEWORK_TARGETS = {
        "validate",
        "make",
        "json",
        "view",
        "compact",
        "create",
        "update",
        "insert",
        "insertgetid",
        "insertorignore",
        "updateorinsert",
        "upsert",
        "forcecreate",
        "firstorcreate",
        "firstornew",
        "updateorcreate",
        "render",
        "share",
        "inertia",
        "response",
        "with",
        "config",
        "settings",
        "mapping",
        "fill",
        "collect",
        "merge",
    }

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        convention_enabled, convention_confidence, convention_evidence = self._dto_convention(facts)
        require_convention = bool(self.get_threshold("require_project_convention", True))
        if require_convention and not convention_enabled:
            return []
        min_convention_confidence = float(
            self.get_threshold(
                "min_convention_confidence",
                self.get_threshold("min_confidence", 0.74),
            )
        )
        if require_convention and convention_confidence < min_convention_confidence:
            return []

        min_keys = max(8, int(self.get_threshold("min_keys", 10)))
        max_findings = max(1, int(self.get_threshold("max_findings_per_file", 2)))
        grouped: dict[str, list[tuple[AssocArrayLiteral, str]]] = {}

        for array in getattr(facts, "assoc_arrays", []) or []:
            if int(array.key_count or 0) < min_keys:
                continue
            if self._is_inside_data_object(array):
                continue
            boundary = self._boundary_consumer(array)
            if not boundary:
                continue
            grouped.setdefault(str(array.file_path), []).append((array, boundary))

        findings: list[Finding] = []
        for file_path in sorted(grouped):
            items = sorted(grouped[file_path], key=lambda item: int(item[0].line_number or 0))
            for array, boundary in items[:max_findings]:
                confidence = min(0.94, 0.76 + max(0.0, convention_confidence - 0.6) * 0.3)
                findings.append(
                    self.create_finding(
                        title="Large array crosses a boundary in a data-object-oriented project",
                        context=(
                            f"{array.class_fqcn or file_path}::{array.method_name}:"
                            f"{boundary}:{array.key_count}"
                        ),
                        file=file_path,
                        line_start=int(array.line_number or 1),
                        description=(
                            f"A {array.key_count}-field associative array is passed to `{boundary}`. "
                            "This project already prefers DTO/data-object contracts."
                        ),
                        why_it_matters=(
                            "At an object or layer boundary, an explicit data contract prevents silent key drift and "
                            "makes refactoring safer. Local arrays and framework payloads do not need this treatment."
                        ),
                        suggested_fix=self.fix_suggestion,
                        tags=["maintainability", "dto", "typing", "architecture", "semantic"],
                        confidence=confidence,
                        evidence_signals=[
                            "project_dto_convention=true",
                            f"convention_confidence={convention_confidence:.2f}",
                            f"array_keys={array.key_count}",
                            f"used_as={array.used_as}",
                            f"boundary_consumer={boundary}",
                            *convention_evidence[:4],
                        ],
                    ),
                )
        return findings

    def _dto_convention(self, facts: Facts) -> tuple[bool, float, list[str]]:
        context = getattr(facts, "project_context", None)
        expectations = (
            getattr(context, "backend_team_expectations", None)
            or getattr(context, "team_expectations", None)
            or {}
        )
        payload = expectations.get("dto_data_objects_preferred", {}) if isinstance(expectations, dict) else {}
        if not isinstance(payload, dict):
            return (False, 0.0, [])
        return (
            bool(payload.get("enabled", False)),
            float(payload.get("confidence", 0.0) or 0.0),
            [str(item) for item in (payload.get("evidence", []) or []) if str(item or "")],
        )

    def _is_inside_data_object(self, array: AssocArrayLiteral) -> bool:
        fqcn = str(array.class_fqcn or "").strip("\\")
        class_name = fqcn.rsplit("\\", 1)[-1]
        return bool(class_name and self._DATA_OBJECT_NAME.search(class_name))

    def _boundary_consumer(self, array: AssocArrayLiteral) -> str | None:
        used_as = str(array.used_as or "").lower()
        candidates = [str(item or "").strip() for item in (array.consumer_calls or []) if str(item or "").strip()]
        if used_as == "argument" and array.target:
            candidates.insert(0, str(array.target).strip())
        if used_as not in {"argument", "assignment"}:
            return None
        for candidate in candidates:
            if self._is_boundary_call(candidate):
                return candidate
        return None

    def _is_boundary_call(self, call: str) -> bool:
        normalized = re.sub(r"\s+", "", str(call or "")).lower()
        if not normalized:
            return False
        method = re.split(r"->|::", normalized)[-1]
        if method in self._FRAMEWORK_TARGETS:
            return False
        if normalized.startswith("$this->") and normalized.count("->") == 1:
            # A direct local helper call is not an architectural boundary.
            return False
        if "->" in normalized:
            receiver = normalized.rsplit("->", 1)[0]
            return receiver not in {"$this", "self", "static"}
        if "::" in normalized:
            scope = normalized.rsplit("::", 1)[0]
            return scope not in {"self", "static", "parent", "response", "view", "inertia"}
        return normalized in {"dispatch", "dispatch_sync", "event", "broadcast"}
