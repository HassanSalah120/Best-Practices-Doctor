"""
Model Cross-Model Query Rule.

Detects model methods that directly query a different model via query builder
entrypoints such as `OtherModel::query()` / `OtherModel::where(...)`.
"""

from __future__ import annotations

from collections import defaultdict

from schemas.facts import ClassInfo, Facts, MethodInfo, QueryUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule
from core.project_recommendations import recommendation_context_tags


class ModelCrossModelQueryRule(Rule):
    id = "model-cross-model-query"
    name = "Cross-Model Query Inside Model"
    description = "Detects direct queries to another model from within model methods"
    category = Category.ARCHITECTURE
    default_severity = Severity.LOW
    default_classification = FindingClassification.ADVISORY
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _RELATION_CALL_MARKERS = (
        "belongsto(",
        "hasone(",
        "hasmany(",
        "morphto(",
        "morphmany(",
        "morphedbymany(",
        "belongstomany(",
        "hasonethrough(",
        "hasmanythrough(",
    )
    _QUERY_CHAIN_MARKERS = (
        "query",
        "where",
        "first",
        "get",
        "count",
        "exists",
        "create",
        "update",
        "delete",
        "paginate",
        "pluck",
        "find",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        models_by_file: dict[str, list[ClassInfo]] = defaultdict(list)
        for model in facts.models:
            models_by_file[str(model.file_path or "")].append(model)
        if not models_by_file:
            return []

        methods_by_file_and_name: dict[tuple[str, str], list[MethodInfo]] = defaultdict(list)
        for method in facts.methods:
            methods_by_file_and_name[(str(method.file_path or ""), str(method.name or ""))].append(method)

        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 3) or 3))
        findings: list[Finding] = []
        per_file_count: dict[str, int] = defaultdict(int)
        seen_keys: set[tuple[str, str, str, str]] = set()

        for query in facts.queries:
            file_path = str(query.file_path or "")
            if file_path not in models_by_file:
                continue
            if per_file_count[file_path] >= max_findings_per_file:
                continue

            owner_model, owner_method = self._resolve_owner(file_path, query, models_by_file, methods_by_file_and_name)
            if owner_model is None:
                continue

            owner_name = self._short_name(owner_model.name or owner_model.fqcn)
            target_name = self._short_name(query.model)
            if not target_name:
                continue
            if target_name.lower() == owner_name.lower():
                continue

            if owner_method and self._is_relation_declaration(owner_method):
                if not self._looks_like_query_builder_chain(query):
                    continue

            key = (file_path, str(query.method_name or ""), owner_name.lower(), target_name.lower())
            if key in seen_keys:
                continue
            seen_keys.add(key)

            chain = str(getattr(query, "method_chain", "") or "").strip()
            confidence = 0.74
            query_type = str(getattr(query, "query_type", "") or "").strip().lower()
            if query_type in {"insert", "update", "delete"}:
                confidence = 0.82
            elif "query" in chain.lower():
                confidence = 0.79

            cross_model_signal = f"{owner_name}->{target_name}"
            method_name = str(getattr(query, "method_name", "") or "") or "<unknown>"
            decision_profile = {
                "decision": "emit",
                "decision_summary": (
                    f"Model `{owner_name}` directly queries `{target_name}` inside `{method_name}`."
                ),
                "decision_reasons": [
                    f"cross_model_query_signal={cross_model_signal}",
                    f"query_chain={chain or 'unknown'}",
                ],
                "cross_model_query_signal": cross_model_signal,
                "query_type": query_type or "unknown",
            }

            findings.append(
                self.create_finding(
                    title="Model directly queries another model",
                    context=f"{owner_name}::{method_name}",
                    file=file_path,
                    line_start=int(getattr(query, "line_number", 1) or 1),
                    description=(
                        f"Model `{owner_name}` queries `{target_name}` directly via `{chain or 'query chain'}` "
                        f"in method `{method_name}`."
                    ),
                    why_it_matters=(
                        "Cross-model querying inside model methods blurs boundaries and makes model behavior "
                        "harder to reason about, especially as workflows grow."
                    ),
                    suggested_fix=(
                        "1. Move cross-model query orchestration to a Service/Action/Repository layer\n"
                        "2. Keep model methods focused on local model behavior and relationships\n"
                        "3. If this is a relationship, expose it as an Eloquent relation method and query from callers"
                    ),
                    tags=["architecture", "models", "boundaries", *recommendation_context_tags(facts)],
                    confidence=confidence,
                    evidence_signals=[
                        f"cross_model_query_signal={cross_model_signal}",
                        f"query_chain={chain or 'unknown'}",
                    ],
                    metadata={
                        "cross_model_query_signal": cross_model_signal,
                        "decision_profile": decision_profile,
                    },
                )
            )
            per_file_count[file_path] += 1

        return findings

    def _resolve_owner(
        self,
        file_path: str,
        query: QueryUsage,
        models_by_file: dict[str, list[ClassInfo]],
        methods_by_file_and_name: dict[tuple[str, str], list[MethodInfo]],
    ) -> tuple[ClassInfo | None, MethodInfo | None]:
        model_candidates = models_by_file.get(file_path, [])
        if not model_candidates:
            return (None, None)

        method_name = str(getattr(query, "method_name", "") or "")
        if not method_name:
            return (model_candidates[0], None)

        method_candidates = methods_by_file_and_name.get((file_path, method_name), [])
        if not method_candidates:
            return (model_candidates[0], None)

        model_fqcns = {str(model.fqcn or "").strip() for model in model_candidates}
        for method in method_candidates:
            if str(method.class_fqcn or "").strip() in model_fqcns:
                for model in model_candidates:
                    if str(model.fqcn or "").strip() == str(method.class_fqcn or "").strip():
                        return (model, method)

        # Fallback to first model class in the file.
        return (model_candidates[0], method_candidates[0])

    def _is_relation_declaration(self, method: MethodInfo) -> bool:
        calls = [str(call or "").strip().lower().replace(" ", "") for call in (method.call_sites or [])]
        return any(any(marker in call for marker in self._RELATION_CALL_MARKERS) for call in calls)

    def _looks_like_query_builder_chain(self, query: QueryUsage) -> bool:
        chain = str(getattr(query, "method_chain", "") or "").strip().lower()
        if not chain:
            return False
        return any(marker in chain for marker in self._QUERY_CHAIN_MARKERS)

    @staticmethod
    def _short_name(value: str | None) -> str:
        raw = str(value or "").strip().lstrip("\\")
        if not raw:
            return ""
        return raw.split("\\")[-1]
