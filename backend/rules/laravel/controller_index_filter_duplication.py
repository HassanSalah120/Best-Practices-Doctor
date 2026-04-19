"""
Controller Index Filter Duplication Rule.

Detects duplicated inline extraction of common index/list filters
across multiple controllers when a shared helper is not used.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Category, Finding, FindingClassification, Severity
from rules.base import Rule
from core.project_recommendations import recommendation_context_tags


@dataclass
class _FilterSignal:
    method: MethodInfo
    signature: str
    signature_human: str
    evidence: list[str]
    filter_keys: list[str]
    inline_filter_count: int
    has_render_response_context: bool


class ControllerIndexFilterDuplicationRule(Rule):
    id = "controller-index-filter-duplication"
    name = "Controller Index Filter Duplication"
    description = "Detects repeated inline index filter extraction in controllers"
    category = Category.ARCHITECTURE
    default_severity = Severity.MEDIUM
    default_classification = FindingClassification.ADVISORY
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    _INDEX_METHOD_NAMES = {"index", "list", "listing", "search", "browse", "results"}
    _HELPER_DELEGATION_MARKERS = (
        "resolveindexfilters(",
        "buildindexfilters(",
        "extractindexfilters(",
        "indexfilters(",
    )
    _FILTER_CALL_PATTERN = re.compile(
        r"(?P<prefix>\$[a-z_][a-z0-9_]*|request\(\)|request)"
        r"->(?P<source>string|input|query|get)\(['\"](?P<key>[a-z0-9_.-]+)['\"]\)",
        re.IGNORECASE,
    )
    _RESPONSE_CONTEXT_MARKERS = (
        "inertia::render(",
        "view(",
        "response()->",
        "json(",
        "return[",
        "redirect()->",
        "back()->",
    )

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        candidates = self._collect_candidates(facts)
        if not candidates:
            return []

        min_confidence = float(self.get_threshold("min_confidence", 0.74) or 0.74)
        max_findings_per_file = max(1, int(self.get_threshold("max_findings_per_file", 2) or 2))
        single_method_min_filters = int(self.get_threshold("single_method_min_filters", 0) or 0)
        min_filter_keys_for_candidate = max(2, int(self.get_threshold("min_filter_keys_for_candidate", 2) or 2))

        grouped: dict[str, list[_FilterSignal]] = defaultdict(list)
        for item in candidates:
            if item.inline_filter_count < min_filter_keys_for_candidate:
                continue
            grouped[item.signature].append(item)

        qualifying_signatures: dict[str, set[str]] = {}
        for signature, items in grouped.items():
            unique_controllers = {
                str(item.method.class_fqcn or item.method.class_name or "").strip()
                or item.method.file_path
                for item in items
            }
            if len(unique_controllers) >= 2:
                qualifying_signatures[signature] = unique_controllers

        findings: list[Finding] = []
        per_file_count: dict[str, int] = defaultdict(int)
        for signal in candidates:
            if signal.inline_filter_count < min_filter_keys_for_candidate:
                continue
            emit_path = ""
            duplicate_count = 0
            if signal.signature in qualifying_signatures:
                emit_path = "duplicate"
                duplicate_count = len(qualifying_signatures[signal.signature])
            elif (
                single_method_min_filters >= 2
                and signal.inline_filter_count >= single_method_min_filters
                and signal.has_render_response_context
            ):
                emit_path = "single_high_cardinality"
                duplicate_count = 1
            else:
                continue

            file_path = signal.method.file_path
            if per_file_count[file_path] >= max_findings_per_file:
                continue

            if emit_path == "duplicate":
                confidence = min(0.93, 0.76 + (0.04 * max(0, duplicate_count - 2)))
                decision_summary = (
                    f"Repeated inline index filters detected in {duplicate_count} controllers "
                    f"with signature `{signal.signature_human}`."
                )
                description = (
                    f"Method `{signal.method.name}` repeats inline index filter extraction "
                    f"that also appears in {duplicate_count - 1} other controller(s)."
                )
            else:
                confidence = min(0.91, 0.78 + (0.02 * max(0, signal.inline_filter_count - single_method_min_filters)))
                decision_summary = (
                    f"Inline index filter extraction in `{signal.method.name}` uses "
                    f"{signal.inline_filter_count} keys without helper delegation."
                )
                description = (
                    f"Method `{signal.method.name}` extracts {signal.inline_filter_count} request filters inline. "
                    "Use a shared helper to keep normalization/defaults consistent."
                )

            if confidence < min_confidence:
                continue

            decision_profile = {
                "decision": "emit",
                "decision_summary": decision_summary,
                "decision_reasons": [
                    f"duplicate_filter_signature={signal.signature_human}",
                    f"filter_keys={','.join(signal.filter_keys)}",
                    f"inline_filter_count={signal.inline_filter_count}",
                    f"duplicate_controller_count={duplicate_count}" if emit_path == "duplicate" else "duplicate_controller_count=1",
                    "helper_delegation_absent",
                    f"emit_path={emit_path}",
                ],
                "duplicate_filter_signature": signal.signature_human,
                "duplicate_controller_count": duplicate_count,
                "filter_keys": signal.filter_keys,
                "inline_filter_count": signal.inline_filter_count,
                "emit_path": emit_path,
                "suppression_checks": {
                    "helper_delegation_present": False,
                    "render_response_context_present": signal.has_render_response_context,
                },
            }

            findings.append(
                self.create_finding(
                    title="Repeated inline index filter extraction",
                    context=signal.method.method_fqn,
                    file=file_path,
                    line_start=signal.method.line_start,
                    line_end=signal.method.line_end,
                    description=description,
                    why_it_matters=(
                        "Repeating index filter parsing across controllers drifts quickly and creates subtle "
                        "behavior mismatches. A shared helper keeps list/search behavior consistent."
                    ),
                    suggested_fix=(
                        "1. Extract the common filter parsing into a private helper such as `resolveIndexFilters(Request $request)`\n"
                        "2. Reuse the helper in index-like controller methods\n"
                        "3. Keep normalization/defaults (e.g., status fallback, q trim) in one place"
                    ),
                    tags=[
                        "architecture",
                        "controllers",
                        "dry",
                        "filtering",
                        *recommendation_context_tags(facts),
                    ],
                    confidence=confidence,
                    evidence_signals=[
                        *signal.evidence,
                        f"duplicate_filter_signature={signal.signature_human}",
                        f"filter_keys={','.join(signal.filter_keys)}",
                        f"inline_filter_count={signal.inline_filter_count}",
                        f"duplicate_filter_count={duplicate_count}",
                        f"emit_path={emit_path}",
                    ],
                    metadata={
                        "duplicate_filter_signature": signal.signature_human,
                        "duplicate_filter_signature_key": signal.signature,
                        "filter_keys": signal.filter_keys,
                        "inline_filter_count": signal.inline_filter_count,
                        "emit_path": emit_path,
                        "duplicate_filter_count": duplicate_count,
                        "decision_profile": decision_profile,
                        # Helps downstream overlap handling suppress sibling duplication findings.
                        "overlap_group": "controller-index-filter-duplication",
                        "overlap_scope": f"{file_path}|{signal.signature}",
                        "overlap_rank": 180,
                        "overlap_role": "child",
                        "overlap_with_rule": "dry-violation",
                    },
                )
            )
            per_file_count[file_path] += 1

        return findings

    def _collect_candidates(self, facts: Facts) -> list[_FilterSignal]:
        controller_files = {c.file_path for c in facts.controllers}
        if not controller_files:
            return []

        controller_fqcn_by_file: dict[str, set[str]] = defaultdict(set)
        for controller in facts.controllers:
            controller_fqcn_by_file[controller.file_path].add(str(controller.fqcn or "").strip())

        out: list[_FilterSignal] = []
        for method in facts.methods:
            if method.file_path not in controller_files:
                continue
            if method.class_fqcn and method.class_fqcn not in controller_fqcn_by_file.get(method.file_path, set()):
                continue
            if str(method.name or "").lower() not in self._INDEX_METHOD_NAMES:
                continue

            normalized_calls = [
                self._normalize_call(call) for call in (method.call_sites or []) if str(call or "").strip()
            ]
            if self._has_helper_delegation(normalized_calls):
                continue

            extracted = self._extract_signature(normalized_calls)
            if extracted is None:
                continue
            out.append(
                _FilterSignal(
                    method=method,
                    signature=extracted[0],
                    signature_human=extracted[1],
                    evidence=extracted[2],
                    filter_keys=extracted[3],
                    inline_filter_count=extracted[4],
                    has_render_response_context=self._has_response_render_context(normalized_calls),
                )
            )
        return out

    def _extract_signature(self, calls: list[str]) -> tuple[str, str, list[str], list[str], int] | None:
        by_key: dict[str, dict[str, object]] = {}

        for call in calls:
            for match in self._FILTER_CALL_PATTERN.finditer(call):
                source_name = str(match.group("source") or "").strip().lower()
                key_name = str(match.group("key") or "").strip().lower()
                prefix = str(match.group("prefix") or "").strip().lower()
                if not key_name:
                    continue

                # Keep non-request get() calls out (for precision).
                if source_name == "get" and "request" not in prefix:
                    continue

                state = by_key.setdefault(
                    key_name,
                    {"sources": set(), "trim": False, "value": False},
                )
                sources = state["sources"]
                if isinstance(sources, set):
                    sources.add(source_name)
                state["trim"] = bool(state["trim"]) or ("->trim(" in call)
                state["value"] = bool(state["value"]) or ("->value(" in call)

        if len(by_key) < 2:
            return None

        keys = sorted(by_key.keys())
        signature_parts: list[str] = []
        human_parts: list[str] = []
        for key_name in keys:
            state = by_key[key_name]
            sources_raw = state.get("sources", set())
            sources = sorted(list(sources_raw)) if isinstance(sources_raw, set) else []
            source_key = sources[0] if sources else "unknown"
            has_trim = int(bool(state.get("trim", False)))
            has_value = int(bool(state.get("value", False)))
            signature_parts.append(f"{key_name}:{source_key}:trim={has_trim}:value={has_value}")
            human_parts.append(
                f"{key_name}({source_key}"
                f"{'->trim' if has_trim else ''}"
                f"{'->value' if has_value else ''})"
            )

        signature = "|".join(signature_parts)
        human_signature = " + ".join(human_parts)
        evidence = [
            "index_filter_extraction=inline",
            f"filter_keys={','.join(keys)}",
            f"inline_filter_count={len(keys)}",
        ]
        return (signature, human_signature, evidence, keys, len(keys))

    def _has_helper_delegation(self, calls: list[str]) -> bool:
        for call in calls:
            if any(marker in call for marker in self._HELPER_DELEGATION_MARKERS):
                return True
        return False

    def _has_response_render_context(self, calls: list[str]) -> bool:
        for call in calls:
            if any(marker in call for marker in self._RESPONSE_CONTEXT_MARKERS):
                return True
        return False

    @staticmethod
    def _normalize_call(call: str) -> str:
        return re.sub(r"\s+", "", str(call or "").strip().lower())
