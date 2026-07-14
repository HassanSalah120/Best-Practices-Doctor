"""
Rule Engine

Orchestrates rule loading, execution, and result collection.
"""
import contextlib
import logging
import os
import pkgutil
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date
from importlib import import_module
from pathlib import Path

from core.context_profiles import (
    ContextProfileMatrix,
    ContextSignalState,
    EffectiveContext,
    load_laravel_context_matrix,
    load_react_context_matrix,
)
from core.path_utils import normalize_rel_path
from core.ruleset import RuleConfig, Ruleset
from core.source_store import SourceFileStore, normalize_extensions
from rules.base import Rule, RuleResult

from core.rule_registry import ALL_RULES, WRAPPED_INTERNAL_RULES


from schemas.facts import Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics

logger = logging.getLogger(__name__)


@dataclass
class EngineResult:
    """Result from running all rules."""
    findings: list[Finding] = field(default_factory=list)
    rules_run: int = 0
    rules_skipped: int = 0
    suppressed_count: int = 0
    deduped_overlap_count: int = 0
    filtered_by_confidence: int = 0
    differential_filtered: int = 0
    execution_time_ms: float = 0.0
    rule_results: dict[str, RuleResult] = field(default_factory=dict)
    analysis_stats: dict[str, object] = field(default_factory=dict)


# Registry of all available rules
LEGACY_RULE_ALIASES: dict[str, str] = {
    "rate-limit-public-forms": "missing-rate-limiting",
    "rate-limit-password-reset": "missing-rate-limiting",
    "sql-injection-raw-php": "sql-injection-risk",
}

INTERNAL_RULE_WRAPPERS: dict[str, str] = dict(WRAPPED_INTERNAL_RULES)

RULE_ALIASES: dict[str, str] = {
    **WRAPPED_INTERNAL_RULES,
    **LEGACY_RULE_ALIASES,
}


def resolve_rule_alias(rule_id: str) -> str:
    """Resolve legacy/alias ids to canonical runtime ids."""
    current = str(rule_id or "").strip()
    if not current:
        return current
    seen: set[str] = set()
    while current in RULE_ALIASES and current not in seen:
        seen.add(current)
        current = RULE_ALIASES[current]
    return current


def _iter_rule_subclasses(base: type[Rule]) -> list[type[Rule]]:
    """Collect every loaded subclass recursively."""
    out: list[type[Rule]] = []
    stack: list[type[Rule]] = list(base.__subclasses__())
    seen: set[type[Rule]] = set()
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        out.append(cls)
        stack.extend(cls.__subclasses__())
    return out


_RULE_DISCOVERY_FAMILIES: tuple[str, ...] = ("rules.laravel", "rules.react", "rules.php")


def _import_discovery_modules() -> list[str]:
    """Import rule modules under known families and return imported module names."""
    imported: list[str] = []
    for family_module in _RULE_DISCOVERY_FAMILIES:
        try:
            family_pkg = import_module(family_module)
        except Exception as exc:
            logger.warning("Rule discovery failed to import %s: %s", family_module, exc)
            continue

        imported.append(family_module)
        for module_info in pkgutil.walk_packages(
            family_pkg.__path__,
            prefix=f"{family_module}.",
        ):
            module_name = str(module_info.name)
            try:
                import_module(module_name)
                imported.append(module_name)
            except Exception as exc:
                logger.warning("Rule discovery skipped module %s: %s", module_name, exc)
    return imported


def discover_rules() -> dict[str, type[Rule]]:
    """Discover rules by importing modules and scanning loaded Rule subclasses."""
    _import_discovery_modules()
    discovered: dict[str, type[Rule]] = {}
    for rule_cls in _iter_rule_subclasses(Rule):
        rule_id = str(getattr(rule_cls, "id", "") or "").strip()
        if not rule_id:
            logger.warning(
                "Rule discovery skipped malformed rule class %s.%s: missing `id`",
                str(getattr(rule_cls, "__module__", "unknown")),
                str(getattr(rule_cls, "__name__", "Rule")),
            )
            continue
        if rule_id == "base-rule":
            continue
        if rule_id in discovered and discovered[rule_id] is not rule_cls:
            logger.warning(
                "Rule discovery duplicate id '%s': keeping %s, skipping %s",
                rule_id,
                discovered[rule_id].__name__,
                rule_cls.__name__,
            )
            continue
        discovered[rule_id] = rule_cls
    return discovered


def get_unaccounted_discovered_rule_ids(
    discovered_registry: dict[str, type[Rule]] | None = None,
    manual_registry: dict[str, type[Rule]] | None = None,
) -> list[str]:
    discovered = set((discovered_registry or DISCOVERED_RULES).keys())
    manual = set((manual_registry or ALL_RULES).keys())
    wrapped = set(WRAPPED_INTERNAL_RULES.keys())
    return sorted(discovered - manual - wrapped)


def build_rule_registry(
    manual_registry: dict[str, type[Rule]] | None = None,
    discovered_registry: dict[str, type[Rule]] | None = None,
) -> dict[str, type[Rule]]:
    """Merge manual registry with discovered rules (manual remains authoritative)."""
    manual = dict(manual_registry or {})
    discovered = dict(discovered_registry or discover_rules())
    merged = dict(manual)

    added = 0
    for rule_id, rule_cls in discovered.items():
        if rule_id in merged:
            continue
        merged[rule_id] = rule_cls
        added += 1

    logger.info(
        "Rule discovery complete: manual=%d discovered=%d merged=%d added=%d",
        len(manual),
        len(discovered),
        len(merged),
        added,
    )
    _validate_rule_registry(merged)
    return merged


def _validate_rule_registry(registry: dict[str, type[Rule]]) -> None:
    """Guard against silent registry corruption from malformed entries."""
    for rule_id, rule_cls in registry.items():
        canonical_id = str(rule_id or "").strip()
        if not canonical_id:
            raise ValueError("Rule registry contains an empty rule id key")
        if not isinstance(rule_cls, type) or not issubclass(rule_cls, Rule):
            raise ValueError(f"Rule registry entry '{canonical_id}' is not a Rule subclass")

        class_rule_id = str(getattr(rule_cls, "id", "") or "").strip()
        if not class_rule_id:
            raise ValueError(f"Rule class {rule_cls.__name__} has no `id`")

        category = getattr(rule_cls, "category", None)
        if isinstance(category, Category):
            pass
        elif isinstance(category, str):
            Category(category)
        else:
            raise ValueError(f"Rule class {rule_cls.__name__} has invalid category")

        severity = getattr(rule_cls, "default_severity", None)
        if isinstance(severity, Severity):
            pass
        elif isinstance(severity, str):
            Severity(severity)
        else:
            raise ValueError(f"Rule class {rule_cls.__name__} has invalid default severity")


DISCOVERED_RULES: dict[str, type[Rule]] = discover_rules()
REGISTERED_RULES: dict[str, type[Rule]] = build_rule_registry(ALL_RULES, DISCOVERED_RULES)
RUNTIME_RULES: dict[str, type[Rule]] = dict(ALL_RULES)
UNACCOUNTED_DISCOVERED_RULE_IDS: list[str] = get_unaccounted_discovered_rule_ids(
    discovered_registry=DISCOVERED_RULES,
    manual_registry=ALL_RULES,
)

for _rule_id in UNACCOUNTED_DISCOVERED_RULE_IDS:
    logger.warning(
        "Rule discovery found non-runtime rule id '%s' without explicit wrapper mapping",
        _rule_id,
    )


class RuleEngine:
    """
    Orchestrates rule execution.

    Loads rules based on ruleset configuration and executes
    them against the Facts/Metrics to produce Findings.
    """

    def __init__(self, ruleset: Ruleset, selected_rules: list[str] | None = None):
        self.ruleset = ruleset
        self.rules: list[Rule] = []
        self.selected_rules = (
            {resolve_rule_alias(rule_id) for rule_id in selected_rules}
            if selected_rules
            else None
        )
        self._context_matrices: dict[str, ContextProfileMatrix] = {}
        with contextlib.suppress(Exception):
            self._context_matrices["laravel"] = load_laravel_context_matrix()
        with contextlib.suppress(Exception):
            self._context_matrices["react"] = load_react_context_matrix()
        self._load_rules()

    def _load_rules(self) -> None:
        """Load and configure rules from the runtime registry (manual source of truth)."""
        for rule_id, rule_class in RUNTIME_RULES.items():

            # If selected_rules is specified, only load those rules
            if self.selected_rules is not None and rule_id not in self.selected_rules:
                continue

            # Get config from ruleset (or use defaults)
            config = self._resolve_rule_config(rule_id)

            if config.enabled:
                try:
                    rule_instance = rule_class(config)
                    rule_instance._base_thresholds = dict(getattr(config, "thresholds", {}) or {})
                    self.rules.append(rule_instance)
                    logger.debug(f"Loaded rule: {rule_id}")
                except Exception as e:
                    logger.warning(f"Failed to load rule {rule_id}: {e}")

    def _resolve_rule_config(self, rule_id: str) -> RuleConfig:
        """Resolve config by canonical id with legacy alias fallback."""
        config = self.ruleset.get_rule_config(rule_id)
        if config.enabled:
            return config

        for alias_id, canonical_id in RULE_ALIASES.items():
            if canonical_id != rule_id:
                continue
            alias_cfg = self.ruleset.get_rule_config(alias_id)
            if alias_cfg.enabled:
                return alias_cfg
        return config

    def run(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
        project_type: str = "",
        cancellation_check: Callable[[], bool] | None = None,
        differential_mode: bool = False,
        changed_files: set[str] | list[str] | tuple[str, ...] | None = None,
        progress_callback: Callable[[float, int, int], None] | None = None,
    ) -> EngineResult:
        """
        Execute all applicable rules against the codebase facts.

        Args:
            facts: Raw facts about the codebase
            metrics: Derived metrics (keyed by method_fqn)
            project_type: Detected project type for filtering
            cancellation_check: Optional callback to check for cancellation

        Returns:
            EngineResult with all findings and execution metadata
        """
        import time

        result = EngineResult()
        start = time.perf_counter()
        self._apply_context_calibration(facts)

        def _overrides(rule: Rule, method_name: str) -> bool:
            method = getattr(rule.__class__, method_name, None)
            base_method = getattr(Rule, method_name, None)
            return method is not None and method is not base_method

        facts_based_rules: list[Rule] = []
        file_based_ast_rules: list[Rule] = []
        process_rules: list[Rule] = []
        regex_rules: list[Rule] = []
        supplemental_regex_rules: list[Rule] = []

        for rule in self.rules:
            rule_type = str(getattr(rule, "type", "ast") or "ast").strip().lower()
            if rule_type == "regex":
                regex_rules.append(rule)
                continue
            if rule_type == "process":
                process_rules.append(rule)
            elif _overrides(rule, "analyze_ast"):
                file_based_ast_rules.append(rule)
            else:
                facts_based_rules.append(rule)

            if _overrides(rule, "analyze_regex"):
                supplemental_regex_rules.append(rule)

        call_once_rules = facts_based_rules + process_rules
        regex_scan_rules = regex_rules + supplemental_regex_rules
        source_store = SourceFileStore(
            str(getattr(facts, "project_path", "") or "."),
            list(getattr(facts, "files", []) or []),
            list(getattr(facts, "test_files", []) or []),
        )
        phase_timings: dict[str, float] = {}
        regex_rule_file_pairs = 0
        ast_rule_file_pairs = 0

        def _run_call_once_rule(rule: Rule) -> tuple[str, RuleResult]:
            """Execute a single analyze()-based rule and return (rule_id, result)."""
            rule_result = rule.run(facts, project_type, metrics)
            return (rule.id, rule_result)

        max_workers = min(8, len(call_once_rules)) if call_once_rules else 1
        total_rules = len(call_once_rules) + len(file_based_ast_rules) + len(regex_scan_rules)
        rules_completed = 0

        call_once_start = time.perf_counter()
        if call_once_rules:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_rule = {
                    executor.submit(_run_call_once_rule, rule): rule
                    for rule in call_once_rules
                }

                # Collect results as they complete
                for future in as_completed(future_to_rule):
                    # Check for cancellation
                    if cancellation_check and cancellation_check():
                        logger.info("Rule engine cancelled")
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                    try:
                        rule_id, rule_result = future.result()
                        result.rule_results[rule_id] = rule_result

                        if rule_result.skipped:
                            result.rules_skipped += 1
                            logger.debug(f"Skipped rule {rule_id}: {rule_result.skip_reason}")
                        else:
                            result.rules_run += 1
                            result.findings.extend(rule_result.findings)
                            logger.debug(
                                f"Rule {rule_id}: {len(rule_result.findings)} findings "
                                f"({rule_result.execution_time_ms:.1f}ms)",
                            )
                    except Exception as e:
                        rule = future_to_rule[future]
                        logger.warning(f"Rule {rule.id} failed: {e}")
                        result.rules_skipped += 1

                    # Update progress
                    rules_completed += 1
                    if progress_callback and total_rules > 0:
                        progress_callback(rules_completed / total_rules, rules_completed, total_rules)
        phase_timings["call_once_rules_ms"] = round((time.perf_counter() - call_once_start) * 1000.0, 3)

        # Regex rules plus supplemental regex passes are lightweight and run directly on file contents.
        regex_start = time.perf_counter()
        if not (cancellation_check and cancellation_check()) and regex_scan_rules:
            import time as _time
            for rule in regex_scan_rules:
                if cancellation_check and cancellation_check():
                    logger.info("Rule engine cancelled")
                    break

                existing_rr = result.rule_results.get(rule.id)
                rr = existing_rr or RuleResult(rule_id=rule.id)
                if not rule.is_applicable(facts, project_type):
                    if existing_rr is None:
                        rr.skipped = True
                        rr.skip_reason = "Disabled" if not rule.enabled else "Not applicable to this project type"
                        result.rule_results[rule.id] = rr
                        result.rules_skipped += 1
                    rules_completed += 1
                    if progress_callback and total_rules > 0:
                        progress_callback(rules_completed / total_rules, rules_completed, total_rules)
                    continue

                t0 = _time.perf_counter()
                findings: list[Finding] = []
                try:
                    allowed_exts = normalize_extensions(
                        getattr(rule, "regex_file_extensions", None),
                        (".php",),
                    )
                    scan_paths = source_store.paths_for_extensions(
                        allowed_exts,
                        include_tests=bool(getattr(rule, "include_test_files", False)),
                    )
                    regex_rule_file_pairs += len(scan_paths)
                    for rel_path in scan_paths:
                        content = source_store.read(rel_path)
                        if not content:
                            continue
                        findings.extend(rule.analyze_regex(rel_path, content, facts, metrics))
                except Exception as e:
                    if existing_rr is None:
                        rr.skipped = True
                        rr.skip_reason = f"Error: {str(e)}"
                    else:
                        logger.warning(f"Supplemental regex pass failed for {rule.id}: {e}")
                finally:
                    rr.execution_time_ms += (_time.perf_counter() - t0) * 1000

                if findings:
                    rr.findings.extend(findings)

                result.rule_results[rule.id] = rr
                if existing_rr is None:
                    if rr.skipped:
                        result.rules_skipped += 1
                        logger.debug(f"Skipped rule {rule.id}: {rr.skip_reason}")
                    else:
                        result.rules_run += 1
                if not rr.skipped:
                    result.findings.extend(findings)
                    logger.debug(
                        f"Rule {rule.id}: {len(findings)} regex finding(s) "
                        f"({rr.execution_time_ms:.1f}ms)",
                    )

                # Update progress after each regex rule
                rules_completed += 1
                if progress_callback and total_rules > 0:
                    progress_callback(rules_completed / total_rules, rules_completed, total_rules)
        phase_timings["regex_rules_ms"] = round((time.perf_counter() - regex_start) * 1000.0, 3)

        # File-based AST rules (analyze_ast) - run on each file
        ast_start = time.perf_counter()
        if not (cancellation_check and cancellation_check()) and file_based_ast_rules:
            import time as _time_ast
            for rule in file_based_ast_rules:
                if cancellation_check and cancellation_check():
                    logger.info("Rule engine cancelled")
                    break

                rr = RuleResult(rule_id=rule.id)
                if not rule.is_applicable(facts, project_type):
                    rr.skipped = True
                    rr.skip_reason = "Disabled" if not rule.enabled else "Not applicable to this project type"
                    result.rule_results[rule.id] = rr
                    result.rules_skipped += 1
                    rules_completed += 1
                    if progress_callback and total_rules > 0:
                        progress_callback(rules_completed / total_rules, rules_completed, total_rules)
                    continue

                t0 = _time_ast.perf_counter()
                try:
                    findings: list[Finding] = []
                    allowed_exts = normalize_extensions(
                        getattr(rule, "regex_file_extensions", None),
                        (".tsx", ".ts", ".jsx", ".js"),
                    )
                    scan_paths = source_store.paths_for_extensions(allowed_exts)
                    ast_rule_file_pairs += len(scan_paths)
                    for rel_path in scan_paths:
                        content = source_store.read(rel_path)
                        if not content:
                            continue
                        findings.extend(rule.analyze_ast(rel_path, content, facts, metrics))
                    rr.findings = findings
                except Exception as e:
                    rr.skipped = True
                    rr.skip_reason = f"Error: {str(e)}"
                finally:
                    rr.execution_time_ms = (_time_ast.perf_counter() - t0) * 1000

                result.rule_results[rule.id] = rr
                if rr.skipped:
                    result.rules_skipped += 1
                    logger.debug(f"Skipped rule {rule.id}: {rr.skip_reason}")
                else:
                    result.rules_run += 1
                    result.findings.extend(rr.findings)
                    logger.debug(
                        f"Rule {rule.id}: {len(rr.findings)} findings "
                        f"({rr.execution_time_ms:.1f}ms)",
                    )

                # Update progress after each AST rule
                rules_completed += 1
                if progress_callback and total_rules > 0:
                    progress_callback(rules_completed / total_rules, rules_completed, total_rules)
        phase_timings["ast_rules_ms"] = round((time.perf_counter() - ast_start) * 1000.0, 3)

        before_conf = len(result.findings)
        result.findings = self._apply_confidence_filter(result.findings)
        result.filtered_by_confidence = max(0, before_conf - len(result.findings))

        before_suppression = len(result.findings)
        result.findings = self._apply_suppressions(result.findings, facts)
        result.suppressed_count = max(0, before_suppression - len(result.findings))

        before_overlap = len(result.findings)
        result.findings = self._apply_overlap_dedupe(result.findings)
        result.deduped_overlap_count = max(0, before_overlap - len(result.findings))

        mode = differential_mode or (os.environ.get("BPD_DIFFERENTIAL_MODE", "").strip() == "1")
        if mode:
            changed = self._resolve_changed_files(changed_files)
            if changed:
                before_diff = len(result.findings)
                result.findings = self._apply_differential_filter(result.findings, changed)
                result.differential_filtered = max(0, before_diff - len(result.findings))

        result.execution_time_ms = (time.perf_counter() - start) * 1000
        slowest_rules = sorted(
            (
                {
                    "rule_id": rule_id,
                    "execution_time_ms": round(float(rule_result.execution_time_ms or 0.0), 3),
                    "findings": len(rule_result.findings or []),
                    "skipped": bool(rule_result.skipped),
                }
                for rule_id, rule_result in result.rule_results.items()
            ),
            key=lambda item: float(item["execution_time_ms"]),
            reverse=True,
        )[:10]
        result.analysis_stats = {
            "phases": phase_timings,
            "source_store": source_store.stats(),
            "regex_rule_file_pairs": regex_rule_file_pairs,
            "ast_rule_file_pairs": ast_rule_file_pairs,
            "slowest_rules": slowest_rules,
        }

        logger.info(
            f"Rule engine complete: {result.rules_run} rules, "
            f"{len(result.findings)} findings, {result.execution_time_ms:.1f}ms",
        )

        return result

    def _apply_context_calibration(self, facts: Facts) -> None:
        if not self._context_matrices:
            return
        laravel_context = self._build_effective_context_from_facts(facts)
        react_context = self._build_react_effective_context_from_facts(facts)
        for rule in self.rules:
            self._reset_rule_runtime_state(rule)
            matrix, effective_context = self._matrix_and_context_for_rule(rule, laravel_context, react_context)
            if matrix is not None and rule.id in matrix.rule_behavior:
                calibration = matrix.calibrate_rule(rule.id, effective_context)
                calibration.setdefault("context_policy", "matrix")
            else:
                calibration = self._generic_context_calibration(rule, effective_context)
            rule._context_calibration = calibration
            rule._runtime_effective_context = effective_context
            if calibration.get("enabled") is False:
                rule.enabled = False
                continue
            severity_raw = str(calibration.get("severity", "") or "").strip().lower()
            if severity_raw:
                with contextlib.suppress(Exception):
                    rule.severity = Severity(severity_raw)
            thresholds = calibration.get("thresholds")
            if isinstance(thresholds, dict) and thresholds:
                merged = dict(getattr(rule.config, "thresholds", {}) or {})
                merged.update({str(k): v for k, v in thresholds.items()})
                rule.config.thresholds = merged

    def _generic_context_calibration(
        self,
        rule: Rule,
        effective_context: EffectiveContext,
    ) -> dict[str, object]:
        """Give matrix-unlisted rules an explicit, conservative context policy.

        Defect/security checks remain context-independent. Architectural
        recommendations are marked adaptive, and convention suggestions are
        suppressed when the discovered architecture provides no evidence that
        the convention is a team standard.
        """
        declared = str(getattr(rule, "context_policy", "auto") or "auto").strip().lower()
        adaptive_categories = {
            Category.ARCHITECTURE,
            Category.DRY,
            Category.LARAVEL_BEST_PRACTICE,
            Category.REACT_BEST_PRACTICE,
            Category.MAINTAINABILITY,
            Category.PERFORMANCE,
        }
        policy = declared
        if policy == "auto":
            policy = "adaptive" if rule.category in adaptive_categories else "independent"

        architecture = str(effective_context.architecture_profile or "unknown").strip().lower()
        signals = [f"generic_policy={policy}", f"architecture_profile={architecture}"]
        enabled = True

        expectation_by_rule = {
            "action-class-suggestion": "services_actions_expected",
            "contract-suggestion": "services_actions_expected",
        }
        expectation_key = expectation_by_rule.get(rule.id)
        if policy == "adaptive" and expectation_key:
            state = (effective_context.team_expectations or {}).get(expectation_key)
            expected = bool(getattr(state, "enabled", False)) if state is not None else False
            layered = architecture in {"layered", "modular", "api-first"}
            enabled = expected or layered
            signals.extend(
                [
                    f"team_expectation={expectation_key}",
                    f"expectation_enabled={int(expected)}",
                ],
            )

        return {
            "enabled": enabled,
            "context_policy": policy,
            "signals": signals,
        }

    def _matrix_and_context_for_rule(
        self,
        rule: Rule,
        laravel_context: EffectiveContext,
        react_context: EffectiveContext,
    ) -> tuple[ContextProfileMatrix | None, EffectiveContext]:
        module_name = str(getattr(rule.__class__, "__module__", "") or "").lower()
        if ".react." in module_name:
            react_matrix = self._context_matrices.get("react")
            if react_matrix is not None and rule.id in react_matrix.rule_behavior:
                return react_matrix, react_context

            # Most mixed Laravel/Inertia React calibration was historically
            # authored in the Laravel business-context matrix. Preserve those
            # project-aware policies until they are migrated, rather than
            # silently discarding them for every React rule.
            laravel_matrix = self._context_matrices.get("laravel")
            if laravel_matrix is not None and rule.id in laravel_matrix.rule_behavior:
                return laravel_matrix, laravel_context
            return react_matrix, react_context
        if ".laravel." in module_name:
            return self._context_matrices.get("laravel"), laravel_context
        return self._context_matrices.get("laravel"), laravel_context

    def _reset_rule_runtime_state(self, rule: Rule) -> None:
        # Reset runtime state before applying context calibration so repeated runs remain deterministic.
        rule.enabled = bool(getattr(rule.config, "enabled", True))
        base_thresholds = getattr(rule, "_base_thresholds", None)
        if isinstance(base_thresholds, dict):
            rule.config.thresholds = dict(base_thresholds)
        if getattr(rule.config, "severity", None):
            try:
                rule.severity = Severity(str(rule.config.severity))
            except Exception:
                rule.severity = rule.default_severity
        else:
            rule.severity = rule.default_severity

    def _build_effective_context_from_facts(self, facts: Facts) -> EffectiveContext:
        project_context = getattr(facts, "project_context", None)
        if project_context is None:
            return EffectiveContext()

        effective = EffectiveContext(
            framework=str(getattr(project_context, "backend_framework", "laravel") or "laravel"),
            project_type=str(
                getattr(project_context, "project_type", None)
                or getattr(project_context, "project_business_context", "unknown")
                or "unknown",
            ),
            project_type_confidence=float(getattr(project_context, "project_business_confidence", 0.0) or 0.0),
            project_type_confidence_kind=str(getattr(project_context, "project_business_confidence_kind", "unknown") or "unknown"),
            project_type_source=str(getattr(project_context, "project_business_source", "default") or "default"),
            architecture_profile=str(
                getattr(project_context, "architecture_style", None)
                or getattr(project_context, "backend_architecture_profile", "unknown")
                or "unknown",
            ),
            architecture_profile_confidence=float(getattr(project_context, "backend_profile_confidence", 0.0) or 0.0),
            architecture_profile_confidence_kind=str(getattr(project_context, "backend_profile_confidence_kind", "unknown") or "unknown"),
            architecture_profile_source=str(getattr(project_context, "backend_profile_source", "default") or "default"),
        )

        capabilities_payload = (
            getattr(project_context, "capabilities", None)
            or getattr(project_context, "backend_capabilities", {})
            or {}
        )
        for key, payload in capabilities_payload.items():
            if not isinstance(payload, dict):
                continue
            effective.capabilities[str(key)] = ContextSignalState(
                enabled=bool(payload.get("enabled", False)),
                confidence=float(payload.get("confidence", 0.0) or 0.0),
                source=str(payload.get("source", "default") or "default"),
                evidence=list(payload.get("evidence", []) or []),
            )

        expectations_payload = (
            getattr(project_context, "team_expectations", None)
            or getattr(project_context, "backend_team_expectations", {})
            or {}
        )
        for key, payload in expectations_payload.items():
            if not isinstance(payload, dict):
                continue
            effective.team_expectations[str(key)] = ContextSignalState(
                enabled=bool(payload.get("enabled", False)),
                confidence=float(payload.get("confidence", 0.0) or 0.0),
                source=str(payload.get("source", "default") or "default"),
                evidence=list(payload.get("evidence", []) or []),
            )
        return effective

    def _build_react_effective_context_from_facts(self, facts: Facts) -> EffectiveContext:
        project_context = getattr(facts, "project_context", None)
        effective = EffectiveContext(
            framework="react",
            project_type="standalone",
            project_type_confidence=0.6,
            project_type_confidence_kind="heuristic",
            project_type_source="detected",
            architecture_profile="component-driven",
            architecture_profile_confidence=0.6,
            architecture_profile_confidence_kind="heuristic",
            architecture_profile_source="detected",
        )

        imports: list[str] = []
        provider_count = 0
        for component in getattr(facts, "react_components", []) or []:
            comp_imports = [str(item or "") for item in (getattr(component, "imports", []) or [])]
            imports.extend(comp_imports)
            if any("provider" in str(item or "").lower() for item in comp_imports) or "provider" in str(
                getattr(component, "name", ""),
            ).lower():
                provider_count += 1

        graph = getattr(facts, "_frontend_symbol_graph", None)
        if isinstance(graph, dict):
            for payload in (graph.get("files", {}) or {}).values():
                if not isinstance(payload, dict):
                    continue
                imports.extend(str(item or "") for item in (payload.get("imports", []) or []))
                if any("provider" in str(item or "").lower() for item in (payload.get("imports", []) or [])):
                    provider_count += 1

        imports_low = [item.lower() for item in imports]
        technical_project_type = str(getattr(facts, "framework_project_type", "") or "").lower()
        if "inertia_react" in technical_project_type or any("@inertiajs" in item for item in imports_low):
            effective.project_type = "inertia_spa"
            effective.project_type_confidence = 0.9
            effective.project_type_confidence_kind = "structural"
        elif "next" in technical_project_type or any("next/router" in item or "next/navigation" in item for item in imports_low):
            effective.project_type = "next_js"
            effective.project_type_confidence = 0.88
            effective.project_type_confidence_kind = "structural"

        has_design_system = any(
            marker in item
            for marker in ("@radix-ui", "@chakra-ui", "@mui", "shadcn", "@/components/ui")
            for item in imports_low
        )
        is_public_facing = False
        route_count = len(getattr(facts, "routes", []) or [])
        if route_count > 0:
            public_count = 0
            private_count = 0
            for route in getattr(facts, "routes", []) or []:
                middleware = " ".join(str(item or "").lower() for item in (getattr(route, "middleware", []) or []))
                if "auth" in middleware:
                    private_count += 1
                else:
                    public_count += 1
            is_public_facing = public_count > 0 and public_count >= private_count

        if route_count == 0:
            route_count = len(
                [
                    p
                    for p in (getattr(facts, "files", []) or [])
                    if "/pages/" in str(p or "").replace("\\", "/").lower()
                    or "/routes/" in str(p or "").replace("\\", "/").lower()
                ],
            )

        typescript_strict = False
        if project_context is not None:
            auto_ctx = dict(getattr(project_context, "auto_detected_context", {}) or {})
            cap_payload = dict(auto_ctx.get("capabilities", {}) or {})
            strict_payload = cap_payload.get("typescript_strict")
            if isinstance(strict_payload, dict):
                typescript_strict = bool(strict_payload.get("enabled", False))

        effective.capabilities["has_design_system"] = ContextSignalState(
            enabled=has_design_system,
            confidence=0.88 if has_design_system else 0.62,
            source="detected",
            evidence=["imports:design-system"],
        )
        effective.capabilities["is_public_facing"] = ContextSignalState(
            enabled=is_public_facing,
            confidence=0.82,
            source="detected",
            evidence=[f"route_count={route_count}"],
        )
        effective.capabilities["typescript_strict"] = ContextSignalState(
            enabled=typescript_strict,
            confidence=0.8 if typescript_strict else 0.6,
            source="detected",
            evidence=[f"typescript_strict={int(typescript_strict)}"],
        )
        effective.capabilities["context_provider_count_high"] = ContextSignalState(
            enabled=provider_count > 5,
            confidence=0.8,
            source="detected",
            evidence=[f"context_provider_count={provider_count}"],
        )
        effective.capabilities["route_count_large"] = ContextSignalState(
            enabled=route_count >= 10,
            confidence=0.84,
            source="detected",
            evidence=[f"route_count={route_count}"],
        )
        return effective

    def _profile_confidence_floor(self) -> float:
        name = str(getattr(self.ruleset, "name", "") or "").strip().lower()
        if name == "startup":
            return 0.65
        if name == "balanced":
            return 0.55
        if name == "strict":
            return 0.45
        return 0.55

    def _confidence_floor_for_rule(self, rule_id: str) -> float:
        cfg = self.ruleset.get_rule_config(rule_id)
        if cfg and isinstance(cfg.thresholds, dict):
            raw = cfg.thresholds.get("min_confidence")
            if raw is not None:
                try:
                    return max(0.0, min(1.0, float(raw)))
                except Exception:
                    pass
        return self._profile_confidence_floor()

    def _has_explicit_confidence_floor(self, rule_id: str) -> bool:
        cfg = self.ruleset.get_rule_config(rule_id)
        return bool(
            cfg
            and isinstance(cfg.thresholds, dict)
            and cfg.thresholds.get("min_confidence") is not None
        )

    def _effective_confidence_floor_for_rule(
        self,
        rule_id: str,
        classification: FindingClassification | str,
    ) -> float:
        floor = self._confidence_floor_for_rule(rule_id)
        if not self._has_explicit_confidence_floor(rule_id):
            floor += self._classification_confidence_adjustment(classification)
        return max(0.0, min(1.0, floor))

    def _apply_confidence_filter(self, findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        for f in findings:
            floor = self._effective_confidence_floor_for_rule(
                f.rule_id,
                getattr(f, "classification", FindingClassification.ADVISORY),
            )
            conf = float(getattr(f, "confidence", 1.0) or 0.0)
            if conf + 1e-9 >= floor:
                out.append(f)
        return out

    def _classification_confidence_adjustment(self, classification: FindingClassification | str) -> float:
        key = classification.value if isinstance(classification, FindingClassification) else str(classification or "").strip().lower()
        profile = str(getattr(self.ruleset, "name", "") or "").strip().lower()
        adjustments = {
            "startup": {"defect": 0.0, "risk": 0.02, "advisory": 0.05},
            "balanced": {"defect": 0.0, "risk": 0.01, "advisory": 0.03},
            "strict": {"defect": 0.0, "risk": 0.0, "advisory": 0.01},
        }
        return float(adjustments.get(profile, adjustments["balanced"]).get(key, 0.0))

    def _apply_suppressions(self, findings: list[Finding], facts: Facts) -> list[Finding]:
        root = Path(getattr(facts, "project_path", "") or ".").resolve()
        cache: dict[str, list[str]] = {}
        out: list[Finding] = []
        for f in findings:
            if self._is_suppressed(f, root, cache):
                continue
            out.append(f)
        return out

    def _apply_overlap_dedupe(self, findings: list[Finding]) -> list[Finding]:
        grouped: dict[tuple[str, str], list[Finding]] = {}
        primary_by_group: dict[tuple[str, str], Finding] = {}

        for finding in findings:
            metadata = getattr(finding, "metadata", {}) or {}
            group = str(metadata.get("overlap_group", "") or "").strip()
            scope = str(metadata.get("overlap_scope", "") or getattr(finding, "context", "") or "").strip()
            if not group or not scope:
                continue
            key = (group, scope)
            grouped.setdefault(key, []).append(finding)

        for key, items in grouped.items():
            if len(items) <= 1:
                continue
            primary = max(items, key=self._overlap_sort_key)
            primary_by_group[key] = self._merge_overlap_metadata(primary, [item for item in items if item is not primary])

        emitted_groups: set[tuple[str, str]] = set()
        out: list[Finding] = []
        for finding in findings:
            metadata = getattr(finding, "metadata", {}) or {}
            group = str(metadata.get("overlap_group", "") or "").strip()
            scope = str(metadata.get("overlap_scope", "") or getattr(finding, "context", "") or "").strip()
            if not group or not scope:
                out.append(finding)
                continue

            key = (group, scope)
            primary = primary_by_group.get(key)
            if primary is None:
                out.append(finding)
                continue
            if key in emitted_groups:
                continue
            emitted_groups.add(key)
            out.append(primary)
        return out

    def _overlap_sort_key(self, finding: Finding) -> tuple[int, int, int, float, int]:
        metadata = getattr(finding, "metadata", {}) or {}
        overlap_rank = int(metadata.get("overlap_rank", 0) or 0)
        classification_rank = {
            FindingClassification.DEFECT: 3,
            FindingClassification.RISK: 2,
            FindingClassification.ADVISORY: 1,
        }.get(getattr(finding, "classification", FindingClassification.ADVISORY), 0)
        severity_rank = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }.get(getattr(finding, "severity", Severity.LOW), 0)
        confidence = float(getattr(finding, "confidence", 0.0) or 0.0)
        score_impact = int(getattr(finding, "score_impact", 0) or 0)
        return (overlap_rank, classification_rank, severity_rank, confidence, score_impact)

    def _merge_overlap_metadata(self, finding: Finding, suppressed: list[Finding]) -> Finding:
        if not suppressed:
            return finding
        suppressed_rule_ids = sorted({item.rule_id for item in suppressed})
        metadata = dict(getattr(finding, "metadata", {}) or {})
        metadata["suppressed_overlap_rules"] = suppressed_rule_ids
        evidence = list(getattr(finding, "evidence_signals", []) or [])
        evidence.append(f"overlap_suppressed={','.join(suppressed_rule_ids)}")
        deduped = list(dict.fromkeys(evidence))
        return finding.model_copy(update={"metadata": metadata, "evidence_signals": deduped})

    def _is_suppressed(self, finding: Finding, root: Path, cache: dict[str, list[str]]) -> bool:
        rel = normalize_rel_path(str(getattr(finding, "file", "") or ""))
        if not rel:
            return False

        if rel in cache:
            lines = cache[rel]
        else:
            try:
                p = (root / rel).resolve()
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                lines = []
            cache[rel] = lines

        if not lines:
            return False

        line_no = int(getattr(finding, "line_start", 1) or 1)
        if line_no < 1:
            line_no = 1

        # Scan same line and up to two previous lines for inline suppression comments.
        for ln in range(max(1, line_no - 2), min(len(lines), line_no) + 1):
            if self._line_has_matching_suppression(lines[ln - 1], finding.rule_id, applies_to_next_line=False):
                return True

        # Scan previous line for next-line suppression.
        prev = line_no - 1
        if prev >= 1 and prev <= len(lines):
            if self._line_has_matching_suppression(lines[prev - 1], finding.rule_id, applies_to_next_line=True):
                return True

        return False

    def _line_has_matching_suppression(self, line: str, rule_id: str, applies_to_next_line: bool) -> bool:
        txt = str(line or "")
        if "@bpd-ignore" not in txt:
            return False

        m = re.search(
            r"@bpd-ignore(?P<next>-next-line)?\s+(?P<rule>[a-z0-9._*\-]+)(?P<rest>.*)$",
            txt,
            flags=re.IGNORECASE,
        )
        if not m:
            return False

        is_next = bool(m.group("next"))
        if applies_to_next_line != is_next:
            return False

        target_rule = (m.group("rule") or "").strip().lower()
        if target_rule not in {"*", rule_id.lower()}:
            return False

        rest = (m.group("rest") or "").strip()
        until_match = re.search(r"\buntil:(\d{4}-\d{2}-\d{2})\b", rest, flags=re.IGNORECASE)
        if until_match:
            try:
                until_date = date.fromisoformat(until_match.group(1))
                if date.today() > until_date:
                    return False
            except Exception:
                return False

        return True

    def _resolve_changed_files(
        self, changed_files: set[str] | list[str] | tuple[str, ...] | None,
    ) -> set[str]:
        if changed_files:
            src = list(changed_files)
        else:
            src = []
            env_raw = os.environ.get("BPD_CHANGED_FILES", "")
            if env_raw:
                src.extend(re.split(r"[\r\n,;]+", env_raw))

            env_file = os.environ.get("BPD_CHANGED_FILES_FILE", "").strip()
            if env_file:
                try:
                    txt = Path(env_file).read_text(encoding="utf-8", errors="replace")
                    src.extend(re.split(r"[\r\n]+", txt))
                except Exception:
                    pass

        out: set[str] = set()
        for p in src:
            s = normalize_rel_path(str(p or "").strip())
            if not s:
                continue
            out.add(s)
        return out

    def _apply_differential_filter(self, findings: list[Finding], changed: set[str]) -> list[Finding]:
        out: list[Finding] = []
        for f in findings:
            main = normalize_rel_path(str(getattr(f, "file", "") or ""))
            if main in changed:
                out.append(f)
                continue

            related = [normalize_rel_path(str(p)) for p in (getattr(f, "related_files", []) or [])]
            if any(p in changed for p in related):
                out.append(f)
                continue
        return out

    def get_rule_ids(self) -> list[str]:
        """Get list of loaded rule IDs."""
        return [r.id for r in self.rules]

    def get_rule(self, rule_id: str) -> Rule | None:
        """Get a specific rule by ID."""
        return next((r for r in self.rules if r.id == rule_id), None)


def create_engine(
    ruleset: Ruleset | None = None,
    ruleset_path: str | None = None,
    selected_rules: list[str] | None = None,
) -> RuleEngine:
    """
    Factory function to create a RuleEngine.

    Args:
        ruleset_path: Optional path to custom ruleset.yaml
        selected_rules: Optional list of rule IDs to run (for advanced profile)

    Returns:
        Configured RuleEngine instance
    """
    if ruleset is None:
        if ruleset_path:
            ruleset = Ruleset.load_default(override_path=ruleset_path)
        else:
            ruleset = Ruleset.load_default()

    return RuleEngine(ruleset, selected_rules=selected_rules)
