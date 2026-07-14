"""Global dataflow analysis primitives.

This module is the shared semantic layer for all rule families. It builds a
single AnalysisContext per source file so rules can consume one common
interpretation of variables, sources, sinks, guards, framework signals, and
domain-specific semantics. Inventory is represented as a domain tag on generic
sinks rather than as the shape of the IR itself.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field


TAINTED = "tainted"
TRUSTED = "trusted"
SAFE = "safe"
UNKNOWN = "unknown"


DEFAULT_INVENTORY_FIELD_NAMES = frozenset(
    [
        "stock",
        "stock_count",
        "stock_quantity",
        "stock_level",
        "stock_available",
        "stock_remaining",
        "stock_total",
        "stock_left",
        "stock_balance",
        "quantity",
        "qty",
        "quantity_available",
        "quantity_on_hand",
        "quantity_in_stock",
        "quantity_remaining",
        "available_qty",
        "remaining_qty",
        "total_qty",
        "reserved_qty",
        "sold_qty",
        "allocated_qty",
        "held_qty",
        "inventory",
        "inventory_count",
        "inventory_level",
        "inventory_quantity",
        "available_inventory",
        "available",
        "available_count",
        "available_quantity",
        "available_units",
        "units_available",
        "units_remaining",
        "remaining",
        "remaining_quantity",
        "remaining_stock",
        "remaining_count",
        "units",
        "unit_count",
        "items_left",
        "items_available",
        "items_remaining",
        "item_count",
        "in_stock",
        "backorder_quantity",
        "preorder_quantity",
        "warehouse_stock",
        "warehouse_quantity",
        "bin_quantity",
        "storage_quantity",
        "seats",
        "seats_available",
        "seats_remaining",
        "available_seats",
        "capacity",
        "remaining_capacity",
        "max_capacity",
        "current_capacity",
        "reserved",
        "reservation_count",
        "reserved_count",
        "hold_count",
        "hold_quantity",
        "booked",
        "booked_seats",
        "reserved_seats",
        "occupied_seats",
        "credits",
        "credit_balance",
        "token_balance",
        "tokens_remaining",
        "tokens_available",
        "quota",
        "quota_remaining",
        "usage_limit",
        "limit_remaining",
        "api_credits",
        "api_credit_balance",
        "daily_quota",
        "monthly_quota",
        "licenses",
        "license_count",
        "slots",
        "slots_available",
        "slots_remaining",
        "energy",
        "stamina",
        "mana",
        "lives",
        "gems",
    ],
)

INVENTORY_SKIP_FIELDS = frozenset(
    [
        "rating",
        "score",
        "points",
        "reputation",
        "rank",
        "views",
        "view_count",
        "downloads",
        "download_count",
        "likes",
        "like_count",
        "reactions",
        "reaction_count",
        "followers",
        "following",
        "comments",
        "shares",
        "clicks",
        "impressions",
        "conversions",
        "priority",
        "order",
        "sort_order",
        "position",
        "attempts",
        "failed_attempts",
        "retry_count",
        "version",
        "revision",
        "engagement_rate",
        "bounce_rate",
        "retention_rate",
        "ctr",
        "cvr",
        "karma",
        "xp",
        "experience",
        "level",
        "tier",
        "badge_count",
        "following_count",
        "follower_count",
        "subscriber_count",
        "subscribers",
        "revenue",
        "profit",
        "loss",
        "income",
        "balance_sheet",
        "product_rating",
        "review_score",
        "avg_rating",
        "cache_hits",
        "cache_misses",
        "db_queries",
        "response_time",
        "sort_index",
        "display_order",
        "sequence",
    ],
)

_SCAN_DIRS = (
    "app/Http/Controllers/",
    "app/Services/",
    "app/Actions/",
    "app/Jobs/",
    "app/Repositories/",
    "src/Http/Controllers/",
    "src/Services/",
    "src/Actions/",
    "src/Jobs/",
    "src/Repositories/",
)
_SKIP_CLASS_SUFFIXES = ("Test", "Seeder", "Factory")
_NON_INVENTORY_MODELS = frozenset(["User", "Admin", "Log", "Audit", "Setting", "Config", "Permission", "Role"])

_DECREMENT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"->\s*decrement\s*\(\s*['\"]([^'\"]+)['\"](?:\s*,\s*(\$\w+|\d+))?",
            re.IGNORECASE,
        ),
        "decrement",
    ),
    (
        re.compile(
            r"->\s*update\s*\(\s*\[[^\]]*['\"]([^'\"]+)['\"]\s*=>\s*DB::raw\s*\(\s*['\"]\s*\1\s*-\s*(\$\w+|\d+)?",
            re.IGNORECASE,
        ),
        "update_raw",
    ),
    (
        re.compile(
            r"->\s*update\s*\(\s*\[[^\]]*['\"]([^'\"]+)['\"]\s*=>\s*\$\w+\s*->\s*\1\s*-\s*(\$\w+|\d+)?",
            re.IGNORECASE,
        ),
        "update_sub",
    ),
    (re.compile(r"\$\w+\s*->\s*(\w+)\s*-=\s*(\$\w+|\d+)", re.IGNORECASE), "assign_sub"),
    (re.compile(r"\$\w+\s*->\s*(\w+)\s*=\s*\$\w+\s*->\s*\1\s*-\s*(\$\w+|\d+)", re.IGNORECASE), "assign_sub"),
)
_LOCK_PATTERNS = (
    re.compile(r"lockForUpdate\s*\(", re.IGNORECASE),
    re.compile(r"sharedLock\s*\(", re.IGNORECASE),
    re.compile(r"lock_for_update\s*\(", re.IGNORECASE),
    re.compile(r"pessimisticLock\s*\(", re.IGNORECASE),
    re.compile(r"optimisticLock\s*\(", re.IGNORECASE),
    re.compile(r"withLock\s*\(", re.IGNORECASE),
    re.compile(r"\bFOR\s+UPDATE\b", re.IGNORECASE),
)
_TRANSACTION_PATTERNS = (
    re.compile(r"DB::transaction\s*\(", re.IGNORECASE),
    re.compile(r"DB::beginTransaction\s*\(", re.IGNORECASE),
    re.compile(r"beginTransaction\s*\(", re.IGNORECASE),
    re.compile(r"->\s*transaction\s*\(", re.IGNORECASE),
)
_FLOOR_GUARD_PATTERNS = (
    re.compile(r"if\s*\(\s*\$\w+\s*->\s*(\w+)\s*>=\s*(\$\w+|\d+)", re.IGNORECASE),
    re.compile(r"(?:->|::)\s*where\s*\(\s*['\"](\w+)['\"]\s*,\s*['\"]>=['\"]\s*,", re.IGNORECASE),
    re.compile(r"if\s*\(\s*\$\w+\s*->\s*(\w+)\s*<\s*(\$\w+|\d+)", re.IGNORECASE),
    re.compile(r"abort_if\s*\(\s*\$\w+\s*->\s*(\w+)\s*<", re.IGNORECASE),
    re.compile(r"abort\s*\(\s*.*\$\w+\s*->\s*(\w+)\s*<", re.IGNORECASE),
    re.compile(r"InsufficientStockException|OutOfStockException|StockException", re.IGNORECASE),
)
_GT_ZERO_WITH_VAR_QTY = re.compile(
    r"if\s*\(\s*\$\w+\s*->\s*(\w+)\s*>\s*0\s*\)\s*\{[^}]*decrement\s*\(\s*['\"]\1['\"]\s*,\s*\$",
    re.IGNORECASE | re.DOTALL,
)
_QUERY_EXCEPTION_PATTERN = re.compile(r"catch\s*\(\s*QueryException\s", re.IGNORECASE)
_MUTATOR_PATTERN = re.compile(r"function\s+set(\w+)Attribute\s*\(", re.IGNORECASE)
_CLASS_NAME_PATTERN = re.compile(r"class\s+(\w+)\s+", re.IGNORECASE)
_MODEL_NAME_PATTERN = re.compile(r"(?:new\s+)?(\w+)\s*::", re.IGNORECASE)
_PHP_ASSIGNMENT_PATTERN = re.compile(r"\$(\w+)\s*=\s*([^;]+);")
_JS_ASSIGNMENT_PATTERN = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*([^;\n]+)")
_FUNCTION_PATTERN = re.compile(r"function\s+(\w+)\s*\([^)]*\)\s*\{", re.IGNORECASE)
_PHP_VARIABLE_REF_PATTERN = re.compile(r"\$(\w+)")
_JS_VARIABLE_REF_PATTERN = re.compile(r"\b([A-Za-z_]\w*)\b")
_BROWSER_STORAGE_SET_PATTERN = re.compile(
    r"\b(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*(['\"])(.*?)\2\s*,\s*([^)]+)\)",
    re.IGNORECASE | re.DOTALL,
)
_CONSOLE_CALL_PATTERN = re.compile(r"\bconsole\s*\.\s*(log|warn|error|info|debug)\s*\(", re.IGNORECASE)
_FETCH_CALL_PATTERN = re.compile(r"\bfetch\s*\(", re.IGNORECASE)
_BLADE_RAW_ECHO_PATTERN = re.compile(r"\{!!\s*(.*?)\s*!!\}", re.DOTALL)
_PHP_METHOD_CALL_PATTERN = re.compile(
    r"(?P<receiver>\$this|\$\w+|\w+|self|static)\s*(?P<operator>->|::)\s*(?P<method>\w+)\s*\(",
)
_JS_CALL_PATTERN = re.compile(r"\b(?P<callee>[A-Za-z_]\w*)\s*\(")
_REACT_SIGNAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\buseEffect\s*\(", re.IGNORECASE), "react_use_effect"),
    (re.compile(r"\buseMemo\s*\(", re.IGNORECASE), "react_use_memo"),
    (re.compile(r"\buseCallback\s*\(", re.IGNORECASE), "react_use_callback"),
    (re.compile(r"<\s*ErrorBoundary\b", re.IGNORECASE), "react_error_boundary"),
    (re.compile(r"<\s*Suspense\b", re.IGNORECASE), "react_suspense"),
)
_JS_IDENTIFIER_SKIP_WORDS = frozenset(
    [
        "await",
        "const",
        "false",
        "let",
        "new",
        "null",
        "return",
        "true",
        "undefined",
        "var",
    ],
)


@dataclass(frozen=True)
class VariableDefinition:
    name: str
    expression: str
    taint: str
    line: int
    depends_on: tuple[str, ...] = ()
    trace_id: str = ""


@dataclass(frozen=True)
class GuardCondition:
    kind: str
    line: int
    domain: str = "global"
    field_name: str = ""
    operator: str = ""
    variable: str = ""
    trace_id: str = ""


@dataclass(frozen=True)
class EvidenceTrace:
    id: str
    kind: str
    line: int
    summary: str
    signals: tuple[str, ...] = ()
    source: str = ""
    target: str = ""

    def to_debug_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "line": self.line,
            "summary": self.summary,
            "signals": list(self.signals),
            "source": self.source,
            "target": self.target,
        }


@dataclass(frozen=True)
class DataflowSource:
    name: str
    kind: str
    line: int
    taint: str = UNKNOWN
    expression: str = ""
    domain: str = "global"
    trace_id: str = ""

    def to_debug_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind,
            "line": self.line,
            "taint": self.taint,
            "expression": self.expression,
            "domain": self.domain,
            "trace_id": self.trace_id,
        }


@dataclass(frozen=True)
class DataflowSink:
    target: str
    operation: str
    line: int
    kind: str = "write"
    domain: str = "global"
    amount_variable: str = ""
    trace_id: str = ""
    signals: tuple[str, ...] = ()

    @property
    def field_name(self) -> str:
        return self.target

    @property
    def pattern_type(self) -> str:
        return self.operation

    @property
    def is_inventory(self) -> bool:
        return self.domain == "inventory"

    def to_debug_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "operation": self.operation,
            "line": self.line,
            "kind": self.kind,
            "domain": self.domain,
            "amount_variable": self.amount_variable,
            "trace_id": self.trace_id,
            "signals": list(self.signals),
        }


@dataclass(frozen=True)
class FrameworkSignal:
    kind: str
    line: int
    domain: str = "global"
    trace_id: str = ""
    signals: tuple[str, ...] = ()

    def to_debug_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "line": self.line,
            "domain": self.domain,
            "trace_id": self.trace_id,
            "signals": list(self.signals),
        }


@dataclass(frozen=True)
class CallEdge:
    caller: str
    callee: str
    line: int
    receiver: str = ""
    kind: str = "function_call"
    domain: str = "global"
    trace_id: str = ""

    def to_debug_dict(self) -> dict[str, object]:
        return {
            "caller": self.caller,
            "callee": self.callee,
            "line": self.line,
            "receiver": self.receiver,
            "kind": self.kind,
            "domain": self.domain,
            "trace_id": self.trace_id,
        }


@dataclass(frozen=True)
class InventorySink:
    field_name: str
    line: int
    pattern_type: str
    is_inventory: bool
    amount_variable: str = ""
    trace_id: str = ""


@dataclass
class FunctionAnalysisContext:
    name: str
    line_start: int
    line_end: int
    language: str = ""
    variables: dict[str, VariableDefinition] = field(default_factory=dict)
    sources: list[DataflowSource] = field(default_factory=list)
    sinks: list[DataflowSink] = field(default_factory=list)
    guard_conditions: list[GuardCondition] = field(default_factory=list)
    framework_signals: list[FrameworkSignal] = field(default_factory=list)
    call_edges: list[CallEdge] = field(default_factory=list)
    inventory_sinks: list[InventorySink] = field(default_factory=list)
    has_lock: bool = False
    has_transaction: bool = False
    has_floor_validation: bool = False


@dataclass
class AnalysisContext:
    file_path: str
    content_hash: str = ""
    language: str = ""
    class_name: str = ""
    variables: dict[str, VariableDefinition] = field(default_factory=dict)
    sources: list[DataflowSource] = field(default_factory=list)
    sinks: list[DataflowSink] = field(default_factory=list)
    guard_conditions: list[GuardCondition] = field(default_factory=list)
    framework_signals: list[FrameworkSignal] = field(default_factory=list)
    call_edges: list[CallEdge] = field(default_factory=list)
    inventory_sinks: list[InventorySink] = field(default_factory=list)
    traces: list[EvidenceTrace] = field(default_factory=list)
    function_contexts: list[FunctionAnalysisContext] = field(default_factory=list)
    has_lock: bool = False
    has_transaction: bool = False
    has_floor_validation: bool = False
    has_insufficient_floor_guard: bool = False
    has_query_exception_guard: bool = False
    mutator_protected_fields: set[str] = field(default_factory=set)
    referenced_models: set[str] = field(default_factory=set)
    is_scan_target: bool = False
    is_skip_file: bool = False
    is_skip_class: bool = False
    is_non_inventory_only: bool = False

    @property
    def has_inventory_sink(self) -> bool:
        return any(sink.is_inventory for sink in self.sinks)

    @property
    def inventory_sink_fields(self) -> set[str]:
        return {sink.target for sink in self.sinks if sink.is_inventory}

    def domain_sinks(self, domain: str, operation: str | None = None) -> list[DataflowSink]:
        return [
            sink
            for sink in self.sinks
            if sink.domain == domain and (operation is None or sink.operation == operation)
        ]

    def domain_guards(self, domain: str, kind: str | None = None) -> list[GuardCondition]:
        return [
            guard
            for guard in self.guard_conditions
            if guard.domain == domain and (kind is None or guard.kind == kind)
        ]

    def to_debug_dict(self) -> dict[str, object]:
        return {
            "file_path": self.file_path,
            "content_hash": self.content_hash,
            "language": self.language,
            "class_name": self.class_name,
            "has_lock": self.has_lock,
            "has_transaction": self.has_transaction,
            "has_floor_validation": self.has_floor_validation,
            "has_insufficient_floor_guard": self.has_insufficient_floor_guard,
            "has_query_exception_guard": self.has_query_exception_guard,
            "inventory_sink_fields": sorted(self.inventory_sink_fields),
            "variables": {
                name: {
                    "expression": variable.expression,
                    "taint": variable.taint,
                    "line": variable.line,
                    "depends_on": list(variable.depends_on),
                    "trace_id": variable.trace_id,
                }
                for name, variable in sorted(self.variables.items())
            },
            "sources": [source.to_debug_dict() for source in self.sources],
            "sinks": [sink.to_debug_dict() for sink in self.sinks],
            "guard_conditions": [
                {
                    "kind": guard.kind,
                    "line": guard.line,
                    "domain": guard.domain,
                    "field_name": guard.field_name,
                    "operator": guard.operator,
                    "variable": guard.variable,
                    "trace_id": guard.trace_id,
                }
                for guard in self.guard_conditions
            ],
            "framework_signals": [signal.to_debug_dict() for signal in self.framework_signals],
            "call_edges": [edge.to_debug_dict() for edge in self.call_edges],
            "inventory_sinks": [
                {
                    "field_name": sink.field_name,
                    "line": sink.line,
                    "pattern_type": sink.pattern_type,
                    "is_inventory": sink.is_inventory,
                    "amount_variable": sink.amount_variable,
                    "trace_id": sink.trace_id,
                }
                for sink in self.inventory_sinks
            ],
            "mutator_protected_fields": sorted(self.mutator_protected_fields),
            "referenced_models": sorted(self.referenced_models),
            "traces": [trace.to_debug_dict() for trace in self.traces],
        }


def is_inventory_field(field_name: str, extensions: frozenset | None = None) -> bool:
    raw = field_name.strip().strip("`'\"").strip()
    if "." in raw:
        raw = raw.split(".", 1)[-1]
    low = raw.lower()
    if low in INVENTORY_SKIP_FIELDS:
        return False
    if low in DEFAULT_INVENTORY_FIELD_NAMES:
        return True
    return bool(extensions and low in extensions)


def is_skip_file(file_path: str) -> bool:
    norm = (file_path or "").replace("\\", "/").lower()
    skip_segments = ("/tests/", "/test/", "/spec/", "/seeders/", "/factories/", "/migrations/")
    if any(segment in f"/{norm}" for segment in skip_segments):
        return True
    basename = norm.rsplit("/", 1)[-1] if "/" in norm else norm
    return basename.endswith(("test.php", "spec.php", "_test.php"))


def is_scan_target(file_path: str) -> bool:
    norm = (file_path or "").replace("\\", "/")
    return any(norm.startswith(scan_dir) for scan_dir in _SCAN_DIRS)


def is_skip_class(class_name: str) -> bool:
    return bool(class_name and any(class_name.endswith(suffix) for suffix in _SKIP_CLASS_SUFFIXES))


def is_non_inventory_model(model_name: str) -> bool:
    return (model_name or "").strip() in _NON_INVENTORY_MODELS


def has_lock_protection(content: str) -> bool:
    return any(pattern.search(content or "") for pattern in _LOCK_PATTERNS)


def has_transaction_protection(content: str) -> bool:
    return any(pattern.search(content or "") for pattern in _TRANSACTION_PATTERNS)


def has_floor_guard(content: str) -> bool:
    return any(pattern.search(content or "") for pattern in _FLOOR_GUARD_PATTERNS)


def has_query_exception_guard(content: str) -> bool:
    return bool(_QUERY_EXCEPTION_PATTERN.search(content or ""))


def has_mutator_protection(content: str, field_name: str) -> bool:
    field_low = (field_name or "").lower()
    for match in _MUTATOR_PATTERN.finditer(content or ""):
        attr_name = match.group(1)
        if not attr_name or attr_name.lower() != field_low:
            continue
        brace_pos = content.find("{", match.end())
        if brace_pos < 0:
            continue
        body = content[brace_pos : _find_matching_brace(content, brace_pos) + 1]
        if "max(0" in body or "max( 0" in body:
            return True
    return False


def find_decrement_candidates(content: str) -> list[tuple[str, int, str]]:
    candidates: list[tuple[str, int, str]] = []
    for sink in _find_inventory_sinks(content or ""):
        candidates.append((sink.field_name, sink.line, sink.pattern_type))
    return candidates


def iter_analysis_contexts(facts: object) -> list[AnalysisContext]:
    contexts = getattr(facts, "_analysis_contexts", None) or {}
    if isinstance(contexts, dict):
        return [ctx for ctx in contexts.values() if isinstance(ctx, AnalysisContext)]
    if isinstance(contexts, list):
        return [ctx for ctx in contexts if isinstance(ctx, AnalysisContext)]
    return []


class GlobalDataflowAnalyzer:
    """Builds shared dataflow contexts for source files."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, str, tuple[str, ...]], AnalysisContext] = {}

    def analyze_file(
        self,
        file_path: str,
        content: str,
        extensions: frozenset | None = None,
    ) -> AnalysisContext:
        extension_key = tuple(sorted(str(item).lower() for item in (extensions or frozenset())))
        cache_key = (file_path, _stable_hash(content or ""), extension_key)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        context = self._build_context(file_path, content or "", extensions)
        self._cache[cache_key] = context
        return context

    def _build_context(
        self,
        file_path: str,
        content: str,
        extensions: frozenset | None,
    ) -> AnalysisContext:
        language = _detect_language(file_path)
        class_name = _first_group(_CLASS_NAME_PATTERN.search(content))
        variables = _extract_variables(content, file_path, language)
        sources = _extract_sources(variables, file_path)
        guard_conditions = _extract_guard_conditions(content, file_path)
        referenced_models = {match.group(1) for match in _MODEL_NAME_PATTERN.finditer(content) if match.group(1)}
        sinks = _extract_sinks(content, extensions, file_path, language)
        inventory_sinks = _inventory_sinks_from_dataflow_sinks(sinks)
        framework_signals = _extract_framework_signals(content, file_path, language)
        call_edges = _extract_call_edges(content, file_path, language)
        mutator_fields = _find_mutator_protected_fields(content)
        function_contexts = _extract_function_contexts(content, extensions, file_path, language)
        traces = _build_traces(
            file_path=file_path,
            language=language,
            variables=variables,
            sources=sources,
            guards=guard_conditions,
            sinks=sinks,
            framework_signals=framework_signals,
            call_edges=call_edges,
        )

        return AnalysisContext(
            file_path=file_path,
            content_hash=_stable_hash(content),
            language=language,
            class_name=class_name,
            variables=variables,
            sources=sources,
            sinks=sinks,
            guard_conditions=guard_conditions,
            framework_signals=framework_signals,
            call_edges=call_edges,
            inventory_sinks=inventory_sinks,
            traces=traces,
            function_contexts=function_contexts,
            has_lock=has_lock_protection(content),
            has_transaction=has_transaction_protection(content),
            has_floor_validation=bool(guard_conditions),
            has_insufficient_floor_guard=bool(_GT_ZERO_WITH_VAR_QTY.search(content)),
            has_query_exception_guard=has_query_exception_guard(content),
            mutator_protected_fields=mutator_fields,
            referenced_models=referenced_models,
            is_scan_target=is_scan_target(file_path),
            is_skip_file=is_skip_file(file_path),
            is_skip_class=is_skip_class(class_name),
            is_non_inventory_only=bool(referenced_models)
            and all(is_non_inventory_model(model) for model in referenced_models),
        )


def _extract_variables(content: str, file_path: str = "", language: str = "") -> dict[str, VariableDefinition]:
    variables: dict[str, VariableDefinition] = {}
    pattern = _JS_ASSIGNMENT_PATTERN if language in {"javascript", "typescript"} else _PHP_ASSIGNMENT_PATTERN
    for match in pattern.finditer(content):
        name = match.group(1)
        expression = match.group(2).strip()
        line = _line_number(content, match.start())
        depends_on = _extract_variable_refs(expression, language, name)
        taint = _classify_expression_taint(expression, variables, depends_on, language)
        variables[name] = VariableDefinition(
            name=name,
            expression=expression,
            taint=taint,
            line=line,
            depends_on=depends_on,
            trace_id=_trace_id(file_path, "variable_taint", line, name),
        )
    return variables


def _extract_sources(variables: dict[str, VariableDefinition], file_path: str) -> list[DataflowSource]:
    sources: list[DataflowSource] = []
    for variable in variables.values():
        source_kind, domain = _classify_source(variable)
        sources.append(
            DataflowSource(
                name=variable.name,
                kind=source_kind,
                line=variable.line,
                taint=variable.taint,
                expression=variable.expression,
                domain=domain,
                trace_id=_trace_id(file_path, "source", variable.line, f"{source_kind}:{variable.name}"),
            ),
        )
    return sources


def _classify_expression_taint(
    expression: str,
    variables: dict[str, VariableDefinition],
    depends_on: tuple[str, ...],
    language: str = "",
) -> str:
    low = expression.lower()
    if "$request->" in low or "request(" in low or "input(" in low:
        return TAINTED
    if language in {"javascript", "typescript"} and any(
        token in low
        for token in (
            "event.target",
            "localstorage.getitem",
            "sessionstorage.getitem",
            "new urlsearchparams",
            "useparams(",
            "usesearchparams(",
            "window.location",
        )
    ):
        return TAINTED
    if any(variables.get(name) and variables[name].taint == TAINTED for name in depends_on):
        return TAINTED
    if re.fullmatch(r"[\d\s'\"._+-]+", expression):
        return SAFE
    if re.search(r"(::|->)\s*(find|first|get|sole|value)\s*\(", expression, re.IGNORECASE):
        return TRUSTED
    return UNKNOWN


def _classify_source(variable: VariableDefinition) -> tuple[str, str]:
    expression = variable.expression.lower()
    if variable.taint == TAINTED:
        if "localstorage.getitem" in expression or "sessionstorage.getitem" in expression:
            return ("browser_storage_read", "browser_storage")
        if "window.location" in expression or "urlsearchparams" in expression:
            return ("url_input", "browser")
        return ("request_input", "input")
    if variable.taint == TRUSTED:
        return ("database_read", "database")
    if variable.taint == SAFE:
        return ("literal", "literal")
    return ("derived_value", "global")


def _extract_guard_conditions(content: str, file_path: str = "") -> list[GuardCondition]:
    guards: list[GuardCondition] = []
    for pattern in _FLOOR_GUARD_PATTERNS:
        for match in pattern.finditer(content):
            field_name = match.group(1) if match.lastindex else ""
            if field_name and not is_inventory_field(field_name):
                continue
            line = _line_number(content, match.start())
            variable = (
                match.group(2).lstrip("$")
                if match.lastindex and match.lastindex >= 2 and match.group(2)
                else ""
            )
            guards.append(
                GuardCondition(
                    kind="floor_validation",
                    line=line,
                    domain="inventory" if field_name and is_inventory_field(field_name) else "global",
                    field_name=field_name or "",
                    operator=">=" if ">=" in match.group(0) else "<" if "<" in match.group(0) else "",
                    variable=variable,
                    trace_id=_trace_id(file_path, "floor_validation", line, f"{field_name}:{variable}"),
                ),
            )
    return guards


def _extract_sinks(
    content: str,
    extensions: frozenset | None = None,
    file_path: str = "",
    language: str = "",
) -> list[DataflowSink]:
    sinks = _extract_decrement_sinks(content, extensions, file_path)
    if language in {"javascript", "typescript"}:
        sinks.extend(_extract_browser_storage_sinks(content, file_path))
        sinks.extend(_extract_console_sinks(content, file_path))
        sinks.extend(_extract_fetch_sinks(content, file_path))
    if language == "blade":
        sinks.extend(_extract_blade_output_sinks(content, file_path))
    return sinks


def _extract_decrement_sinks(
    content: str,
    extensions: frozenset | None = None,
    file_path: str = "",
) -> list[DataflowSink]:
    sinks: list[DataflowSink] = []
    for pattern, pattern_type in _DECREMENT_PATTERNS:
        for match in pattern.finditer(content):
            field_name = match.group(1) if match.lastindex else ""
            amount = ""
            if match.lastindex and match.lastindex >= 2 and match.group(2):
                amount = str(match.group(2)).lstrip("$")
            if not field_name:
                continue
            line = _line_number(content, match.start())
            is_inventory = is_inventory_field(field_name, extensions)
            domain = "inventory" if is_inventory else "state_counter"
            sinks.append(
                DataflowSink(
                    target=field_name,
                    operation=pattern_type,
                    line=line,
                    kind="state_write",
                    domain=domain,
                    amount_variable=amount,
                    trace_id=_trace_id(file_path, f"{domain}_sink", line, f"{pattern_type}:{field_name}:{amount}"),
                    signals=(
                        f"field={field_name}",
                        f"pattern={pattern_type}",
                        f"is_inventory={str(is_inventory).lower()}",
                    ),
                ),
            )
    return sinks


def _extract_browser_storage_sinks(content: str, file_path: str) -> list[DataflowSink]:
    sinks: list[DataflowSink] = []
    for match in _BROWSER_STORAGE_SET_PATTERN.finditer(content):
        storage = match.group(1)
        key = match.group(3)
        value = match.group(4).strip()
        line = _line_number(content, match.start())
        sinks.append(
            DataflowSink(
                target=key,
                operation="setItem",
                line=line,
                kind="storage_write",
                domain="browser_storage",
                amount_variable=value,
                trace_id=_trace_id(file_path, "browser_storage_sink", line, f"{storage}:{key}:{value}"),
                signals=(f"storage={storage}", f"key={key}"),
            ),
        )
    return sinks


def _extract_console_sinks(content: str, file_path: str) -> list[DataflowSink]:
    sinks: list[DataflowSink] = []
    for match in _CONSOLE_CALL_PATTERN.finditer(content):
        operation = f"console.{match.group(1)}"
        line = _line_number(content, match.start())
        sinks.append(
            DataflowSink(
                target=operation,
                operation=operation,
                line=line,
                kind="log_call",
                domain="logging",
                trace_id=_trace_id(file_path, "logging_sink", line, operation),
                signals=(f"call={operation}",),
            ),
        )
    return sinks


def _extract_fetch_sinks(content: str, file_path: str) -> list[DataflowSink]:
    sinks: list[DataflowSink] = []
    for match in _FETCH_CALL_PATTERN.finditer(content):
        line = _line_number(content, match.start())
        sinks.append(
            DataflowSink(
                target="fetch",
                operation="fetch",
                line=line,
                kind="network_call",
                domain="network",
                trace_id=_trace_id(file_path, "network_sink", line, "fetch"),
                signals=("call=fetch",),
            ),
        )
    return sinks


def _extract_blade_output_sinks(content: str, file_path: str) -> list[DataflowSink]:
    sinks: list[DataflowSink] = []
    for match in _BLADE_RAW_ECHO_PATTERN.finditer(content):
        expression = match.group(1).strip()
        line = _line_number(content, match.start())
        sinks.append(
            DataflowSink(
                target="blade_raw_echo",
                operation="raw_echo",
                line=line,
                kind="template_output",
                domain="blade",
                amount_variable=expression,
                trace_id=_trace_id(file_path, "blade_sink", line, expression),
                signals=("template_output=raw_echo",),
            ),
        )
    return sinks


def _find_inventory_sinks(
    content: str,
    extensions: frozenset | None = None,
    file_path: str = "",
) -> list[InventorySink]:
    return _inventory_sinks_from_dataflow_sinks(_extract_decrement_sinks(content, extensions, file_path))


def _inventory_sinks_from_dataflow_sinks(sinks: list[DataflowSink]) -> list[InventorySink]:
    return [
        InventorySink(
            field_name=sink.target,
            line=sink.line,
            pattern_type=sink.operation,
            is_inventory=sink.is_inventory,
            amount_variable=sink.amount_variable,
            trace_id=sink.trace_id,
        )
        for sink in sinks
        if sink.domain in {"inventory", "state_counter"}
    ]


def _find_mutator_protected_fields(content: str) -> set[str]:
    protected: set[str] = set()
    for match in _MUTATOR_PATTERN.finditer(content):
        attr_name = match.group(1)
        brace_pos = content.find("{", match.end())
        if not attr_name or brace_pos < 0:
            continue
        body = content[brace_pos : _find_matching_brace(content, brace_pos) + 1]
        if "max(0" in body or "max( 0" in body:
            protected.add(attr_name.lower())
    return protected


def _extract_function_contexts(
    content: str,
    extensions: frozenset | None,
    file_path: str = "",
    language: str = "",
) -> list[FunctionAnalysisContext]:
    contexts: list[FunctionAnalysisContext] = []
    for match in _FUNCTION_PATTERN.finditer(content):
        open_brace = content.find("{", match.end() - 1)
        if open_brace < 0:
            continue
        close_brace = _find_matching_brace(content, open_brace)
        body = content[open_brace + 1 : close_brace]
        guards = _extract_guard_conditions(body, file_path)
        variables = _extract_variables(body, file_path, language)
        sinks = _extract_sinks(body, extensions, file_path, language)
        framework_signals = _extract_framework_signals(body, file_path, language)
        call_edges = _extract_call_edges(body, file_path, language, caller=match.group(1))
        contexts.append(
            FunctionAnalysisContext(
                name=match.group(1),
                line_start=_line_number(content, match.start()),
                line_end=_line_number(content, close_brace),
                language=language,
                variables=variables,
                sources=_extract_sources(variables, file_path),
                sinks=sinks,
                guard_conditions=guards,
                framework_signals=framework_signals,
                call_edges=call_edges,
                inventory_sinks=_inventory_sinks_from_dataflow_sinks(sinks),
                has_lock=has_lock_protection(body),
                has_transaction=has_transaction_protection(body),
                has_floor_validation=bool(guards),
            ),
        )
    return contexts


def _extract_framework_signals(content: str, file_path: str, language: str = "") -> list[FrameworkSignal]:
    signals: list[FrameworkSignal] = []
    norm_path = (file_path or "").replace("\\", "/").lower()
    if (norm_path.startswith("routes/") or "/routes/" in norm_path) and norm_path.endswith(".php"):
        signals.append(
            FrameworkSignal(
                kind="laravel_route_file",
                line=1,
                domain="laravel",
                trace_id=_trace_id(file_path, "laravel_route_file", 1, norm_path),
                signals=("route_surface=true",),
            ),
        )
    if (norm_path.startswith("config/") or "/config/" in norm_path) and norm_path.endswith(".php"):
        signals.append(
            FrameworkSignal(
                kind="laravel_config_file",
                line=1,
                domain="laravel",
                trace_id=_trace_id(file_path, "laravel_config_file", 1, norm_path),
                signals=("config_surface=true",),
            ),
        )
    if norm_path in {"composer.json", "package.json"}:
        signals.append(
            FrameworkSignal(
                kind="dependency_manifest",
                line=1,
                domain="devops",
                trace_id=_trace_id(file_path, "dependency_manifest", 1, norm_path),
                signals=(f"manifest={norm_path}",),
            ),
        )
    if norm_path in {"composer.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pnpm-lock.yml"}:
        signals.append(
            FrameworkSignal(
                kind="dependency_lockfile",
                line=1,
                domain="devops",
                trace_id=_trace_id(file_path, "dependency_lockfile", 1, norm_path),
                signals=(f"lockfile={norm_path}",),
            ),
        )
    if norm_path in {".env", ".env.example"}:
        signals.append(
            FrameworkSignal(
                kind="environment_file",
                line=1,
                domain="devops",
                trace_id=_trace_id(file_path, "environment_file", 1, norm_path),
                signals=(f"env_file={norm_path}",),
            ),
        )
    if norm_path == ".gitignore":
        signals.append(
            FrameworkSignal(
                kind="gitignore_file",
                line=1,
                domain="devops",
                trace_id=_trace_id(file_path, "gitignore_file", 1, norm_path),
                signals=("ignore_policy=true",),
            ),
        )
    if norm_path in {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}:
        signals.append(
            FrameworkSignal(
                kind="container_config",
                line=1,
                domain="devops",
                trace_id=_trace_id(file_path, "container_config", 1, norm_path),
                signals=(f"container_config={norm_path}",),
            ),
        )
    if norm_path.startswith(".github/workflows/") and norm_path.endswith((".yml", ".yaml")):
        signals.append(
            FrameworkSignal(
                kind="ci_workflow",
                line=1,
                domain="devops",
                trace_id=_trace_id(file_path, "ci_workflow", 1, norm_path),
                signals=(f"workflow={norm_path}",),
            ),
        )
    for pattern in _LOCK_PATTERNS:
        for match in pattern.finditer(content):
            line = _line_number(content, match.start())
            signals.append(
                FrameworkSignal(
                    kind="lock",
                    line=line,
                    domain="database",
                    trace_id=_trace_id(file_path, "lock", line, "lock"),
                    signals=("has_lock=true",),
                ),
            )
    for pattern in _TRANSACTION_PATTERNS:
        for match in pattern.finditer(content):
            line = _line_number(content, match.start())
            signals.append(
                FrameworkSignal(
                    kind="transaction",
                    line=line,
                    domain="database",
                    trace_id=_trace_id(file_path, "transaction", line, "transaction"),
                    signals=("has_transaction=true",),
                ),
            )
    if language in {"javascript", "typescript"}:
        for pattern, kind in _REACT_SIGNAL_PATTERNS:
            for match in pattern.finditer(content):
                line = _line_number(content, match.start())
                signals.append(
                    FrameworkSignal(
                        kind=kind,
                        line=line,
                        domain="react",
                        trace_id=_trace_id(file_path, kind, line, kind),
                        signals=(f"react_signal={kind}",),
                    ),
                )
    return signals


def _extract_call_edges(
    content: str,
    file_path: str,
    language: str = "",
    caller: str = "file",
) -> list[CallEdge]:
    if language in {"javascript", "typescript"}:
        return _extract_js_call_edges(content, file_path, caller)
    if language == "php":
        return _extract_php_call_edges(content, file_path, caller)
    return []


def _extract_php_call_edges(content: str, file_path: str, caller: str) -> list[CallEdge]:
    edges: list[CallEdge] = []
    for match in _PHP_METHOD_CALL_PATTERN.finditer(content):
        callee = str(match.group("method") or "")
        if not callee:
            continue
        receiver = str(match.group("receiver") or "$this")
        line = _line_number(content, match.start())
        kind = "same_class_call" if receiver == "$this" else "service_or_static_call"
        edges.append(
            CallEdge(
                caller=caller,
                callee=callee,
                receiver=receiver,
                line=line,
                kind=kind,
                domain="php",
                trace_id=_trace_id(file_path, "call_edge", line, f"{caller}:{receiver}:{callee}"),
            ),
        )
    return edges


def _extract_js_call_edges(content: str, file_path: str, caller: str) -> list[CallEdge]:
    edges: list[CallEdge] = []
    for match in _JS_CALL_PATTERN.finditer(content):
        callee = str(match.group("callee") or "")
        if not callee or callee in _JS_IDENTIFIER_SKIP_WORDS:
            continue
        line = _line_number(content, match.start())
        edges.append(
            CallEdge(
                caller=caller,
                callee=callee,
                line=line,
                kind="function_call",
                domain="javascript",
                trace_id=_trace_id(file_path, "call_edge", line, f"{caller}:{callee}"),
            ),
        )
    return edges


def _build_traces(
    *,
    file_path: str,
    language: str,
    variables: dict[str, VariableDefinition],
    sources: list[DataflowSource],
    guards: list[GuardCondition],
    sinks: list[DataflowSink],
    framework_signals: list[FrameworkSignal],
    call_edges: list[CallEdge],
) -> list[EvidenceTrace]:
    traces: list[EvidenceTrace] = []
    for variable in variables.values():
        variable_label = _format_variable_name(variable.name, language)
        traces.append(
            EvidenceTrace(
                id=variable.trace_id,
                kind="variable_taint",
                line=variable.line,
                summary=f"{variable_label} assigned from {variable.expression}",
                signals=(
                    f"variable={variable.name}",
                    f"taint={variable.taint}",
                    f"depends_on={','.join(variable.depends_on)}",
                ),
                source=variable.expression,
                target=variable_label,
            ),
        )
    for source in sources:
        traces.append(
            EvidenceTrace(
                id=source.trace_id,
                kind="source",
                line=source.line,
                summary=f"{source.kind} source for {source.name}",
                signals=(
                    f"name={source.name}",
                    f"kind={source.kind}",
                    f"domain={source.domain}",
                    f"taint={source.taint}",
                ),
                source=source.expression,
                target=source.name,
            ),
        )
    for guard in guards:
        traces.append(
            EvidenceTrace(
                id=guard.trace_id,
                kind=guard.kind,
                line=guard.line,
                summary=f"{guard.domain} {guard.kind} guard for {guard.field_name or 'unknown field'}",
                signals=(
                    f"domain={guard.domain}",
                    f"field={guard.field_name}",
                    f"operator={guard.operator}",
                    f"variable={guard.variable}",
                ),
                source=guard.variable,
                target=guard.field_name,
            ),
        )
    for sink in sinks:
        traces.append(
            EvidenceTrace(
                id=sink.trace_id,
                kind=f"{sink.domain}_sink",
                line=sink.line,
                summary=f"{sink.domain} {sink.operation} sink targets {sink.target}",
                signals=(
                    f"target={sink.target}",
                    f"operation={sink.operation}",
                    f"kind={sink.kind}",
                    f"domain={sink.domain}",
                    f"amount_variable={sink.amount_variable}",
                    *sink.signals,
                ),
                source=sink.amount_variable,
                target=sink.target,
            ),
        )
    for signal in framework_signals:
        traces.append(
            EvidenceTrace(
                id=signal.trace_id,
                kind=signal.kind,
                line=signal.line,
                summary=f"{signal.domain} framework signal: {signal.kind}",
                signals=(f"domain={signal.domain}", *signal.signals),
            ),
        )
    for edge in call_edges:
        traces.append(
            EvidenceTrace(
                id=edge.trace_id,
                kind="call_edge",
                line=edge.line,
                summary=f"{edge.caller} calls {edge.callee}",
                signals=(
                    f"caller={edge.caller}",
                    f"callee={edge.callee}",
                    f"receiver={edge.receiver}",
                    f"kind={edge.kind}",
                    f"domain={edge.domain}",
                ),
                source=edge.caller,
                target=edge.callee,
            ),
        )
    return traces


def _first_match_line(content: str, patterns: tuple[re.Pattern[str], ...]) -> int:
    starts = [match.start() for pattern in patterns if (match := pattern.search(content))]
    if not starts:
        return 0
    return _line_number(content, min(starts))


def _extract_variable_refs(expression: str, language: str, assigned_name: str) -> tuple[str, ...]:
    if language in {"javascript", "typescript"}:
        refs = _JS_VARIABLE_REF_PATTERN.findall(expression)
        return tuple(ref for ref in refs if ref != assigned_name and ref not in _JS_IDENTIFIER_SKIP_WORDS)
    return tuple(ref for ref in _PHP_VARIABLE_REF_PATTERN.findall(expression) if ref != assigned_name)


def _detect_language(file_path: str) -> str:
    low = (file_path or "").lower()
    if low.endswith(".blade.php"):
        return "blade"
    if low.endswith((".js", ".jsx")):
        return "javascript"
    if low.endswith((".ts", ".tsx")):
        return "typescript"
    if low.endswith(".php"):
        return "php"
    if low.endswith(".env") or low.endswith(".env.example") or low.endswith(".gitignore"):
        return "config"
    if low.endswith("dockerfile"):
        return "config"
    if low.endswith((".json", ".lock", ".yaml", ".yml")):
        return "config"
    return "unknown"


def _format_variable_name(name: str, language: str) -> str:
    return f"${name}" if language == "php" else name


def _find_matching_brace(text: str, open_idx: int) -> int:
    depth = 1
    i = open_idx + 1
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return max(open_idx, i - 1)


def _line_number(content: str, index: int) -> int:
    return content.count("\n", 0, max(0, index)) + 1


def _first_group(match: re.Match[str] | None) -> str:
    return match.group(1) if match else ""


def _stable_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:length]


def _trace_id(file_path: str, kind: str, line: int, key: str) -> str:
    digest = _stable_hash(f"{file_path}:{kind}:{line}:{key}", 12)
    return f"trace_{digest}"
