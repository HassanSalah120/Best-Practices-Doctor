"""
N+1 Risk Rule

Detects likely lazy-loaded relation access inside iteration constructs.

Tree-sitter is the source of truth: the FactsBuilder extracts RelationAccess facts
from AST nodes (foreach + collection ->each/map callbacks). This rule only reads facts.
"""
import re
from collections import defaultdict

from schemas.facts import Facts, RelationAccess, QueryUsage
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class NPlusOneRiskRule(Rule):
    """
    Flags relation access in loops as a likely N+1 performance issue.

    This is heuristic-based because we don't do full type inference:
    - We assume `$item->relation` in an iteration is a relation access, not a scalar property.
    - We increase confidence when the surrounding method contains queries without eager loading.
    """

    id = "n-plus-one-risk"
    name = "N+1 Risk Detection"
    description = "Detects likely lazy-loaded relation access in loops (N+1 risk)"
    category = Category.PERFORMANCE
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]

    # Scalar-ish members that frequently appear in loops but are not relations.
    _scalar_like_members = {
        "id",
        "name",
        "email",
        "title",
        "status",
        "type",
        "reason",
        "value",
        "label",
        "key",
        "created_at",
        "updated_at",
        "deleted_at",
        "start_date",
        "end_date",
        "start_time",
        "end_time",
        "notes",
        "description",
        "details",
        "features",
        "limits",
        "settings",
        "slug",
        "code",
        "phone",
        "method",
        "amount",
        "currency",
        "duration",
        "duration_minutes",
        "nodevalue",
        "nodename",
    }
    _scalar_suffixes = (
        "_id",
        "_at",
        "_date",
        "_time",
        "_amount",
        "_number",
        "_count",
        "_name",
        "_code",
        "_slug",
        "_status",
        "_type",
        "_minutes",
        "_en",
        "_ar",
    )
    _base_var_aliases = {
        "apt": "appointment",
        "appt": "appointment",
        "pt": "patient",
        "enc": "encounter",
        "rx": "prescription",
        "inv": "invoice",
    }
    _relation_builder_re = re.compile(
        r"\b("
        r"belongsTo|hasOne|hasMany|belongsToMany|morphTo|morphOne|morphMany|"
        r"morphToMany|morphedByMany|hasOneThrough|hasManyThrough"
        r")\b",
        re.IGNORECASE,
    )

    def _looks_scalar_member(self, rel: str) -> bool:
        r = (rel or "").strip().lower()
        if not r:
            return True
        if r in self._scalar_like_members:
            return True
        if r.startswith(("is_", "has_")):
            return True
        return any(r.endswith(s) for s in self._scalar_suffixes)

    def _normalize_model_key(self, raw: str) -> str:
        x = (raw or "").strip().lower().lstrip("$")
        if not x:
            return ""
        # strip common wrappers and hints
        x = x.replace("{", "").replace("}", "")
        for suffix in ("_dto", "dto"):
            if x.endswith(suffix):
                x = x[: -len(suffix)]
        if x in self._base_var_aliases:
            return self._base_var_aliases[x]
        if x.endswith("ies") and len(x) > 3:
            return x[:-3] + "y"
        if x.endswith("s") and len(x) > 3:
            return x[:-1]
        return x

    def _build_model_relation_index(
        self,
        facts: Facts,
    ) -> tuple[dict[str, set[str]], set[str]]:
        """
        Build a best-effort index:
        - model_key -> relation method names
        - global set of known relation names
        """
        model_keys_by_fqcn: dict[str, str] = {}
        for c in facts.classes:
            fp = (c.file_path or "").replace("\\", "/")
            if not fp.startswith("app/Models/"):
                continue
            fqcn = (c.fqcn or "").strip()
            if not fqcn:
                continue
            model_keys_by_fqcn[fqcn] = self._normalize_model_key(fqcn.split("\\")[-1])

        by_model: dict[str, set[str]] = defaultdict(set)
        all_rel_names: set[str] = set()
        for m in facts.methods:
            fqcn = (m.class_fqcn or "").strip()
            model_key = model_keys_by_fqcn.get(fqcn)
            if not model_key:
                continue
            calls_joined = " ".join(str(x) for x in (m.call_sites or []))
            if not self._relation_builder_re.search(calls_joined):
                continue
            rel_name = (m.name or "").strip().lower()
            if not rel_name:
                continue
            by_model[model_key].add(rel_name)
            all_rel_names.add(rel_name)

        return dict(by_model), all_rel_names

    def _infer_model_key_from_queries(
        self,
        qs: list[QueryUsage],
        model_relations: dict[str, set[str]],
    ) -> str:
        keys: set[str] = set()
        for q in qs:
            raw = str(getattr(q, "model", "") or "")
            if not raw:
                continue
            base = raw.split("\\")[-1]
            k = self._normalize_model_key(base)
            if k and k in model_relations:
                keys.add(k)
        return next(iter(keys)) if len(keys) == 1 else ""

    def _should_skip_access(self, ra: RelationAccess) -> bool:
        rel = (ra.relation or "").strip().lower()
        base = (ra.base_var or "").strip().lower()
        loop_kind = (ra.loop_kind or "").strip().lower()
        access_type = (ra.access_type or "").strip().lower()

        # Static/helper calls like Arr::get(), data_get(), etc. are NOT relation access.
        if access_type in {"static_call", "function_call"}:
            return True

        # DTO loops are usually in-memory transformations, not Eloquent relation access.
        if "dto" in base:
            return True

        # Enum iteration (e.g. SomeEnum::cases() as $status => $status->value)
        # commonly accesses scalar enum members.
        if rel in {"value", "name"} and loop_kind.startswith("collection_"):
            return True

        # Common scalar/date column access on models.
        if self._looks_scalar_member(rel):
            return True

        return False

    def _is_eager_loaded_in_queries(self, rel: str, qs: list[QueryUsage]) -> bool:
        """Check if a relation name is present in any eager-loading calls in the queries."""
        if not rel or not qs:
            return False
        rel_lower = rel.lower()
        for q in qs:
            # Check if this query has eager loading flag set
            if getattr(q, "has_eager_loading", False):
                # The relation is likely eager loaded if there's a with() call
                # Nested relations like 'patient.clinic' also eager load 'patient'
                return True
            # Fallback: check the raw query text for relation name in common patterns
            # This handles cases like ->with('patient') or ->with(['patient', 'clinic'])
            raw_text = str(getattr(q, "method_chain", "") or "")
            if raw_text:
                # Look for the relation name in the method chain
                if f"with->{rel_lower}" in raw_text.lower():
                    return True
                if f"with('{rel_lower}')" in raw_text.lower():
                    return True
                if f'with("{rel_lower}")' in raw_text.lower():
                    return True
                # Check for nested relation patterns: 'patient.clinic' also loads 'patient'
                if f"{rel_lower}." in raw_text.lower():
                    return True
        return False

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        min_confidence = float(self.get_threshold("min_confidence", 0.55))

        # Index queries by method for confidence tuning.
        q_by_method: dict[tuple[str, str], list[QueryUsage]] = {}
        for q in facts.queries:
            q_by_method.setdefault((q.file_path, q.method_name), []).append(q)

        model_relations, global_relation_names = self._build_model_relation_index(facts)

        # Group accesses to avoid noisy duplicates.
        grouped: dict[tuple[str, str, str, str], list[RelationAccess]] = {}
        for ra in facts.relation_accesses:
            if self._should_skip_access(ra):
                continue
            key = (
                ra.file_path,
                ra.method_name,
                ra.relation,
                ra.loop_kind,
            )
            grouped.setdefault(key, []).append(ra)

        for (file_path, method_name, relation, loop_kind), ras in grouped.items():
            sample = ras[0]
            line_start = min(r.line_number for r in ras)
            occurrences = len(ras)

            qs = q_by_method.get((file_path, method_name), [])
            has_any_query = len(qs) > 0
            has_any_eager = any(q.has_eager_loading for q in qs)
            rel = (relation or "").strip().lower()

            # If the relation is explicitly eager-loaded in this method's queries,
            # it is NOT an N+1 — skip it entirely.
            if self._is_eager_loaded_in_queries(rel, qs):
                continue

            # Also check if ANY query in the file has eager loading for this relation
            # (handles cases where data is fetched in a helper method)
            all_file_queries = [q for q in facts.queries if q.file_path == file_path]
            if self._is_eager_loaded_in_queries(rel, all_file_queries):
                continue

            model_key = self._normalize_model_key(sample.base_var or "")
            if model_key not in model_relations:
                # Fallback for generic loop vars like `$item`, `$row`, `$entry`:
                # if the method clearly queries one model type, use it as context.
                q_model_key = self._infer_model_key_from_queries(qs, model_relations)
                if q_model_key:
                    model_key = q_model_key
            model_known = model_key in model_relations
            model_match = model_known and rel in model_relations.get(model_key, set())
            model_mismatch = model_known and not model_match
            access_method = (sample.access_type or "").strip().lower() == "method"
            global_match = rel in global_relation_names

            # Strong mismatch signal: variable likely maps to a known model, but accessed
            # member is not a declared relation on that model.
            if model_mismatch and not access_method:
                continue

            # Collection mapper loops with pure property access and no local query context
            # are often in-memory transformations (high FP source).
            if (
                (loop_kind or "").startswith("collection_")
                and not has_any_query
                and not access_method
            ):
                continue

            # Signal-based confidence.
            signal = 0.0
            if access_method:
                signal += 0.45
            if model_match:
                signal += 0.35
            elif global_match:
                signal += 0.20
            elif rel.endswith("s") and rel not in {"status", "settings", "notes"}:
                signal += 0.15

            if has_any_query and not has_any_eager:
                signal += 0.30
            elif has_any_query and has_any_eager:
                signal += 0.15

            confidence = min(0.95, 0.20 + signal)

            # Avoid noisy weak signals.
            if confidence < min_confidence:
                continue

            ctx_cls = sample.class_fqcn or ""
            ctx = f"{ctx_cls}::{method_name}:{sample.base_var}->{relation}:{loop_kind}"

            findings.append(
                self.create_finding(
                    title="Potential N+1: lazy-loaded relation inside iteration",
                    context=ctx,
                    file=file_path,
                    line_start=line_start,
                    description=(
                        f"Detected `{sample.base_var}->{relation}` accessed inside `{loop_kind}`. "
                        "In Laravel/Eloquent, accessing relations inside a loop often triggers one query per item (N+1). "
                        + (f"({occurrences} occurrence(s) detected.)" if occurrences > 1 else "")
                    ),
                    why_it_matters=(
                        "N+1 query patterns can massively slow down pages and APIs by multiplying database round-trips. "
                        "The fix is usually to eager load the relation or restructure the data access so it runs once."
                    ),
                    suggested_fix=(
                        "1. Eager load the relation before iterating: `Model::with('relation')->...->get()`\n"
                        "2. If iterating an existing collection, consider `load('relation')` before the loop\n"
                        "3. If you need aggregates, use `withCount()` / `withSum()` instead of per-item queries\n"
                        "4. Confirm with Telescope/Debugbar query count"
                    ),
                    code_example=(
                        "// Before\n"
                        "$users = User::all();\n"
                        "foreach ($users as $user) {\n"
                        "    $user->posts; // lazy loads per user\n"
                        "}\n\n"
                        "// After\n"
                        "$users = User::with('posts')->get();\n"
                    ),
                    confidence=confidence,
                    tags=["performance", "n+1", "eloquent", "eager-loading"],
                )
            )

        return findings
