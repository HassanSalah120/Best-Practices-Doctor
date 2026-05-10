"""
DTO Suggestion Rule

Flags large associative arrays being passed around between layers and suggests DTOs.
"""
from rules.base import Rule
from schemas.facts import AssocArrayLiteral, Facts
from schemas.finding import Category, Finding, FindingClassification, Severity
from schemas.metrics import MethodMetrics


class DtoSuggestionRule(Rule):
    severity_weight = 0
    confidence = 'low'
    fix_suggestion = 'Address the dto suggestion by making the framework contract explicit and keeping the change local to the affected boundary.'
    examples = {}
    priority = 4
    group = 'Code Quality'
    applies_to = ['service']
    references = []
    related_rules = []
    false_positive_notes = 'This is a heuristic/style signal and may be acceptable when the team has an explicit convention for this pattern.'
    detection_type = 'ast'
    analysis_cost = 'medium'
    auto_fixable = False
    tags = {'domain': 'laravel', 'type': 'quality', 'concern': 'dto-suggestion'}
    """
    Suggest using DTOs instead of passing large associative arrays between layers.

    This rule uses AST-extracted facts (AssocArrayLiteral). It intentionally ignores:
    - Validation rule arrays (`validate`, `Validator::make`)
    - View/response payload arrays (`view`, `json`) where arrays are expected
    """

    id = "dto-suggestion"
    name = "DTO Suggestion"
    description = "Suggests DTOs when large associative arrays are used as data carriers"
    category = Category.MAINTAINABILITY
    default_severity = Severity.MEDIUM
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

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        dto_import_files = {
            str(item.file_path)
            for item in (getattr(facts, "use_imports", []) or [])
            if "\\dto\\" in str(item.fqcn or "").lower()
            or "\\dtos\\" in str(item.fqcn or "").lower()
            or str(item.alias or "").upper().endswith("DTO")
        }

        min_keys = int(self.get_threshold("min_keys", 14))
        ignore_targets = {
            "validate", "make", "json", "view", "compact",
            "create", "update", "insert", "forceCreate", "updateOrCreate",
            "render", "share", "inertia", "response", "with",
            "config", "settings", "mapping", "allowedTransitions",
            "getAttributes", "setAttributes", "fill",
        }

        grouped: dict[tuple[str, str, str, str | None], list[AssocArrayLiteral]] = {}
        for a in facts.assoc_arrays:
            if a.key_count < min_keys:
                continue
            # Global File Path Exclusions
            lower_path = str(a.file_path or "").replace("\\", "/").lower()
            if any(p in lower_path for p in [
                "app/dtos/",
                "app/http/requests/",
                "app/http/middleware/",
                "app/services/mappers/",
                "app/mappers/",
                "app/transformers/",
                "app/providers/",
                "app/repositories/",
                "database/seeders/",
                "database/factories/",
            ]):
                continue
            if str(a.file_path) in dto_import_files:
                continue

            # Method Name Exclusions
            ignores_methods = {
                "rules", "toArray", "toResponse", "jsonSerialize",
                "toModelAttributes", "getAttributes", "definition",
                "share", "props", "map", "transform", "fields",
            }
            if (a.method_name or "") in ignores_methods:
                continue

            # Actions that build data (likely for responses/transformers)
            if "app/actions/" in lower_path and (a.method_name or "").startswith(("get", "build", "format")):
                continue

            if a.target and a.target in ignore_targets:
                continue
            lower_path = str(a.file_path or "").replace("\\", "/").lower()
            lower_fqcn = str(a.class_fqcn or "").lower()
            lower_method = str(a.method_name or "").lower()
            is_transport_layer = (
                "middleware" in lower_path
                or any(token in lower_path for token in ("/dashboard/", "/history/", "/communication/"))
                or any(token in lower_fqcn for token in ("dashboard", "history", "communication"))
                or any(token in lower_method for token in ("share", "payload", "props", "viewdata", "response"))
            )
            if is_transport_layer and str(a.used_as or "").lower() in {"return", "argument", "unknown"}:
                continue

            key = (a.file_path, a.method_name, a.used_as, a.target)
            grouped.setdefault(key, []).append(a)

        # Group by file_path for aggregation
        by_file: dict[str, list[dict]] = {}

        for (file_path, method_name, used_as, target), arrs in grouped.items():
            sample = arrs[0]
            line_start = min(a.line_number for a in arrs)
            max_keys = max(a.key_count for a in arrs)
            count = len(arrs)
            ctx_cls = sample.class_fqcn or ""

            # Store raw data for aggregation
            by_file.setdefault(file_path, []).append({
                "method": method_name,
                "used_as": used_as,
                "target": target,
                "line": line_start,
                "max_keys": max_keys,
                "count": count,
                "context": f"{ctx_cls}::{method_name}:{used_as}:{target or ''}:{max_keys}",
            })

        # Generate findings (aggregated per file)
        for file_path, items in by_file.items():
            if not items:
                continue

            items.sort(key=lambda x: x["line"])
            first = items[0]
            total_arrays = sum(i["count"] for i in items)

            # If only one distinct issue site, report normally
            if len(items) == 1:
                ctx = first["context"]
                tgt = first["target"] or "data flow"
                findings.append(
                    self.create_finding(
                        title="Consider using a DTO instead of a large associative array",
                        context=ctx,
                        file=file_path,
                        line_start=first["line"],
                        description=(
                            f"Found {first['count']} associative array literal(s) with {first['max_keys']} key(s) used as `{first['used_as']}` "
                            f"(target: `{tgt}`). Large arrays passed between layers tend to become untyped DTOs."
                        ),
                        why_it_matters=(
                            "Large associative arrays are easy to accidentally break (typos, missing keys) and hard to refactor. "
                            "DTOs (or Value Objects) provide explicit structure, type-safety, and improve readability."
                        ),
                        suggested_fix=(
                            "1. Introduce a DTO class (e.g., `UserPayload`, `OrderData`)\n"
                            "2. Replace array creation with `new Dto(...)` or a named constructor\n"
                            "3. Pass the DTO between layers instead of raw arrays\n"
                            "4. Add DTO validation/coercion at boundaries (request -> DTO)"
                        ),
                        code_example=(
                            "// Before\n"
                            "$payload = [\n"
                            "  'user_id' => $id,\n"
                            "  'email' => $email,\n"
                            "  // ...\n"
                            "];\n"
                            "$service->handle($payload);\n\n"
                            "// After\n"
                            "$payload = new UserPayload(userId: $id, email: $email);\n"
                            "$service->handle($payload);\n"
                        ),
                        tags=["maintainability", "dto", "typing", "architecture"],
                        confidence=0.7,
                    ),
                )
            else:
                # Multiple sites in one file -> Aggregate
                locations = ", ".join(f"line {i['line']} ({i['method']})" for i in items[:3])
                if len(items) > 3:
                     locations += f", and {len(items)-3} more"

                aggregated = self.create_finding(
                    title=f"Multiple DTO opportunities detected ({total_arrays} instances)",
                    context=f"file:{file_path}",
                    file=file_path,
                    line_start=first["line"],
                    description=(
                        f"Found {total_arrays} large associative arrays used as data carriers in this file.\n"
                        f"Locations: {locations}."
                    ),
                    why_it_matters=(
                        "Using loose arrays for complex data structures makes code brittle and hard to refactor. "
                        "Converting these to DTOs will explicitely document the data contract."
                    ),
                    suggested_fix=(
                        "Refactor these array usages into dedicated DTO/Value Object classes."
                    ),
                    tags=["maintainability", "dto", "typing", "architecture"],
                    confidence=0.7,
                    evidence_signals=[f"count={total_arrays}", f"file={file_path}"],
                )

                for i in items:
                    aggregated.evidence_signals.append(f"match_line={i['line']}: {i['method']} (keys={i['max_keys']})")

                findings.append(aggregated)

        return findings
