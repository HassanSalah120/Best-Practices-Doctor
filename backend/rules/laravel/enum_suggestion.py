"""
Enum Suggestion Rule
Detects repeated string literals that should be PHP enums.
"""
import re
from collections import defaultdict
from schemas.facts import Facts, StringLiteral, StringOccurrence
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class EnumSuggestionRule(Rule):
    """
    Detects groups of repeated string literals that form enum candidates.
    Uses context clustering (variable names, keys, etc.) to discover all enums at once.
    """
    
    id = "enum-suggestion"
    name = "Enum Suggestion"
    description = "Suggests creating PHP enums for clustered or repeated string literals"
    category = Category.DRY
    default_severity = Severity.LOW
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    
    # Common enum patterns for high-confidence matching
    ENUM_PATTERNS = {
        "status": [
            "pending", "approved", "rejected", "completed", "active", "inactive",
            "open", "closed", "planned", "scheduled", "rescheduled", "no_show",
            "paid", "unpaid", "partially_paid", "received",
        ],
        "role": ["admin", "moderator", "editor", "viewer", "user", "guest"],
        "type": ["primary", "secondary", "danger", "warning", "success", "info"],
        "state": ["draft", "published", "archived", "hidden", "deleted"],
        "priority": ["low", "medium", "high", "urgent", "critical"],
        "channel": ["email", "sms", "whatsapp", "push", "in_app"],
        "game_status": ["waiting", "in_progress", "finished", "paused", "staging"],
        "game_phase": ["day", "night", "discussion", "voting", "setup", "reveal"],
        "player_status": ["alive", "dead", "spectator", "disconnected", "eliminated"],
    }

    # Strings that look like enum values but are common in Laravel framework contexts
    # (validation rules, route params, config keys, DocBlock annotations, DB columns).
    _FRAMEWORK_NOISE = {
        "confirmed", "default", "deleted", "user", "guest",
        "required", "nullable", "sometimes", "unique", "exists",
        "action", "cancelled", "id", "name", "email", "password",
        "iso2", "dial_code", "name_en", "name_ar", "max_users", "max_patients",
        "id", "ip_address", "date", "type", "action", "clinic",
    }
    
    # Patterns indicating enum is already being used
    _ENUM_USAGE_PATTERNS = [
        r"\w+Enum::\w+->value",  # StatusEnum::PENDING->value
        r"\w+Enum::\w+->name",   # StatusEnum::PENDING->name
        r"\w+Enum::class",       # StatusEnum::class
    ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._enum_usage_regex = [re.compile(p) for p in self._ENUM_USAGE_PATTERNS]
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []
        existing_enums = self._existing_enum_names(facts)
        
        # 1. Group values by context
        context_to_values = defaultdict(set)
        context_to_occurrences = defaultdict(list)
        
        for literal in facts.string_literals:
            val = literal.value
            for occ in literal.occurrences:
                # Skip translation files
                if "/lang/" in occ.file_path.lower().replace("\\", "/"):
                    continue
                
                if occ.context:
                    context_to_values[occ.context].add(val)
                    context_to_occurrences[occ.context].append(occ)

        # 2. Extract findings from context clusters
        for context, values in context_to_values.items():
            if len(values) >= 2:
                ctx_lower = context.lower()
                # Skip common noise and context-specific FPs
                if ctx_lower in self._FRAMEWORK_NOISE:
                    continue
                
                # Skip strings that are clearly numeric keys or generic metadata
                if any(v.isdigit() for v in values):
                    continue
                
                # Skip if it looks like a list of headings or labels
                if any(v[0].isupper() for v in values if v) and ctx_lower in ["headings", "labels", "columns"]:
                    continue
                if self._matching_enum_exists(ctx_lower, existing_enums):
                    continue

                occs = context_to_occurrences[context]
                findings.append(self._create_cluster_finding(context, list(values), occs))

        # 3. Identify pattern-based groups (legacy but enriched)
        pattern_findings = self._find_enum_groups(facts.string_literals)
        # Avoid duplicate findings (if a pattern group was already found by context)
        detected_values = {tuple(sorted(f.metadata.get("values", []))) for f in findings if f.metadata and "values" in f.metadata}
        
        # Check if codebase already uses enums extensively
        has_enum_usage = self._check_for_existing_enum_usage(facts)
        
        for pf in pattern_findings:
            p_values = tuple(sorted(pf.metadata.get("values", [])))
            if p_values not in detected_values:
                context = str((pf.metadata or {}).get("context", "") or "").lower()
                if self._matching_enum_exists(context, existing_enums):
                    continue
                # If enums are already used extensively, lower confidence
                if has_enum_usage:
                    pf.confidence = 0.3  # Lower confidence since enums are already in use
                findings.append(pf)
                detected_values.add(p_values)

        return findings

    def _existing_enum_names(self, facts: Facts) -> set[str]:
        names = {
            re.sub(r"[^a-z0-9]+", "", str(getattr(enum_info, "name", "") or "").lower())
            for enum_info in getattr(facts, "enums", []) or []
            if getattr(enum_info, "name", None)
        }
        for file_path in getattr(facts, "files", []) or []:
            normalized = str(file_path or "").replace("\\", "/")
            if not normalized.lower().endswith("enum.php"):
                continue
            stem = normalized.split("/")[-1].rsplit(".", 1)[0]
            clean = re.sub(r"[^a-z0-9]+", "", stem.lower())
            if clean:
                names.add(clean)
        return names

    def _matching_enum_exists(self, context: str, existing_enums: set[str]) -> bool:
        normalized = re.sub(r"[^a-z0-9]+", "", context.lower())
        if not normalized:
            return False
        return any(normalized in enum_name for enum_name in existing_enums)
    
    def _check_for_existing_enum_usage(self, facts: Facts) -> bool:
        """Check if the codebase already uses enums extensively."""
        # Check for enum files in the codebase
        enum_file_count = len(facts.enums) if hasattr(facts, 'enums') else 0
        if enum_file_count >= 2:
            return True
        
        # Check for enum usage patterns in class constant accesses
        enum_usage_count = 0
        for ref in getattr(facts, 'class_const_accesses', []):
            expr = getattr(ref, 'expression', '')
            if expr and any(pattern.search(expr) for pattern in self._enum_usage_regex):
                enum_usage_count += 1
                if enum_usage_count >= 3:
                    return True
        
        return False
    
    def _find_enum_groups(self, literals: list[StringLiteral]) -> list[Finding]:
        findings = []
        min_occurrences = int(self.config.thresholds.get("min_occurrences", 3) or 3)
        for pattern_name, pattern_values in self.ENUM_PATTERNS.items():
            matching_vals = []
            all_occs = []
            
            for literal in literals:
                if literal.value.lower() in pattern_values:
                    relevant = [occ for occ in literal.occurrences if "/lang/" not in occ.file_path.lower().replace("\\", "/")]
                    if relevant:
                        matching_vals.append(literal.value)
                        all_occs.extend(relevant)
            
            unique_vals = list(set(matching_vals))
            if len(unique_vals) >= 2:
                findings.append(self._create_cluster_finding(pattern_name, list(set(matching_vals)), all_occs))
                continue

            # Repeated single known-domain values are still useful enum candidates
            # when they exceed the configured occurrence threshold.
            if len(unique_vals) == 1 and len(all_occs) >= min_occurrences:
                findings.append(self._create_cluster_finding(pattern_name, unique_vals, all_occs))
        
        return findings

    def _create_cluster_finding(self, context: str, values: list[str], occurrences: list[StringOccurrence]) -> Finding:
        first = occurrences[0] if occurrences else StringOccurrence(file_path="", line_number=0, context=context)
        enum_name = f"{context.title()}Enum"
        val_list = sorted(values)
        
        return self.create_finding(
            title=f"Create {enum_name} for related string literals",
            file=first.file_path,
            line_start=first.line_number,
            description=(
                f"Found related string literals used in the context of '{context}': "
                f"{', '.join(val_list)}. "
                f"These appear {len(occurrences)} times across the codebase."
            ),
            why_it_matters=(
                "Magic strings are error-prone and hard to refactor. "
                "PHP 8.1+ enums provide type safety and IDE autocompletion."
            ),
            suggested_fix=self._generate_enum_fix(context, val_list),
            code_example=self._generate_enum_example(context, val_list),
            metadata={"values": val_list, "context": context},
            tags=["enum", "dry", "type-safety"],
        )
    
    def _generate_enum_fix(self, context: str, values: list[str]) -> str:
        enum_name = f"{context.title()}Enum"
        return (
            f"1. Create `app/Enums/{enum_name}.php` with cases for: {', '.join(values)}\n"
            f"2. Add `$casts` to relevant Models: `'{context}' => {enum_name}::class`"
        )

    def _generate_enum_example(self, context: str, values: list[str]) -> str:
        enum_name = f"{context.title()}Enum"
        cases = "\n    ".join(f"case {v.upper().replace('-', '_').replace(' ', '_')} = '{v}';" for v in values)
        return f"""// app/Enums/{enum_name}.php
enum {enum_name}: string
{{
    {cases}
}}

// Usage in Model
protected $casts = ['{context}' => {enum_name}::class];"""
