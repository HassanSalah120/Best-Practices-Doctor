"""
DRY Violation Rule
Detects duplicate code blocks across the codebase.
"""
from __future__ import annotations

from fnmatch import fnmatch

from schemas.facts import Facts, DuplicateBlock
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class DryViolationRule(Rule):
    """
    Detects duplicate code that violates DRY principle.
    
    Duplication is detected by the FactsBuilder using token hashing.
    This rule reports significant duplications.
    """
    
    id = "dry-violation"
    name = "DRY Violation Detection"
    description = "Detects duplicate code blocks"
    category = Category.DRY
    default_severity = Severity.MEDIUM
    _DEFAULT_IGNORED_PATH_PATTERNS = [
        "vendor/**",
        "bootstrap/cache/**",
        "storage/**",
        "resources/lang/**",
        "lang/**",
        "routes/**",
        "tests/**",
        "app/**/RouteRegistrars/**",
        "app/Providers/**",
        "app/Http/Requests/**",
        "app/Http/Resources/**",
        "app/DTOs/**",
        "app/Services/Mappers/**",
        # Static lookup/configuration data files
        "app/Data/**",
        "app/Constants/**",
        "app/Enums/**",
        "config/**",
        # Reporting services naturally have similar status counting patterns
        "app/Services/*Reporting*.php",
        "app/Services/*Report*.php",
    ]
    _LOW_SIGNAL_WRAPPER_SNIPPETS = (
        "db::transaction(",
        "return db::transaction(",
    )
    _LOW_SIGNAL_DATA_MAPPING_PATH_PREFIXES = (
        "app/Http/Controllers/",
        "app/Services/",
        "app/Actions/",
        "app/Http/Resources/",
    )
    _LOW_SIGNAL_DATA_MAPPING_CONTROL_FLOW = (
        "if (",
        "foreach (",
        "for (",
        "while (",
        "switch (",
        "try {",
        "catch (",
    )
    
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings = []

        # Backwards/forwards compatible threshold keys.
        min_tokens = int(self.get_threshold("min_tokens", self.get_threshold("min_token_count", 50)) or 50)
        min_occurrences = int(self.get_threshold("min_occurrences", 2) or 2)
        min_unique_files = int(self.get_threshold("min_unique_files", 2) or 2)
        min_span_lines = int(self.get_threshold("min_span_lines", 6) or 6)
        min_tokens_for_short_span = int(self.get_threshold("min_tokens_for_short_span", 120) or 120)

        raw_ignored = self.get_threshold(
            "ignore_path_patterns",
            self.get_threshold("ignored_path_patterns", self._DEFAULT_IGNORED_PATH_PATTERNS),
        )
        ignored_patterns = self._normalize_patterns(raw_ignored)

        # First pass: collect all individual findings
        all_findings: list[Finding] = []
        for duplicate in self._normalize_duplicates(facts.duplicates):
            if int(duplicate.token_count or 0) < min_tokens:
                continue

            occurrences = list(duplicate.occurrences or [])
            if len(occurrences) < min_occurrences:
                continue

            unique_files = {self._normalize_path(str(occ[0])) for occ in occurrences if occ and occ[0]}
            if len(unique_files) < min_unique_files:
                continue

            # Skip if any file is in an ignored path (static data, config, etc.)
            if unique_files and any(self._is_ignored_path(fp, ignored_patterns) for fp in unique_files):
                continue
            if self._is_low_signal_framework_wrapper_duplicate(duplicate, unique_files):
                continue
            if self._is_low_signal_data_mapping_duplicate(duplicate, unique_files):
                continue
            if self._is_action_extraction_duplicate(duplicate, unique_files):
                continue

            max_span = max((max(1, int(occ[2]) - int(occ[1]) + 1) for occ in occurrences), default=0)
            if max_span < min_span_lines and int(duplicate.token_count or 0) < min_tokens_for_short_span:
                continue

            all_findings.append(self._create_finding(duplicate))

        # Second pass: Aggregate by file
        by_file: dict[str, list[Finding]] = {}
        for f in all_findings:
            by_file.setdefault(f.file, []).append(f)

        final_findings: list[Finding] = []
        for file_path, group in by_file.items():
            if not group:
                continue
            
            # If just one violation, use it as is
            if len(group) == 1:
                final_findings.append(group[0])
                continue

            # Multiple violations in one file -> Aggregate
            group.sort(key=lambda x: x.line_start)
            first = group[0]
            count = len(group)
            
            blocks_desc = ", ".join(f"lines {f.line_start}-{f.line_end}" for f in group[:3])
            if count > 3:
                blocks_desc += f", and {count-3} more"

            aggregated = self.create_finding(
                title=f"Significant code duplication detected ({count} blocks)",
                context=f"file:{file_path}",
                file=file_path,
                line_start=first.line_start,
                description=(
                    f"Found {count} duplicated code blocks in this file.\n"
                    f"Blocks: {blocks_desc}."
                ),
                why_it_matters=(
                    "Massive duplication indicates a need for refactoring. "
                    "It increases maintenance burden and risk of inconsistent updates."
                ),
                suggested_fix=(
                    "Extract common logic into shared methods, traits, or classes."
                ),
                tags=["dry", "refactor", "duplication", "maintenance"],
                confidence=0.8,
                evidence_signals=[f"count={count}", f"file={file_path}"],
                related_files=sorted({rf for f in group for rf in (f.related_files or []) if rf != file_path})[:10]
            )
            
            for f in group:
                aggregated.evidence_signals.append(f"block_line={f.line_start}-{f.line_end}: hash={f.context.replace('dup:', '')}")
            
            final_findings.append(aggregated)

        return final_findings

    def _normalize_duplicates(self, duplicates: list[DuplicateBlock]) -> list[DuplicateBlock]:
        grouped: dict[str, list[DuplicateBlock]] = {}
        for duplicate in duplicates or []:
            grouped.setdefault(str(getattr(duplicate, "hash", "")), []).append(duplicate)

        normalized: list[DuplicateBlock] = []
        for hash_val, members in grouped.items():
            if not hash_val:
                continue

            token_count = max(int(getattr(m, "token_count", 0) or 0) for m in members)
            snippet = ""
            per_file: dict[str, list[tuple[int, int]]] = {}

            for member in members:
                cur_snippet = str(getattr(member, "code_snippet", "") or "")
                if len(cur_snippet) > len(snippet):
                    snippet = cur_snippet

                for occ in (getattr(member, "occurrences", None) or []):
                    if len(occ) != 3:
                        continue
                    file_path = self._normalize_path(str(occ[0] or ""))
                    if not file_path:
                        continue
                    line_start = int(occ[1])
                    line_end = int(occ[2])
                    if line_start > line_end:
                        line_start, line_end = line_end, line_start
                    per_file.setdefault(file_path, []).append((line_start, line_end))

            merged_occurrences: list[tuple[str, int, int]] = []
            for file_path, intervals in per_file.items():
                for line_start, line_end in self._merge_intervals(intervals):
                    merged_occurrences.append((file_path, int(line_start), int(line_end)))

            if len(merged_occurrences) < 2:
                continue

            merged_occurrences.sort(key=lambda occ: (occ[0], int(occ[1]), int(occ[2])))
            normalized.append(
                DuplicateBlock(
                    hash=hash_val,
                    token_count=token_count,
                    occurrences=merged_occurrences,
                    code_snippet=snippet[:200],
                )
            )

        normalized.sort(key=lambda d: (-int(d.token_count or 0), -len(d.occurrences or []), d.hash))
        return normalized

    @staticmethod
    def _merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
        if not intervals:
            return []
        sorted_intervals = sorted((int(s), int(e)) for s, e in intervals)
        merged: list[tuple[int, int]] = []
        cur_start, cur_end = sorted_intervals[0]
        for start, end in sorted_intervals[1:]:
            if start <= cur_end + 1:
                cur_end = max(cur_end, end)
            else:
                merged.append((cur_start, cur_end))
                cur_start, cur_end = start, end
        merged.append((cur_start, cur_end))
        return merged

    @staticmethod
    def _normalize_path(path: str) -> str:
        s = str(path or "").replace("\\", "/")
        while s.startswith("./"):
            s = s[2:]
        while "//" in s:
            s = s.replace("//", "/")
        return s

    @staticmethod
    def _normalize_patterns(raw: object) -> list[str]:
        if isinstance(raw, str):
            candidates = [raw]
        elif isinstance(raw, (list, tuple, set)):
            candidates = list(raw)
        else:
            candidates = []
        patterns: list[str] = []
        for pattern in candidates:
            s = str(pattern or "").strip()
            if not s:
                continue
            patterns.append(s.replace("\\", "/"))
        return patterns

    def _is_ignored_path(self, file_path: str, patterns: list[str]) -> bool:
        path = self._normalize_path(file_path)
        return any(fnmatch(path, pattern) for pattern in patterns)

    def _is_low_signal_framework_wrapper_duplicate(
        self,
        duplicate: DuplicateBlock,
        unique_files: set[str],
    ) -> bool:
        snippet = str(getattr(duplicate, "code_snippet", "") or "").lower()
        if not snippet:
            return False
        if not any(token in snippet for token in self._LOW_SIGNAL_WRAPPER_SNIPPETS):
            return False
        if int(getattr(duplicate, "token_count", 0) or 0) > 110:
            return False
        return bool(unique_files) and all(
            path.startswith("app/Actions/") or path.startswith("app/Services/")
            for path in unique_files
        )

    def _is_low_signal_data_mapping_duplicate(
        self,
        duplicate: DuplicateBlock,
        unique_files: set[str],
    ) -> bool:
        snippet = str(getattr(duplicate, "code_snippet", "") or "")
        if not snippet:
            return False
        token_count = int(getattr(duplicate, "token_count", 0) or 0)
        if token_count > 140:
            return False
        if snippet.count("=>") < 5:
            return False

        normalized = snippet.lower().replace("\n", " ")
        if any(token in normalized for token in self._LOW_SIGNAL_DATA_MAPPING_CONTROL_FLOW):
            return False

        if not unique_files:
            return False

        if not all(path.startswith(self._LOW_SIGNAL_DATA_MAPPING_PATH_PREFIXES) for path in unique_files):
            return False

        return True

    def _is_action_extraction_duplicate(
        self,
        duplicate: DuplicateBlock,
        unique_files: set[str],
    ) -> bool:
        normalized_files = {self._normalize_path(path) for path in unique_files}
        lower_files = {path.lower() for path in normalized_files}
        if not lower_files:
            return False
        if not any(path.startswith("app/actions/") for path in lower_files):
            return False
        if not all(path.startswith(("app/actions/", "app/services/")) for path in lower_files):
            return False
        if len(lower_files) > 3 or len(list(duplicate.occurrences or [])) > 4:
            return False

        token_count = int(getattr(duplicate, "token_count", 0) or 0)
        if token_count > 180:
            return False

        max_span = max(
            (max(1, int(occ[2]) - int(occ[1]) + 1) for occ in (duplicate.occurrences or [])),
            default=0,
        )
        if max_span > 45:
            return False

        domains = {
            parts[2]
            for path in lower_files
            if (parts := path.split("/")) and len(parts) >= 4 and parts[0] == "app" and parts[1] in {"actions", "services"}
        }
        if not domains or len(domains) > 1:
            return False

        snippet = str(getattr(duplicate, "code_snippet", "") or "").lower()
        return not any(token in snippet for token in ("route::", "schema::", "view(", "migration", "create table"))

    def _create_finding(self, duplicate: DuplicateBlock) -> Finding:
        """Create finding for duplicate block."""
        occurrences = list(duplicate.occurrences or [])
        if not occurrences:
            return self.create_finding(
                title="Duplicate code block detected",
                context=f"dup:{duplicate.hash}",
                file="",
                line_start=1,
                line_end=1,
                description="Duplicate code detected.",
                why_it_matters="Duplicate code increases maintenance risk.",
                suggested_fix="Extract shared logic.",
                tags=["dry", "refactor", "duplication"],
            )

        first_occ = occurrences[0]
        other_files: list[str] = []
        seen_files = {first_occ[0]}
        for occ in occurrences[1:]:
            fp = occ[0]
            if fp in seen_files:
                continue
            seen_files.add(fp)
            other_files.append(fp)

        return self.create_finding(
            title="Duplicate code block detected",
            context=f"dup:{duplicate.hash}",
            file=first_occ[0],
            line_start=first_occ[1],
            line_end=first_occ[2],
            description=(
                f"This code block is duplicated in {len(occurrences)} places "
                f"({duplicate.token_count} tokens). "
                f"Consider extracting to a shared function or trait."
            ),
            why_it_matters=(
                "Duplicate code violates the DRY (Don't Repeat Yourself) principle. "
                "When you need to change logic, you must find and update all copies. "
                "Missed copies lead to bugs and inconsistent behavior."
            ),
            suggested_fix=(
                "1. Identify the common logic in the duplicated blocks\n"
                "2. Extract to a shared method, trait, or helper class\n"
                "3. Replace all occurrences with calls to the shared code\n"
                "4. Add tests for the extracted logic"
            ),
            code_example=f"// Duplicated code snippet:\n{duplicate.code_snippet[:200]}...",
            related_files=other_files,
            tags=["dry", "refactor", "duplication"],
        )
