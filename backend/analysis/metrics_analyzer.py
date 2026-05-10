"""
Metrics Analyzer

Analyzes raw Facts to compute derived metrics:
- Cyclomatic Complexity (Tree-sitter AST when available; heuristic fallback)
- Method Coupling (outgoing calls)
- Class Cohesion (LCOM4 approximation)
- God Class detection
"""
import logging
from pathlib import Path

from schemas.facts import Facts, MethodInfo
from schemas.metrics import FileMetrics, MethodMetrics, ProjectMetrics

logger = logging.getLogger(__name__)


class MetricsAnalyzer:
    """Computes derived metrics from raw facts."""

    _QUERY_PATTERNS = (
        "::where", "::find", "::all", "::query", "db::",
        "->get(", "->first(", "->pluck(", "->paginate(", "->count(",
        "->save(", "->update(", "->delete(", "->create(", "->insert(",
    )
    _VALIDATION_PATTERNS = ("->validate", "validated(", "validator::", "validate(")
    _BUSINESS_LOGIC_HINTS = (
        "calculate", "compute", "process", "transform", "convert",
        "generate", "sync", "import", "export", "charge", "refund",
        "notify", "dispatch", "send",
    )

    def __init__(self) -> None:
        self.file_metrics: dict[str, FileMetrics] = {}
        self.project_metrics = ProjectMetrics()

    def analyze(self, facts: Facts) -> dict[str, MethodMetrics]:
        """
        Analyze facts and return computed metrics.

        Args:
            facts: Raw extracted facts

        Returns:
            Dictionary mapping method_fqn to MethodMetrics
        """
        metrics = {}

        # Phase 10: Import optional test coverage artifacts (if present).
        # This is not a derived metric; we attach it to Facts as a private attribute so
        # rules can use it without changing the metrics dict shape.
        try:
            from analysis.coverage_importer import load_coverage

            facts._coverage = load_coverage(getattr(facts, "project_path", ""))
        except Exception:
            facts._coverage = None

        # Tree-sitter PHP parser (optional). Metrics remain derived, separate from Facts.
        self._php_parser = None
        self._php_lang = None
        try:
            import tree_sitter
            import tree_sitter_php

            self._php_lang = tree_sitter.Language(tree_sitter_php.language_php())
            self._php_parser = tree_sitter.Parser(self._php_lang)
        except Exception:
            self._php_parser = None
            self._php_lang = None

        # Per-file parsed trees cache
        file_cache: dict[str, tuple[bytes, object]] = {}

        # 1. Analyze methods
        for method in facts.methods:
            m_metrics = self._analyze_method(method, facts, file_cache)
            metrics[method.method_fqn] = m_metrics

        # 2. Analyze file-level aggregations for downstream reporting and diagnostics.
        self.file_metrics = self._analyze_files(facts, metrics)

        # 3. Analyze project-wide aggregations for dashboards and future rules.
        self.project_metrics = self._analyze_project(facts, metrics, self.file_metrics)

        return metrics

    def _analyze_files(
        self,
        facts: Facts,
        method_metrics: dict[str, MethodMetrics],
    ) -> dict[str, FileMetrics]:
        """Compute file-level metrics from scanned files and method metrics."""
        project_root = Path(facts.project_path) if facts.project_path else None
        classes_by_file: dict[str, int] = {}
        for cls in facts.classes:
            classes_by_file[cls.file_path] = classes_by_file.get(cls.file_path, 0) + 1

        methods_by_file: dict[str, list[MethodInfo]] = {}
        for method in facts.methods:
            methods_by_file.setdefault(method.file_path, []).append(method)

        result: dict[str, FileMetrics] = {}
        for file_path in sorted(facts.files):
            total_lines = 0
            blank_lines = 0
            comment_lines = 0
            if project_root:
                try:
                    lines = (project_root / file_path).read_text(
                        encoding="utf-8",
                        errors="replace",
                    ).splitlines()
                    total_lines = len(lines)
                    for line in lines:
                        stripped = line.strip()
                        if not stripped:
                            blank_lines += 1
                        elif stripped.startswith(("//", "#", "/*", "*", "*/")):
                            comment_lines += 1
                except Exception:
                    total_lines = 0
                    blank_lines = 0
                    comment_lines = 0

            file_methods = methods_by_file.get(file_path, [])
            complexities = [
                metric.cyclomatic_complexity
                for method in file_methods
                if (metric := method_metrics.get(method.method_fqn)) is not None
            ]
            result[file_path] = FileMetrics(
                file_path=file_path,
                file_hash=facts.file_hashes.get(file_path, ""),
                total_lines=total_lines,
                code_lines=max(0, total_lines - blank_lines - comment_lines),
                comment_lines=comment_lines,
                blank_lines=blank_lines,
                class_count=classes_by_file.get(file_path, 0),
                method_count=len(file_methods),
                avg_method_complexity=(sum(complexities) / len(complexities)) if complexities else 0.0,
                max_method_complexity=max(complexities) if complexities else 0,
            )

        return result

    def _analyze_project(
        self,
        facts: Facts,
        method_metrics: dict[str, MethodMetrics],
        file_metrics: dict[str, FileMetrics],
    ) -> ProjectMetrics:
        """Compute project-level metrics from file and method aggregations."""
        complexities = [metric.cyclomatic_complexity for metric in method_metrics.values()]
        total_lines = sum(metric.total_lines for metric in file_metrics.values())
        total_files = len(file_metrics)
        controller_count = len(facts.controllers)
        model_count = len(facts.models)
        validation_count = len(facts.validations) + len(facts.form_requests)

        return ProjectMetrics(
            total_files=total_files,
            total_classes=len(facts.classes),
            total_methods=len(facts.methods),
            total_lines=total_lines,
            controller_count=controller_count,
            model_count=model_count,
            service_count=len(facts.services),
            form_request_count=len(facts.form_requests),
            repository_count=len(facts.repositories),
            avg_file_size=(total_lines / total_files) if total_files else 0.0,
            avg_method_complexity=(sum(complexities) / len(complexities)) if complexities else 0.0,
            validation_coverage=(min(1.0, validation_count / controller_count) * 100.0)
            if controller_count
            else 0.0,
            service_coverage=(min(1.0, len(facts.services) / controller_count) * 100.0)
            if controller_count
            else 0.0,
            repository_coverage=(min(1.0, len(facts.repositories) / model_count) * 100.0)
            if model_count
            else 0.0,
            duplicate_block_count=len(facts.duplicates),
            enum_candidate_count=len(facts.enums),
        )

    def _analyze_method(self, method: MethodInfo, facts: Facts, file_cache: dict) -> MethodMetrics:
        """Compute metrics for a single method."""
        # Tree-sitter-first complexity when possible (derived metrics stage is allowed to parse).

        call_sites_lc = [c.lower() for c in method.call_sites]

        # Coupling: count unique call sites as a rough outgoing dependency proxy.
        coupling_count = len(set(call_sites_lc))

        query_count = sum(
            1 for c in call_sites_lc if any(p in c for p in self._QUERY_PATTERNS)
        )
        validation_count = sum(
            1 for c in call_sites_lc if any(p in c for p in self._VALIDATION_PATTERNS)
        )

        has_query = query_count > 0
        has_validation = validation_count > 0
        has_external_api_calls = any("http::" in c or "curl_" in c for c in call_sites_lc)

        cyclomatic, cognitive, nesting_depth = self._compute_complexity_ts(method, facts, file_cache)

        if cyclomatic is None:
            # Fallback heuristic (should be rare): approximate from LOC/calls/params.
            cyclomatic = 1 + (method.loc // 15) + (coupling_count // 4) + len(method.parameters)
            cognitive = cyclomatic
            nesting_depth = max(0, min(8, (cyclomatic - 1) // 3))

        # Business logic heuristic: complexity + no DB/validation + presence of hint words.
        hint_hits = sum(
            1 for c in call_sites_lc if any(h in c for h in self._BUSINESS_LOGIC_HINTS)
        )
        has_business_logic = (cyclomatic >= 4 and not has_query and not has_validation) or hint_hits > 0

        business_logic_confidence = 0.0
        if has_business_logic:
            # Confidence is intentionally coarse; rules should handle 0 as "unknown".
            business_logic_confidence = min(1.0, 0.4 + (cyclomatic / 20) + (hint_hits * 0.1))

        return MethodMetrics(
            method_fqn=method.method_fqn,
            file_path=method.file_path,
            cyclomatic_complexity=cyclomatic,
            cognitive_complexity=cognitive,
            nesting_depth=int(nesting_depth or 0),
            has_validation=has_validation,
            has_query=has_query,
            has_business_logic=has_business_logic,
            business_logic_confidence=business_logic_confidence,
            has_external_api_calls=has_external_api_calls,
            query_count=query_count,
            validation_count=validation_count,
        )

    def _compute_complexity_ts(self, method: MethodInfo, facts: Facts, file_cache: dict) -> tuple[int | None, int | None, int | None]:
        if not self._php_parser or not facts.project_path or not method.file_path:
            return (None, None, None)

        try:
            root = Path(facts.project_path)
            file_path = root / Path(method.file_path)
            content = file_path.read_bytes()
        except Exception:
            return (None, None, None)

        cache_key = str(file_path)
        if cache_key in file_cache:
            content, tree = file_cache[cache_key]
        else:
            try:
                tree = self._php_parser.parse(content)
            except Exception:
                return (None, None, None)
            file_cache[cache_key] = (content, tree)

        # Special-case: legacy "script" pseudo-method extracted from top-level statements.
        if method.name == "__script__":
            try:
                body = tree.root_node

                skip_subtrees = {
                    "class_declaration",
                    "interface_declaration",
                    "trait_declaration",
                    "method_declaration",
                    "function_definition",
                }

                cyclomatic = 1
                cognitive = 0
                max_nesting = 0

                def _binary_bool_ops(n) -> int:
                    if n.type != "binary_expression":
                        return 0
                    ops = 0
                    for ch in n.children:
                        if ch.is_named:
                            continue
                        op = content[ch.start_byte:ch.end_byte].decode("utf-8", errors="ignore").strip().lower()
                        if op in {"&&", "||", "and", "or", "xor"}:
                            ops += 1
                    return ops

                def _count_bool_ops(n) -> int:
                    if not n:
                        return 0
                    ops = 0
                    st = [n]
                    while st:
                        cur = st.pop()
                        ops += _binary_bool_ops(cur)
                        for ch in cur.children:
                            if ch.type in skip_subtrees:
                                continue
                            st.append(ch)
                    return ops

                def _walk(n, nesting: int) -> None:
                    nonlocal cyclomatic, cognitive, max_nesting
                    t = n.type
                    if t in skip_subtrees:
                        return

                    if t == "if_statement":
                        cyclomatic += 1
                        cognitive += 1 + nesting
                        max_nesting = max(max_nesting, nesting + 1)
                        cond = n.child_by_field_name("condition")
                        bops = _count_bool_ops(cond)
                        cyclomatic += bops
                        cognitive += bops

                        cons = n.child_by_field_name("consequence") or n.child_by_field_name("body")
                        if cons:
                            _walk(cons, nesting + 1)

                        for ch in n.children:
                            if ch.type == "elseif_clause":
                                cyclomatic += 1
                                cognitive += 1 + nesting
                                max_nesting = max(max_nesting, nesting + 1)
                                ccond = ch.child_by_field_name("condition")
                                cbops = _count_bool_ops(ccond)
                                cyclomatic += cbops
                                cognitive += cbops
                                ccons = ch.child_by_field_name("consequence") or ch.child_by_field_name("body")
                                if ccons:
                                    _walk(ccons, nesting + 1)
                            elif ch.type == "else_clause":
                                cognitive += 1 + nesting
                                max_nesting = max(max_nesting, nesting + 1)
                                econs = ch.child_by_field_name("consequence") or ch.child_by_field_name("body")
                                if econs:
                                    _walk(econs, nesting + 1)
                        return

                    loop_types = {"for_statement", "foreach_statement", "while_statement", "do_statement"}
                    if t in loop_types:
                        cyclomatic += 1
                        cognitive += 1 + nesting
                        max_nesting = max(max_nesting, nesting + 1)

                        # Count boolean ops in the loop condition (where available).
                        cond = n.child_by_field_name("condition")
                        bops = _count_bool_ops(cond)
                        cyclomatic += bops
                        cognitive += bops

                        body_n = n.child_by_field_name("body") or n.child_by_field_name("consequence")
                        if body_n:
                            _walk(body_n, nesting + 1)
                            return

                    if t == "switch_statement":
                        cyclomatic += 1
                        cognitive += 1 + nesting
                        max_nesting = max(max_nesting, nesting + 1)
                        # Cases will be counted separately.

                    if t == "case_statement":
                        cyclomatic += 1
                        cognitive += 1 + nesting
                        max_nesting = max(max_nesting, nesting + 1)

                    if t == "catch_clause":
                        cyclomatic += 1
                        cognitive += 1 + nesting
                        max_nesting = max(max_nesting, nesting + 1)

                    if t == "conditional_expression":
                        cyclomatic += 1
                        cognitive += 1 + nesting
                        max_nesting = max(max_nesting, nesting + 1)
                        cond = n.child_by_field_name("condition")
                        bops = _count_bool_ops(cond)
                        cyclomatic += bops
                        cognitive += bops

                    if t == "match_expression":
                        cyclomatic += 1
                        cognitive += 1 + nesting
                        max_nesting = max(max_nesting, nesting + 1)

                    for ch in n.children:
                        _walk(ch, nesting)

                _walk(body, 0)

                cognitive = max(cognitive, 1)
                return (cyclomatic, cognitive, max_nesting)
            except Exception:
                return (None, None, None)

        # Find the method/function node by name and line span.
        # We prefer a loose match on start line, since line_end can shift with formatting.
        try:
            import tree_sitter

            root_node = tree.root_node
            q = tree_sitter.Query(
                self._php_lang,
                """
                (method_declaration
                  name: (name) @method_name
                ) @method_def
                (function_definition
                  name: (name) @fn_name
                ) @fn_def
                """,
            )
            cur = tree_sitter.QueryCursor(q)
            raw = cur.captures(root_node)
            method_nodes = []
            if isinstance(raw, dict):
                method_nodes = []
                method_nodes.extend(raw.get("method_def", []) or [])
                method_nodes.extend(raw.get("fn_def", []) or [])
            else:
                for cap in raw:
                    node = cap[0]
                    tag = cap[-1]
                    if tag in {"method_def", "fn_def"}:
                        method_nodes.append(node)

            target = None
            for n in method_nodes:
                name_node = n.child_by_field_name("name")
                if not name_node:
                    continue
                name = content[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="ignore")
                if name != method.name:
                    continue
                start_line = n.start_point.row + 1
                if method.line_start and abs(start_line - method.line_start) <= 2:
                    target = n
                    break
            if not target:
                return (None, None, None)

            body = target.child_by_field_name("body")
            if not body:
                return (1, 1, 0)

            # Cognitive complexity (Sonar-like, simplified):
            # - +1 for each control structure
            # - +nesting for each control structure depending on nesting level
            # - boolean operators in conditions add cost
            cyclomatic = 1
            cognitive = 0
            max_nesting = 0

            skip_subtrees = {
                "class_declaration",
                "interface_declaration",
                "trait_declaration",
                "method_declaration",
                "function_definition",
            }

            def _binary_bool_ops(n) -> int:
                if n.type != "binary_expression":
                    return 0
                ops = 0
                for ch in n.children:
                    if ch.is_named:
                        continue
                    op = content[ch.start_byte:ch.end_byte].decode("utf-8", errors="ignore").strip().lower()
                    if op in {"&&", "||", "and", "or", "xor"}:
                        ops += 1
                return ops

            def _count_bool_ops(n) -> int:
                if not n:
                    return 0
                ops = 0
                st = [n]
                while st:
                    cur_n = st.pop()
                    ops += _binary_bool_ops(cur_n)
                    for ch in cur_n.children:
                        if ch.type in skip_subtrees:
                            continue
                        st.append(ch)
                return ops

            def _walk(n, nesting: int) -> None:
                nonlocal cyclomatic, cognitive, max_nesting
                t = n.type
                if t in skip_subtrees:
                    return

                if t == "if_statement":
                    cyclomatic += 1
                    cognitive += 1 + nesting
                    max_nesting = max(max_nesting, nesting + 1)

                    cond = n.child_by_field_name("condition")
                    bops = _count_bool_ops(cond)
                    cyclomatic += bops
                    cognitive += bops

                    cons = n.child_by_field_name("consequence") or n.child_by_field_name("body")
                    if cons:
                        _walk(cons, nesting + 1)

                    for ch in n.children:
                        if ch.type == "elseif_clause":
                            cyclomatic += 1
                            cognitive += 1 + nesting
                            max_nesting = max(max_nesting, nesting + 1)
                            ccond = ch.child_by_field_name("condition")
                            cbops = _count_bool_ops(ccond)
                            cyclomatic += cbops
                            cognitive += cbops
                            ccons = ch.child_by_field_name("consequence") or ch.child_by_field_name("body")
                            if ccons:
                                _walk(ccons, nesting + 1)
                        elif ch.type == "else_clause":
                            cognitive += 1 + nesting
                            max_nesting = max(max_nesting, nesting + 1)
                            econs = ch.child_by_field_name("consequence") or ch.child_by_field_name("body")
                            if econs:
                                _walk(econs, nesting + 1)
                    return

                loop_types = {"for_statement", "foreach_statement", "while_statement", "do_statement"}
                if t in loop_types:
                    cyclomatic += 1
                    cognitive += 1 + nesting
                    max_nesting = max(max_nesting, nesting + 1)

                    cond = n.child_by_field_name("condition")
                    bops = _count_bool_ops(cond)
                    cyclomatic += bops
                    cognitive += bops

                    body_n = n.child_by_field_name("body") or n.child_by_field_name("consequence")
                    if body_n:
                        _walk(body_n, nesting + 1)
                        return

                if t == "switch_statement":
                    cyclomatic += 1
                    cognitive += 1 + nesting
                    max_nesting = max(max_nesting, nesting + 1)

                if t == "case_statement":
                    cyclomatic += 1
                    cognitive += 1 + nesting
                    max_nesting = max(max_nesting, nesting + 1)

                if t == "catch_clause":
                    cyclomatic += 1
                    cognitive += 1 + nesting
                    max_nesting = max(max_nesting, nesting + 1)

                if t == "conditional_expression":
                    cyclomatic += 1
                    cognitive += 1 + nesting
                    max_nesting = max(max_nesting, nesting + 1)
                    cond = n.child_by_field_name("condition")
                    bops = _count_bool_ops(cond)
                    cyclomatic += bops
                    cognitive += bops

                if t == "match_expression":
                    cyclomatic += 1
                    cognitive += 1 + nesting
                    max_nesting = max(max_nesting, nesting + 1)

                for ch in n.children:
                    _walk(ch, nesting)

            _walk(body, 0)

            cognitive = max(cognitive, 1)
            return (cyclomatic, cognitive, max_nesting)
        except Exception:
            return (None, None, None)
