"""
Facts Builder

Extracts raw facts from source files using Tree-sitter AST parsing.
This module builds the Facts object that represents the codebase.
"""
import logging
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from dataclasses import dataclass, field
from typing import Generator
import fnmatch

from schemas.facts import (
    Facts, ClassInfo, MethodInfo, RouteInfo,
    QueryUsage, ValidationUsage, DuplicateBlock,
    StringLiteral, StringOccurrence, BladeQuery, BladeRawEcho, EnvUsage, ReactComponentInfo,
    RelationAccess, AssocArrayLiteral, ConfigUsage,
    UseImport, FqcnReference, ClassConstAccess,
)
from schemas.project_type import ProjectInfo
from core.path_utils import normalize_rel_path
from core.test_detection import count_test_files

logger = logging.getLogger(__name__)


@dataclass
class BuildProgress:
    """Progress tracking for facts building."""
    total_files: int = 0
    files_processed: int = 0
    current_file: str = ""
    errors: list[str] = field(default_factory=list)


class FactsBuilder:
    """
    Builds Facts from source code using AST parsing.
    
    This is the core analysis engine that extracts raw data:
    - Classes and methods
    - Call sites and imports
    - Routes, queries, validations
    - Duplicate code blocks
    - String literals (enum candidates)
    - React components
    """
    
    def __init__(
        self,
        project_info: ProjectInfo,
        ignore_patterns: list[str] | None = None,
        cancellation_check: callable = None,
        max_file_size_kb: int | None = None,
        max_files: int | None = None,
    ):
        self.project_info = project_info
        self.project_path = Path(project_info.root_path).resolve()
        # Always ignore well-known build/vendor dirs for safety, even if a user edits the ruleset
        # and accidentally removes them (scanning vendor/node_modules is both noisy and slow).
        mandatory_ignores = [
            "vendor/**",
            "node_modules/**",
            "storage/**",
            "bootstrap/cache/**",
            "bootstrap/ssr/**",
            "public/build/**",
            ".git/**",
            "*.min.js",
            "*.min.css",
            # Laravel seeders are often intentionally imperative/noisy and aren't representative
            # of app architecture quality.
            "database/seeders/**",
            "database/seeds/**",
            # Framework generated: migrations/factories are often noisy and don't reflect app architecture.
            "database/migrations/**",
            "database/factories/**",
        ]

        default_ignores = [
            *mandatory_ignores,
            "tests/**",
        ]

        raw = list(ignore_patterns) if ignore_patterns else default_ignores
        # Deduplicate while preserving order.
        seen: set[str] = set()
        merged: list[str] = []
        for p in [*raw, *mandatory_ignores]:
            if not p:
                continue
            if p in seen:
                continue
            seen.add(p)
            merged.append(p)
        self.ignore_patterns = merged
        self.cancellation_check = cancellation_check
        self.max_file_size_kb = int(max_file_size_kb) if max_file_size_kb is not None else 500
        self.max_files = int(max_files) if max_files is not None else 5000

        # Compile ignore patterns
        import pathspec
        self._ignore_spec = pathspec.PathSpec.from_lines("gitignore", self.ignore_patterns) or None
        
        # Tree-sitter parsers (thread-local lazy load)
        self._lock = threading.RLock()
        self._local = threading.local()
        
        # Build state
        self.progress = BuildProgress()
        self._facts = Facts(project_path=str(self.project_path))
        self._facts._frontend_symbol_graph = {"files": {}, "edges": []}

        # Project-level quality gate signals (do not depend on ignore globs).
        try:
            self._facts.has_tests = bool(getattr(self.project_info, "has_tests", False))
        except Exception:
            self._facts.has_tests = False
        self._facts.test_files_count = self._count_test_files()
        
        # Token hashing for duplicate detection.
        # hash -> [(file, start_line, end_line, snippet, token_count, method_key, start_token_idx)]
        self._token_hashes: dict[str, list[tuple[str, int, int, str, int, str, int]]] = {}

        # Phase 11: token-window based duplication (shingles/chunks) with per-file duplication percent.
        # We keep the stored values in `_token_hashes` but enrich occurrences with method+token offsets:
        #   (file, start_line, end_line, snippet, token_count, method_key, start_token_idx)
        self._dup_method_token_counts: dict[str, int] = {}  # method_key -> token_count
        self._dup_method_file: dict[str, str] = {}          # method_key -> file_path
        self._dup_chunk_size: int = 50
        self._dup_step: int = 25

    def _count_test_files(self) -> int:
        """Count test files across backend and frontend test conventions."""
        try:
            return count_test_files(self.project_path)
        except Exception:
            return 0
    
    def build(self, progress_callback: callable = None) -> Facts:
        """
        Build Facts from the codebase.
        
        Args:
            progress_callback: Optional callback(progress: BuildProgress) for updates
        
        Returns:
            Facts object with extracted data
        """
        # PHP extensions commonly found in legacy apps.
        php_exts = ["php", "inc", "phtml", "php3", "php4", "php5"]
        php_files: list[Path] = []
        for ext in php_exts:
            php_files.extend([p for p in self._find_files(f"**/*.{ext}") if not p.name.endswith(".blade.php")])

        # Expand JS/TS extensions manually as PathToken.glob doesn't support {}
        js_files: list[Path] = []
        for ext in ["js", "jsx", "ts", "tsx"]:
            js_files.extend(list(self._find_files(f"**/*.{ext}")))

        blade_files = list(self._find_files("**/*.blade.php"))
        aux_files: list[Path] = []
        for pattern in [
            "**/composer.json",
            "**/composer.lock",
            "**/package.json",
            "**/package-lock.json",
            "**/yarn.lock",
            "**/pnpm-lock.yaml",
            "**/pnpm-lock.yml",
        ]:
            aux_files.extend(list(self._find_files(pattern)))

        # Deduplicate (and apply max_files) deterministically.
        unique: dict[str, Path] = {}
        for p in [*php_files, *js_files, *blade_files, *aux_files]:
            try:
                unique[str(p.resolve())] = p
            except Exception:
                unique[str(p)] = p

        all_files = list(unique.values())
        all_files.sort(key=lambda p: str(p))

        if self.max_files and len(all_files) > self.max_files:
            logger.info(f"File cap reached: {len(all_files)} > {self.max_files}. Truncating.")
            all_files = all_files[: self.max_files]

        self.progress.total_files = len(all_files)
        logger.info(f"Found {self.progress.total_files} files to analyze")

        import os
        max_workers = min(32, (os.cpu_count() or 1) * 2)

        def _process_single_file(file_path: Path):
            if self._is_cancelled():
                return
            
            try:
                # Route to the correct handler.
                if file_path.name.endswith(".blade.php"):
                    self._process_blade_file(file_path)
                elif file_path.suffix.lower() in {".php", ".inc", ".phtml", ".php3", ".php4", ".php5"}:
                    self._process_php_file(file_path)
                elif self._is_auxiliary_scan_file(file_path):
                    self._process_auxiliary_file(file_path)
                else:
                    self._process_js_file(file_path)

                self._update_progress(file_path, progress_callback)
            except Exception as e:
                logger.error(f"Failed to process {file_path}: {e}")
                with self._lock:
                    self.progress.errors.append(f"{file_path}: {e}")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(_process_single_file, all_files)
        
        # Detect duplicates from collected tokens
        self._detect_duplicates()
        
        # Find enum candidates from string literals
        self._analyze_string_literals()
        
        logger.info(
            f"Built facts: {len(self._facts.classes)} classes, "
            f"{len(self._facts.methods)} methods, "
            f"{len(self._facts.routes)} routes"
        )
        
        return self._facts
    
    def _find_files(self, pattern: str) -> Generator[Path, None, None]:
        """Find files matching pattern, excluding ignored paths."""
        import os
        import fnmatch
        
        # Simple filename pattern from glob
        # e.g. "**/*.php" -> "*.php"
        file_pattern = pattern.split("/")[-1]
        
        for root, dirs, files in os.walk(str(self.project_path)):
            for filename in files:
                if fnmatch.fnmatch(filename, file_pattern):
                    path = Path(root) / filename
                    # Size cap (skip huge files to keep scans predictable).
                    try:
                        if self.max_file_size_kb and path.stat().st_size > (self.max_file_size_kb * 1024):
                            continue
                    except Exception:
                        continue
                    if not self._is_ignored(path):
                        yield path
    
    def _is_ignored(self, path: Path) -> bool:
        """Check if path matches any ignore pattern."""
        import os
        try:
            # Absolute normalization
            p_abs = os.path.abspath(path)
            root_abs = os.path.abspath(self.project_path)
            
            rel_path = os.path.relpath(p_abs, root_abs)
            rel_path = rel_path.replace("\\", "/")
            
            if rel_path.startswith(".."):
                return True # Outside project root
            
            if self._ignore_spec:
                return self._ignore_spec.match_file(rel_path)
        except Exception:
            return True # Safe default
            
        return False
    
    def _is_cancelled(self) -> bool:
        """Check if analysis was cancelled."""
        if self.cancellation_check:
            return self.cancellation_check()
        return False
    
    def _update_progress(self, file_path: Path, callback: callable):
        """Update progress and notify callback (thread-safe)."""
        with self._lock:
            self.progress.files_processed += 1
            self.progress.current_file = str(file_path)
            if callback:
                try:
                    callback(self.progress)
                except Exception:
                    pass
    
    def _get_file_hash(self, content: str) -> str:
        """Compute hash for file content."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _is_auxiliary_scan_file(self, file_path: Path) -> bool:
        """Files that are scanned for regex/security rules but not parsed structurally."""
        low = str(file_path.name or "").lower()
        return low in {
            "composer.json",
            "composer.lock",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "pnpm-lock.yml",
        }

    def _process_auxiliary_file(self, file_path: Path) -> None:
        """Register config and lock files for regex-based rules."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            file_hash = self._get_file_hash(content)
            rel_path = normalize_rel_path(str(file_path.relative_to(self.project_path)))
            with self._lock:
                if rel_path not in self._facts.files:
                    self._facts.files.append(rel_path)
                self._facts.file_hashes[rel_path] = file_hash
        except Exception as e:
            logger.warning(f"Error processing auxiliary file {file_path}: {e}")
            with self._lock:
                self.progress.errors.append(f"{file_path}: {e}")
    
    
    def _init_treesitter(self):
        """Initialize Tree-sitter parsers if available (thread-local)."""
        if hasattr(self._local, "php_parser"):
            return

        try:
            import tree_sitter
            import tree_sitter_php

            # Load PHP language
            self._local.php_lang = tree_sitter.Language(tree_sitter_php.language_php())
            self._local.php_parser = tree_sitter.Parser(self._local.php_lang)
            logger.info(f"Tree-sitter PHP parser initialized in thread {threading.get_ident()}")
        except ImportError:
            logger.warning("Tree-sitter not installed. Using regex fallback.")
            self._local.php_parser = None
        except Exception as e:
            logger.warning(f"Failed to initialize Tree-sitter: {e}")
            self._local.php_parser = None

    def _get_query(self, lang, query_str: str):
        """Get a cached Tree-sitter query (thread-local)."""
        if not hasattr(self._local, "query_cache"):
            self._local.query_cache = {}
        
        cache_key = (id(lang), query_str)
        if cache_key not in self._local.query_cache:
            import tree_sitter
            self._local.query_cache[cache_key] = tree_sitter.Query(lang, query_str)
        
        return self._local.query_cache[cache_key]

    def _get_treesitter_js(self, ext: str) -> tuple[object | None, object | None]:
        """Get a Tree-sitter parser/language for a JS/TS extension (thread-local)."""
        ext = (ext or "").lower().lstrip(".")
        if ext not in {"js", "jsx", "ts", "tsx"}:
            return (None, None)

        if not hasattr(self._local, "js_parsers"):
            self._local.js_parsers = {}
            self._local.js_langs = {}

        if ext in self._local.js_parsers and ext in self._local.js_langs:
            return (self._local.js_parsers[ext], self._local.js_langs[ext])

        try:
            import tree_sitter
        except Exception:
            return (None, None)

        try:
            if ext in {"js", "jsx"}:
                import tree_sitter_javascript
                lang = tree_sitter.Language(tree_sitter_javascript.language())
                parser = tree_sitter.Parser(lang)
            else:
                import tree_sitter_typescript
                lang_ptr = (
                    tree_sitter_typescript.language_tsx()
                    if ext == "tsx"
                    else tree_sitter_typescript.language_typescript()
                )
                lang = tree_sitter.Language(lang_ptr)
                parser = tree_sitter.Parser(lang)

            self._local.js_langs[ext] = lang
            self._local.js_parsers[ext] = parser
            return (parser, lang)
        except Exception:
            return (None, None)

    def _process_php_file(self, file_path: Path):
        """Process a PHP file and extract facts."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            file_hash = self._get_file_hash(content)
            rel_path = normalize_rel_path(str(file_path.relative_to(self.project_path)))

            # Track scanned files using relative paths for portability.
            with self._lock:
                if rel_path not in self._facts.files:
                    self._facts.files.append(rel_path)
                self._facts.file_hashes[rel_path] = file_hash

            # Detect direct env() usage (best practice: env() only in config files).
            if not rel_path.startswith("config/"):
                import re
                env_pat = re.compile(r"\benv\s*\(")
                env_hits = []
                for i, line in enumerate(content.splitlines(), start=1):
                    l = line.strip()
                    if not l or l.startswith("//") or l.startswith("#"):
                        continue
                    if env_pat.search(line):
                        env_hits.append(
                            EnvUsage(
                                file_path=rel_path,
                                line_number=i,
                                snippet=l[:200],
                            )
                        )
                if env_hits:
                    with self._lock:
                        self._facts.env_usages.extend(env_hits)
            
            # Lazy init parser
            self._init_treesitter()
            
            parsed = False

            # Tree-sitter is the primary parser.
            if self._local.php_parser:
                try:
                    self._parse_php_treesitter(rel_path, content, file_hash, rel_path, True)
                    parsed = True
                except Exception as e:
                    logger.error(f"Tree-sitter parsing failed for {rel_path}: {e}")

            # Fallback to regex parsing only if Tree-sitter is unavailable/failed.
            if not parsed:
                self._parse_php_basic(rel_path, content, file_hash, rel_path)

            # Supplemental heuristics (allowed) that don't compete with structural AST parsing.
            # These run in both Tree-sitter and fallback mode.
            if "routes/" in rel_path or "routes\\" in rel_path:
                self._extract_routes(rel_path, content)
            self._collect_string_literals(rel_path, content, content.split("\n"))
            
        except Exception as e:
            logger.warning(f"Error processing {file_path}: {e}")
            self.progress.errors.append(f"{file_path}: {e}")

    def _parse_php_treesitter(self, file_path: str, content: str, file_hash: str, rel_path: str, is_ts: bool = False):
        """Parse PHP using Tree-sitter."""
        import tree_sitter
        
        content_bytes = bytes(content, "utf8")
        tree = self._local.php_parser.parse(content_bytes)
        root_node = tree.root_node
        
        # --- 1. Basic Queries ---
        
        # Namespace
        ns_query = self._get_query(self._local.php_lang, "(namespace_definition (namespace_name) @ns)")
        ns_cursor = tree_sitter.QueryCursor(ns_query)
        raw_captures = ns_cursor.captures(root_node)
        ns_caps = self._get_caps_dict(raw_captures)
        
        namespace = ns_caps["ns"][0].text.decode("utf8") if "ns" in ns_caps else ""
        try:
            # Store per-file namespace (raw, no derived logic).
            self._facts.php_namespaces[file_path] = namespace
        except Exception:
            pass

        # --- 1.1 Imports + FQCN references (AST-only) ---
        # These facts are consumed by rules; rules must not re-parse files or read the filesystem.
        try:
            def _has_ancestor(node, types: set[str]) -> bool:
                cur = node
                while cur is not None:
                    if cur.type in types:
                        return True
                    cur = getattr(cur, "parent", None)
                return False

            # Extract top-level `use` imports (namespace imports, not trait `use` inside classes).
            use_query = self._get_query(self._local.php_lang, "(namespace_use_declaration) @use_decl")
            use_cursor = tree_sitter.QueryCursor(use_query)
            use_caps = self._get_caps_dict(use_cursor.captures(root_node))

            for use_node in use_caps.get("use_decl", []) or []:
                use_line = use_node.start_point.row + 1

                # Group use: `use App\\Foo\\{Bar, Baz as Qux};`
                group_node = next((c for c in use_node.children if c.type == "namespace_use_group"), None)
                if group_node is not None:
                    prefix_node = next((c for c in use_node.children if c.type == "namespace_name"), None)
                    prefix = prefix_node.text.decode("utf8").lstrip("\\") if prefix_node else ""
                    for clause in group_node.children:
                        if clause.type != "namespace_use_clause":
                            continue
                        names = [c for c in clause.children if c.type == "name"]
                        if not names:
                            continue
                        sym = names[0].text.decode("utf8")
                        alias = names[1].text.decode("utf8") if len(names) > 1 else None
                        fqcn = f"{prefix}\\{sym}" if prefix else sym
                        fqcn = fqcn.lstrip("\\")
                        if not fqcn:
                            continue
                        self._facts.use_imports.append(
                            UseImport(
                                file_path=file_path,
                                line_number=use_line,
                                fqcn=fqcn,
                                alias=alias,
                                import_type="class",
                            )
                        )
                    continue

                # Simple use: `use App\\Foo\\Bar;` or `use App\\Foo\\Bar as Baz;`
                for clause in use_node.children:
                    if clause.type != "namespace_use_clause":
                        continue

                    qn = next((c for c in clause.children if c.type == "qualified_name"), None)
                    if qn is None:
                        continue

                    fqcn = qn.text.decode("utf8").lstrip("\\")
                    if not fqcn:
                        continue

                    # Alias is a direct `name` child on the clause (outside the qualified_name).
                    alias = None
                    for ch in clause.children:
                        if ch.type == "name" and ch.start_byte >= qn.end_byte:
                            alias = ch.text.decode("utf8")

                    self._facts.use_imports.append(
                        UseImport(
                            file_path=file_path,
                            line_number=use_line,
                            fqcn=fqcn,
                            alias=alias,
                            import_type="class",
                        )
                    )

            # Extract fully-qualified class references: any `qualified_name` starting with "\".
            # We keep this broad and let rules apply namespace/root filters.
            qn_query = self._get_query(self._local.php_lang, "(qualified_name) @qname")
            qn_cursor = tree_sitter.QueryCursor(qn_query)
            qn_caps = self._get_caps_dict(qn_cursor.captures(root_node))

            interesting_parent_kinds: dict[str, str] = {
                "object_creation_expression": "new",
                "scoped_call_expression": "static_call",
                "class_constant_access_expression": "class_const",
                "named_type": "type",
            }
            snippet_parent_types: set[str] = set(interesting_parent_kinds.keys())

            for qn in qn_caps.get("qname", []) or []:
                raw = qn.text.decode("utf8")
                if not raw.startswith("\\"):
                    continue

                # Skip fully qualified names in `use` import declarations.
                if _has_ancestor(qn, {"namespace_use_declaration", "namespace_use_clause", "namespace_use_group"}):
                    continue

                fqcn = raw.lstrip("\\")
                if not fqcn:
                    continue

                parent = getattr(qn, "parent", None)
                kind = interesting_parent_kinds.get(getattr(parent, "type", ""), "other")

                snippet_node = parent if parent is not None and parent.type in snippet_parent_types else qn
                try:
                    snippet = content_bytes[snippet_node.start_byte : snippet_node.end_byte].decode("utf8", errors="replace")
                except Exception:
                    snippet = raw
                snippet = " ".join((snippet or "").strip().split())
                if len(snippet) > 200:
                    snippet = snippet[:197] + "..."

                self._facts.fqcn_references.append(
                    FqcnReference(
                        file_path=file_path,
                        line_number=qn.start_point.row + 1,
                        fqcn=fqcn,
                        raw=raw,
                        kind=kind,
                        snippet=snippet,
                    )
                )
        except Exception:
            # Imports/FQCN references are "nice to have" for readability rules; keep core parsing resilient.
            pass

        # --- 1.2 Class constant access expressions (AST-only) ---
        # Service provider binding maps often reference concrete classes only via `Foo::class`
        # inside class constants/properties (outside of method bodies). This fact helps dead-code
        # heuristics avoid false positives.
        try:
            cc_query = self._get_query(
                self._local.php_lang,
                "(class_constant_access_expression) @cc",
            )
            cc_cursor = tree_sitter.QueryCursor(cc_query)
            cc_caps = self._get_caps_dict(cc_cursor.captures(root_node))
            for node in cc_caps.get("cc", []) or []:
                raw = node.text.decode("utf8", errors="replace")
                s = " ".join((raw or "").strip().split())
                # Keep only `::class` expressions (avoid noise from other constants).
                if not s.endswith("::class"):
                    continue
                if len(s) > 200:
                    s = s[:197] + "..."
                self._facts.class_const_accesses.append(
                    ClassConstAccess(
                        file_path=file_path,
                        line_number=node.start_point.row + 1,
                        expression=s,
                    )
                )
        except Exception:
            pass
        
        # Classes
        class_query = self._get_query(self._local.php_lang, """
            (class_declaration 
                name: (name) @class_name
                (base_clause (qualified_name) @parent)?
                (class_interface_clause (qualified_name) @implements)?
            )
        """)

        # Top-level functions (legacy / non-OO codebases)
        func_query = self._get_query(
            self._local.php_lang,
            """
            (function_definition
              name: (name) @fn_name
              parameters: (formal_parameters) @params
            ) @fn_def
            """,
        )
        
        # Methods
        method_query = self._get_query(self._local.php_lang, """
            (method_declaration
                (visibility_modifier)? @visibility
                name: (name) @method_name
                parameters: (formal_parameters) @params
            ) @method_def
        """)
        
        class_cursor = tree_sitter.QueryCursor(class_query)
        raw_captures = class_cursor.captures(root_node)
        class_caps = self._get_caps_dict(raw_captures)
        
        if "class_name" in class_caps:
            for name_node in class_caps["class_name"]:
                node = name_node.parent # class_declaration
                class_name = name_node.text.decode("utf8")
                
                # Extract parent/implements from children manually
                parent = ""
                implements = []
                is_abstract = False
                is_final = False
                
                # Scan children for base/interfaces/modifiers
                for child in node.children:
                    if child.type == "base_clause":
                        # child 0 is 'extends', child 1 is the name
                        if child.child_count > 1:
                            parent = child.child(1).text.decode("utf8")
                    elif child.type == "class_interface_clause":
                        # implementations list - use 'name' nodes, not 'qualified_name'
                        implements = [c.text.decode("utf8") for c in child.children if c.type == "name"]
                    elif child.type == "abstract_modifier":
                        is_abstract = True
                    elif child.type == "final_modifier":
                        is_final = True

                fqcn = f"{namespace}\\{class_name}" if namespace else class_name
                is_controller = "Controller" in class_name or "Controller" in parent
                is_model = parent in ["Model", "Eloquent"] or "Model" in file_path

                # Location (1-based line numbers)
                cls_line_start = node.start_point.row + 1
                cls_line_end = node.end_point.row + 1
                
                class_info = ClassInfo(
                    name=class_name,
                    namespace=namespace,
                    fqcn=fqcn,
                    file_path=file_path,
                    file_hash=file_hash,
                    extends=parent,
                    implements=implements,
                    is_abstract=is_abstract,
                    is_final=is_final,
                    is_controller=is_controller,
                    is_model=is_model,
                    line_start=cls_line_start,
                    line_end=cls_line_end,
                )
                
                self._facts.classes.append(class_info)
                if is_controller: self._facts.controllers.append(class_info)
                elif is_model: self._facts.models.append(class_info)
                
                # Simplify: Iterate children of class body
                class_body = next((c for c in node.children if c.type == "declaration_list"), None)
                if class_body:
                    for member in class_body.children:
                        if member.type == "method_declaration":
                             self._extract_ts_method(member, class_info, content)

        # Extract top-level functions (not class methods).
        try:
            func_cursor = tree_sitter.QueryCursor(func_query)
            func_caps = self._get_caps_dict(func_cursor.captures(root_node))
            for fn_node in func_caps.get("fn_def", []):
                self._extract_ts_function(fn_node, namespace, file_path, file_hash, content)
        except Exception:
            pass

        # For legacy PHP projects, also treat top-level "script" code as a pseudo-method so
        # we can compute complexity/LOC and produce actionable findings.
        try:
            pt = getattr(getattr(self.project_info, "project_type", None), "value", "")
            if pt in {"native_php", "php_mvc"}:
                self._extract_ts_script(root_node, namespace, file_path, file_hash, content)
        except Exception:
            pass

    def _extract_calls_from_node(self, body_node, content: str) -> tuple[list[str], list[str], list[str]]:
        """Extract call sites/instantiations/throws from a Tree-sitter node (body)."""
        import tree_sitter

        calls: list[str] = []
        instantiations: list[str] = []
        throws: list[str] = []

        try:
            call_query = self._get_query(
                self._local.php_lang,
                """
                (member_call_expression) @member_call
                (scoped_call_expression) @scoped_call
                (function_call_expression) @function_call
                (class_constant_access_expression (qualified_name) @class_const)
                (class_constant_access_expression (name) @class_const_simple)
                (object_creation_expression (qualified_name) @class)
                (object_creation_expression (name) @class_simple)
                (throw_expression (object_creation_expression (qualified_name) @exception))
                (throw_expression (object_creation_expression (name) @exception_simple))
                """,
            )
            call_cursor = tree_sitter.QueryCursor(call_query)
            raw_captures = call_cursor.captures(body_node)
            call_caps = self._get_caps_dict(raw_captures)

            if "member_call" in call_caps:
                calls.extend([n.text.decode("utf8") for n in call_caps["member_call"]])
            if "scoped_call" in call_caps:
                calls.extend([n.text.decode("utf8") for n in call_caps["scoped_call"]])
            if "function_call" in call_caps:
                calls.extend([n.text.decode("utf8") for n in call_caps["function_call"]])
            # Capture `Foo::class` and other class constant access expressions, since container bindings
            # and route/controller wiring often use these without an invocation. CallGraphIndex will
            # mine `Class::` references from these strings.
            if "class_const" in call_caps:
                calls.extend([n.text.decode("utf8") for n in call_caps["class_const"]])
            if "class_const_simple" in call_caps:
                calls.extend([n.text.decode("utf8") for n in call_caps["class_const_simple"]])
            if "class" in call_caps:
                instantiations.extend([n.text.decode("utf8") for n in call_caps["class"]])
            if "class_simple" in call_caps:
                instantiations.extend([n.text.decode("utf8") for n in call_caps["class_simple"]])
            if "exception" in call_caps:
                throws.extend([n.text.decode("utf8") for n in call_caps["exception"]])
            if "exception_simple" in call_caps:
                throws.extend([n.text.decode("utf8") for n in call_caps["exception_simple"]])
        except Exception:
            return ([], [], [])

        # Deduplicate deterministically.
        def _uniq(xs: list[str]) -> list[str]:
            seen: set[str] = set()
            out: list[str] = []
            for x in xs:
                if x in seen:
                    continue
                seen.add(x)
                out.append(x)
            return out

        return (_uniq(calls), _uniq(instantiations), _uniq(throws))

    def _extract_ts_function(self, fn_node, namespace: str, file_path: str, file_hash: str, content: str) -> None:
        """Extract a top-level function as a pseudo MethodInfo for legacy projects."""
        name_node = fn_node.child_by_field_name("name")
        if not name_node:
            return

        fn_name = name_node.text.decode("utf8")
        params_node = fn_node.child_by_field_name("parameters")
        params: list[str] = []
        if params_node:
            params = [p.text.decode("utf8") for p in params_node.children if "parameter" in p.type]

        start_line = fn_node.start_point.row + 1
        end_line = fn_node.end_point.row + 1
        loc = max(0, end_line - start_line + 1)

        body_node = fn_node.child_by_field_name("body")
        calls, instantiations, throws = ([], [], [])
        if body_node:
            calls, instantiations, throws = self._extract_calls_from_node(body_node, content)

        # Encode namespace into class_name so method_fqn is stable and disambiguated.
        cls = f"{namespace}\\<function>" if namespace else "<function>"

        self._facts.methods.append(
            MethodInfo(
                name=fn_name,
                class_name=cls,
                class_fqcn=None,
                file_path=file_path,
                file_hash=file_hash,
                parameters=params,
                visibility="public",
                line_start=start_line,
                line_end=end_line,
                loc=loc,
                call_sites=calls,
                instantiations=instantiations,
                throws=throws,
            )
        )

    def _extract_ts_script(self, root_node, namespace: str, file_path: str, file_hash: str, content: str) -> None:
        """Extract top-level script statements as a pseudo MethodInfo (legacy PHP)."""
        # Only consider named nodes that are not declarations.
        skip = {
            "php_tag",
            "namespace_definition",
            "use_declaration",
            "class_declaration",
            "interface_declaration",
            "trait_declaration",
            "function_definition",
            "comment",
        }

        script_nodes = [c for c in root_node.children if c.is_named and c.type not in skip]
        if not script_nodes:
            return

        start_line = min(n.start_point.row for n in script_nodes) + 1
        end_line = max(n.end_point.row for n in script_nodes) + 1
        loc = max(0, end_line - start_line + 1)

        calls: list[str] = []
        instantiations: list[str] = []
        throws: list[str] = []
        for n in script_nodes:
            c, i, t = self._extract_calls_from_node(n, content)
            calls.extend(c)
            instantiations.extend(i)
            throws.extend(t)

        # De-dupe while preserving order.
        def _uniq(xs: list[str]) -> list[str]:
            seen: set[str] = set()
            out: list[str] = []
            for x in xs:
                if x in seen:
                    continue
                seen.add(x)
                out.append(x)
            return out

        calls = _uniq(calls)
        instantiations = _uniq(instantiations)
        throws = _uniq(throws)

        # Use the file path as "class_name" so method_fqn uniquely identifies the script block.
        self._facts.methods.append(
            MethodInfo(
                name="__script__",
                class_name=file_path,
                class_fqcn=None,
                file_path=file_path,
                file_hash=file_hash,
                parameters=[],
                visibility="public",
                line_start=start_line,
                line_end=end_line,
                loc=loc,
                call_sites=calls,
                instantiations=instantiations,
                throws=throws,
            )
        )

    def _extract_ts_method(self, method_node, class_info, content):
        """Extract method details from Tree-sitter node."""
        import tree_sitter
        
        name_node = method_node.child_by_field_name("name")
        if not name_node: return
        
        method_name = name_node.text.decode("utf8")
        
        # Visibility
        visibility = "public"
        for child in method_node.children:
            # Tree-sitter PHP represents visibility as a `visibility_modifier` node,
            # not a direct "private"/"protected"/"public" child.
            if child.type == "visibility_modifier":
                vis = child.text.decode("utf8").strip().lower()
                if "private" in vis:
                    visibility = "private"
                elif "protected" in vis:
                    visibility = "protected"
                elif "public" in vis:
                    visibility = "public"
                break
                
        # Location
        start_line = method_node.start_point.row + 1
        end_line = method_node.end_point.row + 1
        
        method_body_node = method_node.child_by_field_name("body")
        method_body = method_body_node.text.decode("utf8") if method_body_node else ""
        
        # Params (simplified)
        params_node = method_node.child_by_field_name("parameters")
        params = []
        if params_node:
            # child(0) is '(', last is ')', others are params separated by ','
            params = [p.text.decode("utf8") for p in params_node.children if "parameter" in p.type]

        # Call sites
        calls = []
        instantiations = []
        throws = []
        
        if method_body_node:
            # Capture *expressions* (not just names) so downstream heuristics can match
            # patterns like "->get(", "DB::table(", "$request->validate(", etc.
            call_query = self._get_query(
                self._local.php_lang,
                """
                (member_call_expression) @member_call
                (scoped_call_expression) @scoped_call
                (function_call_expression) @function_call
                (object_creation_expression (qualified_name) @class)
                (object_creation_expression (name) @class_simple)
                (throw_expression (object_creation_expression (qualified_name) @exception))
                (throw_expression (object_creation_expression (name) @exception_simple))
                """,
            )
            
            call_cursor = tree_sitter.QueryCursor(call_query)
            raw_captures = call_cursor.captures(method_body_node)
            call_caps = self._get_caps_dict(raw_captures)
            
            if "member_call" in call_caps:
                calls.extend([n.text.decode("utf8") for n in call_caps["member_call"]])
            if "scoped_call" in call_caps:
                calls.extend([n.text.decode("utf8") for n in call_caps["scoped_call"]])
            if "function_call" in call_caps:
                calls.extend([n.text.decode("utf8") for n in call_caps["function_call"]])
            if "class" in call_caps:
                instantiations.extend([n.text.decode("utf8") for n in call_caps["class"]])
            if "class_simple" in call_caps:
                instantiations.extend([n.text.decode("utf8") for n in call_caps["class_simple"]])
            if "exception" in call_caps:
                throws.extend([n.text.decode("utf8") for n in call_caps["exception"]])
            if "exception_simple" in call_caps:
                throws.extend([n.text.decode("utf8") for n in call_caps["exception_simple"]])
                
        method_fqn = f"{class_info.fqcn}::{method_name}"

        method_info = MethodInfo(
            name=method_name,
            class_name=class_info.name,
            class_fqcn=class_info.fqcn,
            namespace=class_info.namespace,
            file_path=class_info.file_path,
            file_hash=class_info.file_hash,
            method_fqn=method_fqn,
            visibility=visibility,
            line_start=start_line,
            line_end=end_line,
            loc=end_line - start_line + 1,
            parameters=params,
            call_sites=calls,
            instantiations=instantiations,
            throws=throws,
            imports=[], # TODO: resolve imports if needed
        )
        
        self._facts.methods.append(method_info)
        
        if method_body_node:
            # Validation extraction is AST-first (regex is fallback only).
            self._extract_validations_ts(class_info.file_path, method_name, method_body_node, content, start_line, class_info.fqcn)

            # Query extraction (AST-first).
            self._extract_queries_ts(class_info.file_path, method_name, method_body_node, content, start_line)

            # N+1 relation access detection (AST-first).
            self._extract_relation_accesses_ts(class_info.file_path, method_name, method_body_node, content, start_line, class_info.fqcn)

            # Large associative arrays (AST-first; supports DTO suggestion).
            self._extract_assoc_arrays_ts(class_info.file_path, method_name, method_body_node, content, start_line, class_info.fqcn)

            # config() calls (performance smell when used inside loops).
            self._extract_config_usages_ts(class_info.file_path, method_name, method_body_node, content, start_line, class_info.fqcn)

            # Token-based duplicate candidate from AST.
            self._collect_duplicate_candidate_ts(class_info.file_path, start_line, end_line, method_body_node, content)
        elif method_body:
            # Tree-sitter missing body node (rare). Fallback to regex extraction.
            if "validate" in method_body:
                self._extract_validation(class_info.file_path, method_name, method_body, start_line)
    
    def _get_caps_dict(self, captures) -> dict[str, list]:
        """Convert tree-sitter captures (list or dict) to a dictionary of lists."""
        if isinstance(captures, dict):
            return captures
        caps = {}
        for item in captures:
            # Handle both (node, tag) and (node, tag_index, tag_name) formats
            node = item[0]
            tag = item[-1] # Usually tag name is last
            if not isinstance(tag, str): # Fallback for index
                tag = str(tag)
            if tag not in caps:
                caps[tag] = []
            caps[tag].append(node)
        return caps

    def _parse_php_basic(self, file_path: str, content: str, file_hash: str, rel_path: str):
        """Basic regex-based PHP parsing (fallback for Tree-sitter)."""
        import re
        
        lines = content.split("\n")
        
        # Detect namespace
        namespace_match = re.search(r"namespace\s+([\w\\]+);", content)
        namespace = namespace_match.group(1) if namespace_match else ""
        
        # Detect class
        class_match = re.search(
            r"class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w,\s]+))?",
            content
        )
        
        if class_match:
            class_name = class_match.group(1)
            parent = class_match.group(2) or ""
            implements = class_match.group(3) or ""
            interfaces = [i.strip() for i in implements.split(",")] if implements else []
            
            # Determine class type
            is_controller = "Controller" in class_name or "Controller" in parent
            is_model = parent in ["Model", "Eloquent"] or "Model" in file_path
            
            fqcn = f"{namespace}\\{class_name}" if namespace else class_name

            # Approximate class location by matching braces.
            cls_line_start = content[:class_match.start()].count("\n") + 1
            cls_line_end = cls_line_start
            try:
                open_brace = content.find("{", class_match.end())
                if open_brace != -1:
                    depth = 0
                    end_idx = None
                    for i in range(open_brace, len(content)):
                        ch = content[i]
                        if ch == "{":
                            depth += 1
                        elif ch == "}":
                            depth -= 1
                            if depth == 0:
                                end_idx = i
                                break
                    if end_idx is not None:
                        cls_line_end = content[: end_idx + 1].count("\n") + 1
            except Exception:
                pass
            
            class_info = ClassInfo(
                name=class_name,
                namespace=namespace,
                fqcn=fqcn,
                file_path=file_path,
                file_hash=file_hash,
                extends=parent,
                implements=interfaces,
                is_controller=is_controller,
                is_model=is_model,
                line_start=cls_line_start,
                line_end=cls_line_end,
            )
            
            self._facts.classes.append(class_info)
            
            if is_controller:
                self._facts.controllers.append(class_info)
            elif is_model:
                self._facts.models.append(class_info)
            
            # Find methods
            method_pattern = re.compile(
                r"(public|protected|private)\s+function\s+(\w+)\s*\(([^)]*)\)",
                re.MULTILINE
            )
            
            for match in method_pattern.finditer(content):
                visibility = match.group(1)
                method_name = match.group(2)
                params = match.group(3)
                
                # Find method location
                method_start = content[:match.start()].count("\n") + 1

                # Extract method body by matching braces from the first "{" after the signature.
                sig_end = match.end()
                open_brace = content.find("{", sig_end)
                close_brace = None
                if open_brace != -1:
                    depth = 0
                    for i in range(open_brace, len(content)):
                        ch = content[i]
                        if ch == "{":
                            depth += 1
                        elif ch == "}":
                            depth -= 1
                            if depth == 0:
                                close_brace = i
                                break
                if close_brace is None:
                    # Fallback: take a best-effort slice.
                    close_brace = min(len(content) - 1, sig_end + 2000)

                method_body = content[match.start() : close_brace + 1]
                method_end = content[: close_brace + 1].count("\n") + 1
                
                # Find call sites
                # Matches: $var->method(, Class::method(, ->method(
                call_pattern = re.compile(r"(?:\$\w+|(?:\w+::\w+)|->)\s*\w+\s*\(")
                call_sites = [m.group(0).strip() for m in call_pattern.finditer(method_body)]
                
                # Find imports used (simplified)
                imports = []
                use_pattern = re.compile(r"use\s+([\w\\]+);")
                for use_match in use_pattern.finditer(content[:match.start()]):
                    imports.append(use_match.group(1))

                # Find instantiations (new ClassName)
                instantiation_pattern = re.compile(r"new\s+([\w\\]+)")
                instantiations = [m.group(1) for m in instantiation_pattern.finditer(method_body)]
                
                # Find throw statements (throw new ClassName)
                throw_pattern = re.compile(r"throw\s+new\s+([\w\\]+)")
                throws = [m.group(1) for m in throw_pattern.finditer(method_body)]
                
                method_fqn = f"{namespace}\\{class_name}::{method_name}" if namespace else f"{class_name}::{method_name}"
                
                method_info = MethodInfo(
                    name=method_name,
                    class_name=class_name,
                    class_fqcn=f"{namespace}\\{class_name}" if namespace else class_name,
                    namespace=namespace,
                    file_path=file_path,
                    file_hash=file_hash,
                    method_fqn=method_fqn,
                    visibility=visibility,
                    line_start=method_start,
                    line_end=method_end,
                    loc=method_end - method_start + 1,
                    parameters=[p.strip() for p in params.split(",") if p.strip()],
                    return_type="",  # Would need more parsing
                    call_sites=call_sites,
                    instantiations=instantiations,
                    throws=throws,
                    imports=imports,
                )
                
                self._facts.methods.append(method_info)
                
                # Detect validations
                if "validate(" in method_body or "validated(" in method_body:
                    self._extract_validation(file_path, method_name, method_body, method_start)
                
                # Detect query patterns
                if any(p in method_body for p in ["::where", "::find", "::all", "->get(", "->first("]):
                    self._extract_queries(file_path, method_name, method_body, method_start)

                self._collect_duplicate_candidate(file_path, method_start, method_end, method_body)
        
        # Check for routes file
        if "routes/" in rel_path or "routes\\" in rel_path:
            self._extract_routes(file_path, content)
        
        # Collect string literals
        self._collect_string_literals(file_path, content, lines)
    
    def _extract_validation(self, file_path: str, method_name: str, body: str, line_num: int):
        """Extract validation rules from method body."""
        import re
        
        # Find validate() calls with rules
        validate_match = re.search(r"validate\s*\(\s*\[([^\]]+)\]", body, re.DOTALL)
        if validate_match:
            rules_str = validate_match.group(1)
            
            # Parse rules (simplified)
            rules = {}
            rule_pattern = re.compile(r"['\"](\w+)['\"]\s*=>\s*['\"]([^'\"]+)['\"]")
            for match in rule_pattern.finditer(rules_str):
                field = match.group(1)
                rule_list = match.group(2).split("|")
                rules[field] = rule_list
            
            if rules:
                validation = ValidationUsage(
                    file_path=file_path,
                    method_name=method_name,
                    line_number=line_num,
                    validation_type="inline",
                    rules=rules,
                )
                self._facts.validations.append(validation)

        # Validator::make($data, [...]) (legacy/fallback mode)
        make_match = re.search(r"Validator::make\s*\(\s*[^,]+,\s*\[([^\]]+)\]", body, re.DOTALL)
        if make_match:
            rules_str = make_match.group(1)
            rules = {}
            rule_pattern = re.compile(r"['\"](\w+)['\"]\s*=>\s*['\"]([^'\"]+)['\"]")
            for match in rule_pattern.finditer(rules_str):
                field = match.group(1)
                rule_list = match.group(2).split("|")
                rules[field] = rule_list
            self._facts.validations.append(
                ValidationUsage(
                    file_path=file_path,
                    method_name=method_name,
                    line_number=line_num,
                    validation_type="validator_make",
                    rules=rules,
                )
            )

    def _extract_validations_ts(
        self,
        file_path: str,
        method_name: str,
        method_body_node,
        content: str,
        method_start_line: int,
        class_fqcn: str | None = None,
    ) -> None:
        """Tree-sitter-based validation extraction (primary)."""
        import tree_sitter

        if not self._local.php_lang:
            return

        q = self._get_query(
            self._local.php_lang,
            """
            (member_call_expression) @member
            (scoped_call_expression) @scoped
            (function_call_expression) @fn
            """,
        )
        cur = tree_sitter.QueryCursor(q)
        caps = self._get_caps_dict(cur.captures(method_body_node))

        def _line(node) -> int:
            return method_start_line + content[method_body_node.start_byte:node.start_byte].count("\n")

        def _decode(node) -> str:
            return content[node.start_byte:node.end_byte]

        def _strip_quotes(s: str) -> str:
            s = s.strip()
            if len(s) >= 2 and ((s[0] == s[-1] == "'") or (s[0] == s[-1] == '"')):
                return s[1:-1]
            return s

        def _parse_rules_from_array_node(arr_node) -> dict[str, list[str]]:
            # Extract simple string-based Laravel rules from an associative array.
            rules: dict[str, list[str]] = {}
            if not arr_node or arr_node.type != "array_creation_expression":
                return rules

            for init in arr_node.children:
                if not init.is_named or init.type != "array_element_initializer":
                    continue

                init_txt = _decode(init)
                if "=>" not in init_txt:
                    continue

                named = [c for c in init.children if c.is_named]
                if len(named) < 2:
                    continue

                key_node = named[0]
                val_node = named[-1]
                key_txt = _strip_quotes(_decode(key_node))
                if not key_txt:
                    continue

                vals: list[str] = []
                if val_node.type in {"string", "encapsed_string"}:
                    raw = _strip_quotes(_decode(val_node))
                    if raw:
                        vals = [p.strip() for p in raw.split("|") if p.strip()]
                elif val_node.type == "array_creation_expression":
                    for inner in val_node.children:
                        if not inner.is_named or inner.type != "array_element_initializer":
                            continue
                        inner_named = [c for c in inner.children if c.is_named]
                        if not inner_named:
                            continue
                        v = inner_named[-1]
                        if v.type in {"string", "encapsed_string"}:
                            raw = _strip_quotes(_decode(v))
                            if raw:
                                vals.append(raw)
                if vals:
                    rules[key_txt] = vals

            return rules

        seen: set[tuple[int, str]] = set()

        # 1) $request->validate([...]) / request()->validate([...])
        for node in caps.get("member", []):
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            if _decode(name_node) != "validate":
                continue

            args_node = node.child_by_field_name("arguments")
            rules: dict[str, list[str]] = {}
            if args_node:
                # Find first array argument (best effort).
                arr_node = None
                for ch in args_node.children:
                    if ch.is_named and ch.type == "argument":
                        if ch.child_count:
                            cand = next((c for c in ch.children if c.is_named), None)
                            if cand and cand.type == "array_creation_expression":
                                arr_node = cand
                                break
                rules = _parse_rules_from_array_node(arr_node)

            line_no = _line(node)
            key = (line_no, "inline")
            if key in seen:
                continue
            seen.add(key)

            self._facts.validations.append(
                ValidationUsage(
                    file_path=file_path,
                    method_name=method_name,
                    line_number=line_no,
                    validation_type="inline",
                    rules=rules,
                    form_request_class=None,
                )
            )

        # 2) Validator::make($data, [...])
        for node in caps.get("scoped", []):
            scope_node = node.child_by_field_name("scope")
            name_node = node.child_by_field_name("name")
            if not scope_node or not name_node:
                continue
            if _decode(scope_node) != "Validator":
                continue
            if _decode(name_node) != "make":
                continue

            args_node = node.child_by_field_name("arguments")
            rules: dict[str, list[str]] = {}
            if args_node:
                # Validator::make($data, $rules) => second arg
                args = [ch for ch in args_node.children if ch.is_named and ch.type == "argument"]
                if len(args) >= 2:
                    second = args[1]
                    cand = next((c for c in second.children if c.is_named), None)
                    if cand and cand.type == "array_creation_expression":
                        rules = _parse_rules_from_array_node(cand)

            line_no = _line(node)
            key = (line_no, "validator_make")
            if key in seen:
                continue
            seen.add(key)

            self._facts.validations.append(
                ValidationUsage(
                    file_path=file_path,
                    method_name=method_name,
                    line_number=line_no,
                    validation_type="validator_make",
                    rules=rules,
                    form_request_class=None,
                )
            )
    
    def _extract_queries(self, file_path: str, method_name: str, body: str, line_num: int):
        """Extract database query patterns into QueryUsage facts."""
        import re

        seen: set[tuple[int, str, str | None]] = set()

        # Start-points for queries (we'll infer the method chain from the statement).
        start_patterns: list[tuple[re.Pattern[str], str | None]] = [
            (re.compile(r"(?P<model>(?!DB\b)[A-Z]\w*)::(?P<meth>where|find|all|query|with|first|get|paginate|pluck|count|exists|create|update|delete)\s*\(", re.IGNORECASE), "model"),
            (re.compile(r"DB::(?P<meth>table|select|statement|raw)\s*\(", re.IGNORECASE), None),
        ]

        def _statement_slice(start_idx: int) -> str:
            # Best-effort: grab to semicolon, else to line break.
            semi = body.find(";", start_idx)
            if semi != -1:
                return body[start_idx : semi + 1]
            nl = body.find("\n", start_idx)
            if nl != -1:
                return body[start_idx : nl]
            return body[start_idx:]

        for pat, model_group in start_patterns:
            for m in pat.finditer(body):
                start = m.start()
                snippet = _statement_slice(start)

                # Loop context heuristic (for N+1 risk).
                before = body[:start].lower()
                in_loop = any(kw in before for kw in ["foreach", "for", "while", "@foreach"])

                chain = []
                if m.groupdict().get("meth"):
                    chain.append(m.group("meth"))
                chain.extend(re.findall(r"->\s*(\w+)\s*\(", snippet))

                method_chain = "->".join([c for c in chain if c])

                has_eager = any(x in method_chain.lower().split("->") for x in ["with", "load", "loadmissing"])
                is_raw = ("db::raw" in snippet.lower()) or any(x.lower().endswith("raw") for x in method_chain.split("->"))

                # Detect query type (INSERT/UPDATE/DELETE don't have N+1 issues)
                query_type = "select"
                chain_lower = method_chain.lower()
                if any(op in chain_lower for op in ["->insert", "->create", "->insertgetid", "->upsert"]):
                    query_type = "insert"
                elif any(op in chain_lower for op in ["->update", "->increment", "->decrement"]):
                    query_type = "update"
                elif any(op in chain_lower for op in ["->delete", "->destroy", "->forceDelete"]):
                    query_type = "delete"

                model = None
                if model_group == "model":
                    model = m.group("model")
                    if model:
                        model = model.strip()

                line_no = line_num + body[:start].count("\n")

                key = (line_no, method_chain, model)
                if key in seen:
                    continue
                seen.add(key)

                n_plus_one_risk = "none"
                n_plus_one_reason = None
                # Only flag N+1 risk if in loop AND no eager loading
                if in_loop and not has_eager:
                    n_plus_one_risk = "high"
                    n_plus_one_reason = "Query detected inside a loop context; consider eager loading."

                self._facts.queries.append(
                    QueryUsage(
                        file_path=file_path,
                        line_number=line_no,
                        method_name=method_name,
                        model=model,
                        method_chain=method_chain,
                        query_type=query_type,
                        is_raw=is_raw,
                        has_eager_loading=has_eager,
                        n_plus_one_risk=n_plus_one_risk,
                        n_plus_one_reason=n_plus_one_reason,
                    )
                )

    def _extract_queries_ts(self, file_path: str, method_name: str, method_body_node, content: str, method_start_line: int) -> None:
        """Tree-sitter-based query extraction (primary)."""
        import tree_sitter

        if not self._local.php_lang:
            return

        # Capture scoped calls and member calls; we then compute chain from AST.
        q = self._get_query(
            self._local.php_lang,
            """
            (scoped_call_expression) @scoped
            (member_call_expression) @member
            """,
        )
        cur = tree_sitter.QueryCursor(q)
        caps = self._get_caps_dict(cur.captures(method_body_node))

        def _is_in_loop(node) -> bool:
            loop_types = {"foreach_statement", "for_statement", "while_statement", "do_statement"}
            p = node.parent
            while p:
                if p.type in loop_types:
                    return True
                p = p.parent
            return False

        def _extract_chain(node) -> tuple[str | None, list[str], bool]:
            """Return (model/scope, chain, is_db) for call chains ending at node."""
            chain: list[str] = []
            is_db = False
            model = None

            n = node
            while n:
                if n.type == "member_call_expression":
                    name_node = n.child_by_field_name("name")
                    if name_node:
                        chain.append(content[name_node.start_byte:name_node.end_byte])
                    n = n.child_by_field_name("object")
                    continue
                if n.type == "scoped_call_expression":
                    name_node = n.child_by_field_name("name")
                    scope_node = n.child_by_field_name("scope")
                    if name_node:
                        chain.append(content[name_node.start_byte:name_node.end_byte])
                    if scope_node:
                        scope_txt = content[scope_node.start_byte:scope_node.end_byte]
                        if scope_txt == "DB":
                            is_db = True
                        else:
                            model = scope_txt
                    break
                break

            chain.reverse()
            return (model, chain, is_db)

        seen: set[tuple[int, str, str | None]] = set()
        interesting = {"where", "find", "all", "query", "with", "first", "get", "paginate", "pluck", "count", "exists", "create", "update", "delete", "insert", "save", "load", "loadMissing"}
        db_interest = {"table", "select", "statement", "raw"}
        # Terminal methods that indicate a complete query chain
        terminal_methods = {"get", "first", "paginate", "pluck", "count", "exists", "find", "findorfail", "all", "create", "update", "delete", "insert", "save"}

        nodes: list = []
        nodes.extend(caps.get("scoped", []))
        nodes.extend(caps.get("member", []))
        for node in nodes:
            model, chain, is_db = _extract_chain(node)
            if not chain:
                continue
            # Only process complete query chains (ending with terminal methods)
            # This avoids detecting partial chains like ->where() without ->get()
            if chain[-1].lower() not in terminal_methods:
                continue
            # IMPORTANT: only treat calls as DB queries when the chain is rooted in a scoped call
            # (Model::..., DB::...). Plain member calls like `$this->service->create()` are not queries.
            if not is_db and model is None:
                continue
            first = chain[0]
            if is_db:
                if first not in db_interest:
                    continue
            else:
                if first not in interesting:
                    # We care primarily about model scoped calls; if this is a member call chain
                    # without a scoped root, skip (too noisy).
                    continue

            has_eager = any(x in {"with", "load", "loadMissing"} for x in chain)
            is_raw = is_db and ("raw" in chain)

            # Detect query type (INSERT/UPDATE/DELETE don't have N+1 issues)
            query_type = "select"
            chain_set = set(x.lower() for x in chain)
            if chain_set & {"insert", "create", "insertgetid", "upsert"}:
                query_type = "insert"
            elif chain_set & {"update", "increment", "decrement"}:
                query_type = "update"
            elif chain_set & {"delete", "destroy"}:
                query_type = "delete"

            in_loop = _is_in_loop(node)
            n_plus_one_risk = "none"
            n_plus_one_reason = None
            # Only flag N+1 risk if in loop AND no eager loading
            if in_loop and not has_eager:
                n_plus_one_risk = "high"
                n_plus_one_reason = "Query detected inside a loop context; consider eager loading."

            line_no = method_start_line + content[method_body_node.start_byte:node.start_byte].count("\n")
            method_chain = "->".join(chain)
            key = (line_no, method_chain, model)
            if key in seen:
                continue
            seen.add(key)

            self._facts.queries.append(
                QueryUsage(
                    file_path=file_path,
                    line_number=line_no,
                    method_name=method_name,
                    model=model,
                    method_chain=method_chain,
                    query_type=query_type,
                    is_raw=is_raw,
                    has_eager_loading=has_eager,
                    n_plus_one_risk=n_plus_one_risk,
                    n_plus_one_reason=n_plus_one_reason,
                )
            )

    def _extract_relation_accesses_ts(
        self,
        file_path: str,
        method_name: str,
        method_body_node,
        content: str,
        method_start_line: int,
        class_fqcn: str | None = None,
    ) -> None:
        """Tree-sitter-based relation access extraction for N+1 risk detection."""
        import tree_sitter

        if not self._local.php_lang:
            return

        # Focus on common N+1 patterns:
        # - foreach (...) { $item->relation; }
        # - $items->each(fn($item) => $item->relation);
        # We intentionally keep this heuristic and avoid deep type inference.
        ignore_props = {
            "id",
            "name",
            "email",
            "created_at",
            "updated_at",
            "deleted_at",
            "pivot",
            "attributes",
        }
        queryish = {"get", "first", "count", "exists", "pluck", "paginate", "sum", "avg", "max", "min"}
        iter_methods = {"each", "map", "filter", "reject", "transform", "flatMap"}

        def _line(node) -> int:
            return method_start_line + content[method_body_node.start_byte:node.start_byte].count("\n")

        def _txt(node) -> str:
            return content[node.start_byte:node.end_byte]

        def _collect_member_accesses(body_node, var_txt: str, loop_kind: str):
            seen_local: set[tuple[int, str]] = set()
            stack = [body_node]
            while stack:
                n = stack.pop()
                if not getattr(n, "is_named", False):
                    continue

                if n.type == "member_access_expression":
                    obj = n.child_by_field_name("object")
                    name_node = n.child_by_field_name("name")
                    if obj and name_node and _txt(obj) == var_txt:
                        rel = _txt(name_node)
                        if rel and rel not in ignore_props:
                            ln = _line(n)
                            key = (ln, rel)
                            if key not in seen_local:
                                seen_local.add(key)
                                self._facts.relation_accesses.append(
                                    RelationAccess(
                                        file_path=file_path,
                                        line_number=ln,
                                        method_name=method_name,
                                        class_fqcn=class_fqcn,
                                        base_var=var_txt,
                                        relation=rel,
                                        loop_kind=loop_kind,
                                        access_type="property",
                                    )
                                )

                # Detect chains rooted at $var->relation()->...->get()/count()/...
                if n.type == "member_call_expression":
                    # Extract chain names from nested member_call_expression nodes.
                    chain: list[str] = []
                    base = None
                    cur = n
                    while cur and cur.type == "member_call_expression":
                        name_node = cur.child_by_field_name("name")
                        if name_node:
                            chain.append(_txt(name_node))
                        obj = cur.child_by_field_name("object")
                        if obj is None:
                            break
                        if obj.type == "variable_name":
                            base = _txt(obj)
                            break
                        cur = obj

                    if base == var_txt and len(chain) >= 2:
                        chain_rev = list(reversed(chain))
                        if any(m in queryish for m in chain_rev[1:]):
                            rel = chain_rev[0]
                            if rel and rel not in ignore_props:
                                # Anchor on the start of the whole chain.
                                ln = _line(n)
                                key = (ln, rel)
                                if key not in seen_local:
                                    seen_local.add(key)
                                    self._facts.relation_accesses.append(
                                        RelationAccess(
                                            file_path=file_path,
                                            line_number=ln,
                                            method_name=method_name,
                                            class_fqcn=class_fqcn,
                                            base_var=var_txt,
                                            relation=rel,
                                            loop_kind=loop_kind,
                                            access_type="method",
                                        )
                                    )

                for ch in reversed(getattr(n, "children", []) or []):
                    if getattr(ch, "is_named", False):
                        stack.append(ch)

        # 1) foreach loops
        q_foreach = self._get_query(self._local.php_lang, "(foreach_statement) @foreach")
        cur = tree_sitter.QueryCursor(q_foreach)
        caps = self._get_caps_dict(cur.captures(method_body_node))
        for foreach_node in caps.get("foreach", []):
            body = foreach_node.child_by_field_name("body")
            if not body:
                body = next((c for c in foreach_node.children if getattr(c, "is_named", False) and c.type == "compound_statement"), None)
            if not body:
                continue

            # Find value variable (supports both `as $v` and `as $k => $v`).
            var_txt = None
            named_children = [c for c in foreach_node.children if getattr(c, "is_named", False)]
            # body is typically last.
            before_body = [
                c
                for c in named_children
                if not (body and c.type == body.type and c.start_byte == body.start_byte and c.end_byte == body.end_byte)
            ]
            if len(before_body) >= 2:
                cand = before_body[-1]
                if cand.type == "variable_name":
                    var_txt = _txt(cand)
                elif cand.type == "pair":
                    vs = [v for v in cand.children if getattr(v, "is_named", False) and v.type == "variable_name"]
                    if vs:
                        var_txt = _txt(vs[-1])

            if not var_txt:
                continue

            _collect_member_accesses(body, var_txt, "foreach")

        # 2) Collection higher-order iteration: ->each(fn($x) => $x->relation)
        q_iter = self._get_query(self._local.php_lang, "(member_call_expression) @mcall")
        cur2 = tree_sitter.QueryCursor(q_iter)
        caps2 = self._get_caps_dict(cur2.captures(method_body_node))
        for call_node in caps2.get("mcall", []):
            name_node = call_node.child_by_field_name("name")
            if not name_node:
                continue
            mname = _txt(name_node)
            if mname not in iter_methods:
                continue

            args_node = call_node.child_by_field_name("arguments")
            if not args_node:
                continue

            # Find first closure argument.
            closure = None
            for arg in args_node.children:
                if not getattr(arg, "is_named", False) or arg.type != "argument":
                    continue
                cand = next((c for c in arg.children if getattr(c, "is_named", False)), None)
                if cand and cand.type in {"anonymous_function", "arrow_function"}:
                    closure = cand
                    break

            if not closure:
                continue

            params_node = closure.child_by_field_name("parameters")
            body_node = closure.child_by_field_name("body")
            if not params_node or not body_node:
                continue

            # First param only.
            first_param = next((c for c in params_node.children if getattr(c, "is_named", False) and c.type == "simple_parameter"), None)
            if not first_param:
                continue
            name_var = first_param.child_by_field_name("name")
            if not name_var:
                continue
            var_txt = _txt(name_var)
            if not var_txt:
                continue

            _collect_member_accesses(body_node, var_txt, f"collection_{mname}")

    def _extract_assoc_arrays_ts(
        self,
        file_path: str,
        method_name: str,
        method_body_node,
        content: str,
        method_start_line: int,
        class_fqcn: str | None = None,
    ) -> None:
        """Tree-sitter-based associative array literal extraction (for DTO suggestions)."""
        import tree_sitter

        if not self._local.php_lang:
            return

        q = self._get_query(self._local.php_lang, "(array_creation_expression) @arr")
        cur = tree_sitter.QueryCursor(q)
        caps = self._get_caps_dict(cur.captures(method_body_node))

        def _line(node) -> int:
            return method_start_line + content[method_body_node.start_byte:node.start_byte].count("\n")

        def _txt(node) -> str:
            return content[node.start_byte:node.end_byte]

        seen: set[tuple[int, int, str, str | None]] = set()
        for arr in caps.get("arr", []):
            # Count only associative keys at the top level.
            key_count = 0
            for init in arr.children:
                if not getattr(init, "is_named", False) or init.type != "array_element_initializer":
                    continue
                init_txt = _txt(init)
                if "=>" in init_txt:
                    key_count += 1

            if key_count <= 0:
                continue

            ln = _line(arr)
            used_as = "unknown"
            target = None

            p = arr.parent
            if p and p.type == "assignment_expression":
                used_as = "assignment"
                left = p.child_by_field_name("left")
                if left and left.type == "variable_name":
                    target = _txt(left)
            elif p and p.type == "return_statement":
                used_as = "return"
                target = "return"
            elif p and p.type == "argument":
                used_as = "argument"
                args = p.parent  # arguments
                call = args.parent if args else None
                if call and call.type in {"member_call_expression", "scoped_call_expression"}:
                    n = call.child_by_field_name("name")
                    if n:
                        target = _txt(n)
                elif call and call.type == "function_call_expression":
                    fn = call.child_by_field_name("function")
                    if fn:
                        target = _txt(fn)

                # If this call is returned, mark as return context.
                if call and call.parent and call.parent.type == "return_statement":
                    used_as = "return"
                    target = target or "return"

            snippet = _txt(arr).strip().replace("\n", " ")
            if len(snippet) > 160:
                snippet = snippet[:157] + "..."

            key = (ln, key_count, used_as, target)
            if key in seen:
                continue
            seen.add(key)

            self._facts.assoc_arrays.append(
                AssocArrayLiteral(
                    file_path=file_path,
                    line_number=ln,
                    method_name=method_name,
                    class_fqcn=class_fqcn,
                    key_count=key_count,
                    used_as=used_as,
                    target=target,
                    snippet=snippet,
                )
            )

    def _extract_config_usages_ts(
        self,
        file_path: str,
        method_name: str,
        method_body_node,
        content: str,
        method_start_line: int,
        class_fqcn: str | None = None,
    ) -> None:
        """Tree-sitter-based config() call extraction (primary)."""
        import tree_sitter

        if not self._local.php_lang:
            return

        q = self._get_query(self._local.php_lang, "(function_call_expression) @fn")
        cur = tree_sitter.QueryCursor(q)
        caps = self._get_caps_dict(cur.captures(method_body_node))

        loop_types = {"foreach_statement", "for_statement", "while_statement", "do_statement"}

        def _line(node) -> int:
            return method_start_line + content[method_body_node.start_byte:node.start_byte].count("\n")

        def _txt(node) -> str:
            return content[node.start_byte:node.end_byte]

        def _is_in_loop(node) -> bool:
            p = node.parent
            while p and p is not method_body_node:
                if p.type in loop_types:
                    return True
                p = p.parent
            return False

        seen: set[tuple[int, bool]] = set()
        for fn_call in caps.get("fn", []):
            fn_name = fn_call.child_by_field_name("function")
            if not fn_name:
                continue
            if _txt(fn_name) != "config":
                continue

            in_loop = _is_in_loop(fn_call)
            ln = _line(fn_call)
            key = (ln, in_loop)
            if key in seen:
                continue
            seen.add(key)

            snippet = _txt(fn_call).strip().replace("\n", " ")
            if len(snippet) > 160:
                snippet = snippet[:157] + "..."

            self._facts.config_usages.append(
                ConfigUsage(
                    file_path=file_path,
                    line_number=ln,
                    method_name=method_name,
                    class_fqcn=class_fqcn,
                    in_loop=in_loop,
                    snippet=snippet,
                )
            )

    def _collect_duplicate_candidate_ts(self, file_path: str, start_line: int, end_line: int, body_node, content: str) -> None:
        """Token-window duplicate detection using Tree-sitter AST (primary).

        Phase 11: Instead of hashing the entire method body, we hash overlapping token windows (chunks)
        and then merge consecutive matches into larger duplicated segments. This is closer to Sonar-style
        duplication detection and enables per-file duplication percentage.
        """
        import hashlib as _hashlib

        b = content.encode("utf-8", errors="ignore")

        tokens: list[str] = []
        lines: list[int] = []
        stack = [body_node]
        while stack:
            n = stack.pop()
            if n.child_count == 0:
                ln = (n.start_point.row + 1) if hasattr(n, "start_point") else start_line
                if n.is_named:
                    t = n.type
                    if t in {"name", "qualified_name", "variable_name"}:
                        tokens.append("ID")
                        lines.append(ln)
                    elif "string" in t:
                        tokens.append("STR")
                        lines.append(ln)
                    elif t in {"integer", "float"}:
                        tokens.append("NUM")
                        lines.append(ln)
                    else:
                        tokens.append(t)
                        lines.append(ln)
                else:
                    txt = b[n.start_byte:n.end_byte].decode("utf-8", errors="ignore").strip()
                    if txt:
                        tokens.append(txt)
                        lines.append(ln)
                continue

            for child in reversed(n.children):
                stack.append(child)

        token_count = len(tokens)
        chunk_size = int(getattr(self, "_dup_chunk_size", 50))
        step = int(getattr(self, "_dup_step", 25))
        if token_count < chunk_size or chunk_size <= 0 or step <= 0:
            return

        method_key = f"{file_path}:{start_line}:{end_line}"
        self._dup_method_token_counts[method_key] = token_count
        self._dup_method_file[method_key] = file_path

        # Keep a real-code snippet for UI context (even though hashing is normalized tokens).
        snippet = content[body_node.start_byte:body_node.end_byte].strip()[:400]

        for i in range(0, token_count - chunk_size + 1, step):
            window = tokens[i : i + chunk_size]
            h = _hashlib.sha1((" ".join(window)).encode("utf-8", errors="ignore")).hexdigest()[:16]
            ln0 = lines[i] if i < len(lines) else start_line
            ln1 = lines[i + chunk_size - 1] if (i + chunk_size - 1) < len(lines) else end_line
            self._token_hashes.setdefault(h, []).append((file_path, ln0, ln1, snippet, chunk_size, method_key, i))
    
    def _extract_routes(self, file_path: str, content: str):
        """Extract route definitions with inherited group context (middleware/prefix)."""
        import re

        route_call = re.compile(
            r"(?:Route::|->)\s*(?P<verb>get|post|put|patch|delete|head|options|any)\s*\(\s*['\"](?P<uri>[^'\"]+)['\"]",
            re.IGNORECASE,
        )
        route_match = re.compile(
            r"(?:Route::|->)\s*match\s*\(\s*\[(?P<methods>[^\]]*)\]\s*,\s*['\"](?P<uri>[^'\"]+)['\"]",
            re.IGNORECASE | re.DOTALL,
        )

        statements = self._iter_route_statements(content)
        group_contexts = self._extract_route_group_contexts(statements)

        for stmt_start, stmt_end, stmt in statements:
            stmt_l = stmt.lower()

            method_uri_pairs: list[tuple[str, str]] = []
            for m in route_call.finditer(stmt):
                method_uri_pairs.append(((m.group("verb") or "").upper(), (m.group("uri") or "").strip()))

            for m in route_match.finditer(stmt):
                uri = (m.group("uri") or "").strip()
                methods_blob = m.group("methods") or ""
                methods = re.findall(r"['\"]([A-Za-z]+)['\"]", methods_blob)
                for meth in methods:
                    method_uri_pairs.append((str(meth).upper(), uri))

            if not method_uri_pairs:
                continue

            # Ignore group declarations and non-route helper chains.
            if ("->group(" in stmt_l or "route::group(" in stmt_l) and all(m not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"} for m, _ in method_uri_pairs):
                continue

            controller, action = self._extract_route_handler(stmt)
            route_name = self._extract_route_name(stmt)

            inherited = self._route_context_for_offset(group_contexts, stmt_start)
            inherited_mw = inherited.get("middleware", []) if isinstance(inherited, dict) else []
            inherited_prefixes = inherited.get("prefixes", []) if isinstance(inherited, dict) else []

            inline_mw = self._extract_route_middleware(stmt)
            inline_prefixes = self._extract_route_prefixes(stmt)

            middleware = self._merge_route_tokens(inherited_mw, inline_mw)
            prefixes = [*inherited_prefixes, *inline_prefixes]
            line_number = content.count("\n", 0, stmt_start) + 1

            for verb, uri in method_uri_pairs:
                normalized_uri = self._join_route_prefix_and_uri(prefixes, uri)
                route = RouteInfo(
                    method=verb,
                    uri=normalized_uri,
                    name=route_name,
                    controller=controller,
                    action=action,
                    middleware=middleware,
                    file_path=file_path,
                    line_number=line_number,
                    source="static",
                )
                self._facts.routes.append(route)

    def _iter_route_statements(self, content: str) -> list[tuple[int, int, str]]:
        """Return top-level Route statements by tracking braces/parentheses and strings/comments."""
        out: list[tuple[int, int, str]] = []
        i = 0
        n = len(content)

        while i < n:
            start = content.find("Route::", i)
            if start < 0:
                break

            j = start
            paren = 0
            brace = 0
            in_string: str | None = None
            in_line_comment = False
            in_block_comment = False
            done = False

            while j < n:
                ch = content[j]
                nxt = content[j + 1] if j + 1 < n else ""

                if in_line_comment:
                    if ch == "\n":
                        in_line_comment = False
                    j += 1
                    continue

                if in_block_comment:
                    if ch == "*" and nxt == "/":
                        in_block_comment = False
                        j += 2
                        continue
                    j += 1
                    continue

                if in_string:
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == in_string:
                        in_string = None
                    j += 1
                    continue

                if ch == "/" and nxt == "/":
                    in_line_comment = True
                    j += 2
                    continue

                if ch == "/" and nxt == "*":
                    in_block_comment = True
                    j += 2
                    continue

                if ch in {"'", '"', "`"}:
                    in_string = ch
                    j += 1
                    continue

                if ch == "(":
                    paren += 1
                elif ch == ")":
                    paren = max(0, paren - 1)
                elif ch == "{":
                    brace += 1
                elif ch == "}":
                    brace = max(0, brace - 1)
                elif ch == ";" and paren == 0 and brace == 0:
                    end = j + 1
                    out.append((start, end, content[start:end]))
                    i = end
                    done = True
                    break

                j += 1

            if not done:
                break

        return out

    def _extract_route_group_contexts(self, statements: list[tuple[int, int, str]]) -> list[dict]:
        """Extract route group block ranges with their own middleware/prefix context."""
        groups: list[dict] = []
        for stmt_start, _stmt_end, stmt in statements:
            low = stmt.lower()
            if "group(" not in low:
                continue

            open_brace = stmt.find("{")
            if open_brace < 0:
                continue
            close_brace = self._find_matching_brace(stmt, open_brace)
            if close_brace <= open_brace:
                continue

            header = stmt[:open_brace]
            header_low = header.lower()
            if "->group(" not in header_low and "route::group(" not in header_low:
                continue

            middleware = self._extract_route_middleware(header)
            prefixes = self._extract_route_prefixes(header)

            groups.append(
                {
                    "start": stmt_start + open_brace,
                    "end": stmt_start + close_brace,
                    "middleware": middleware,
                    "prefixes": prefixes,
                }
            )

        groups.sort(key=lambda g: (int(g["start"]), int(g["end"])))
        return groups

    def _route_context_for_offset(self, groups: list[dict], offset: int) -> dict:
        middleware: list[str] = []
        prefixes: list[str] = []
        for g in groups:
            start = int(g.get("start", -1))
            end = int(g.get("end", -1))
            if start <= offset <= end:
                middleware = self._merge_route_tokens(middleware, [str(x) for x in (g.get("middleware") or [])])
                prefixes.extend([str(x) for x in (g.get("prefixes") or []) if str(x).strip()])
        return {"middleware": middleware, "prefixes": prefixes}

    def _extract_route_middleware(self, text: str) -> list[str]:
        import re

        out: list[str] = []
        # Chain style: ->middleware('auth') / ->middleware(['auth', 'verified'])
        chain_pat = re.compile(r"(?:Route::|->)\s*middleware\s*\((?P<arg>.*?)\)", re.IGNORECASE | re.DOTALL)
        for m in chain_pat.finditer(text or ""):
            arg = m.group("arg") or ""
            vals = re.findall(r"['\"]([^'\"]+)['\"]", arg)
            out = self._merge_route_tokens(out, vals)

        # Legacy style: Route::group(['middleware' => ...], function () { ... })
        legacy_pat = re.compile(
            r"['\"]middleware['\"]\s*=>\s*(?P<arg>\[[^\]]*\]|['\"][^'\"]+['\"])",
            re.IGNORECASE | re.DOTALL,
        )
        for m in legacy_pat.finditer(text or ""):
            arg = m.group("arg") or ""
            vals = re.findall(r"['\"]([^'\"]+)['\"]", arg)
            out = self._merge_route_tokens(out, vals)
        return out

    def _extract_route_prefixes(self, text: str) -> list[str]:
        import re

        out: list[str] = []
        chain_pat = re.compile(r"(?:Route::|->)\s*prefix\s*\((?P<arg>.*?)\)", re.IGNORECASE | re.DOTALL)
        for m in chain_pat.finditer(text or ""):
            arg = m.group("arg") or ""
            vals = re.findall(r"['\"]([^'\"]+)['\"]", arg)
            if vals:
                out.append(vals[0])

        legacy_pat = re.compile(
            r"['\"]prefix['\"]\s*=>\s*['\"](?P<pfx>[^'\"]+)['\"]",
            re.IGNORECASE | re.DOTALL,
        )
        for m in legacy_pat.finditer(text or ""):
            pfx = (m.group("pfx") or "").strip()
            if pfx:
                out.append(pfx)
        return out

    def _extract_route_name(self, text: str) -> str | None:
        import re

        m = re.search(r"->\s*name\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", text or "", flags=re.IGNORECASE)
        if not m:
            return None
        name = (m.group(1) or "").strip()
        return name or None

    def _extract_route_handler(self, text: str) -> tuple[str, str]:
        import re

        # [Controller::class, 'method']
        arr = re.search(
            r"\[\s*([A-Za-z0-9_\\]+)::class\s*,\s*['\"]([A-Za-z0-9_]+)['\"]\s*\]",
            text or "",
            flags=re.IGNORECASE | re.DOTALL,
        )
        if arr:
            return ((arr.group(1) or "").strip(), (arr.group(2) or "").strip())

        # 'Controller@method'
        legacy = re.search(
            r",\s*['\"]([A-Za-z0-9_\\]+)@([A-Za-z0-9_]+)['\"]",
            text or "",
            flags=re.IGNORECASE | re.DOTALL,
        )
        if legacy:
            return ((legacy.group(1) or "").strip(), (legacy.group(2) or "").strip())

        # Single-action controller: Controller::class
        inv = re.search(
            r",\s*([A-Za-z0-9_\\]+)::class\s*[\),]",
            text or "",
            flags=re.IGNORECASE | re.DOTALL,
        )
        if inv:
            return ((inv.group(1) or "").strip(), "__invoke")

        return ("", "")

    @staticmethod
    def _merge_route_tokens(base: list[str], incoming: list[str]) -> list[str]:
        out: list[str] = [str(x).strip() for x in (base or []) if str(x).strip()]
        seen = {x.lower() for x in out}
        for tok in incoming or []:
            s = str(tok or "").strip()
            if not s:
                continue
            key = s.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(s)
        return out

    @staticmethod
    def _join_route_prefix_and_uri(prefixes: list[str], uri: str) -> str:
        raw_uri = str(uri or "").strip()
        if not raw_uri:
            raw_uri = "/"
        if raw_uri.startswith("http://") or raw_uri.startswith("https://"):
            return raw_uri

        parts: list[str] = []
        for p in prefixes or []:
            s = str(p or "").strip().strip("/")
            if s:
                parts.append(s)

        u = raw_uri.strip().strip("/")
        if u:
            parts.append(u)

        if not parts:
            return "/"
        return "/" + "/".join(parts)

    @staticmethod
    def _find_matching_brace(text: str, open_idx: int) -> int:
        depth = 0
        in_string: str | None = None
        in_line_comment = False
        in_block_comment = False
        i = open_idx

        while i < len(text):
            ch = text[i]
            nxt = text[i + 1] if i + 1 < len(text) else ""

            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                i += 1
                continue
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if in_string:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_string:
                    in_string = None
                i += 1
                continue

            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch in {"'", '"', "`"}:
                in_string = ch
                i += 1
                continue

            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
            i += 1

        return -1
    
    def _collect_string_literals(self, file_path: str, content: str, lines: list[str]):
        """Collect string literals for enum candidate analysis with context."""
        import re

        # Skip files that are already enum definitions or "enum containers"
        fp_lc = (file_path or "").lower().replace("\\", "/")
        if "/enums/" in fp_lc or fp_lc.startswith("app/enums/"):
            return
        if fp_lc.startswith("config/"):
            return
        
        # Find quoted strings that look like enum values
        string_pattern = re.compile(r"(['\"])(\w{2,20})\1")
        local_literals = {} # value -> list of occurrences
        
        for i, line in enumerate(lines):
            for match in string_pattern.finditer(line):
                quote_char = match.group(1)
                value = match.group(2)

                # Context extraction heuristics
                context = None
                
                # 1. Assignment: $status = 'active' or $order->status = 'active'
                prefix = line[:match.start()].rstrip()
                # matches $var = or $var->prop = or $var['key'] =
                assignment_match = re.search(r"\$([a-zA-Z0-9_]+)(?:->([a-zA-Z0-9_]+)|\[['\"]?([a-zA-Z0-9_]+)['\"]?\])?\s*=\s*$", prefix)
                if assignment_match:
                    # Group 2 is property name, Group 3 is array key, Group 1 is variable name
                    context = assignment_match.group(2) or assignment_match.group(3) or assignment_match.group(1)
                
                # 2. Array value: 'status' => 'active' or "status" => "active"
                if not context:
                    assoc_match = re.search(r"(['\"])([a-zA-Z0-9_]+)\1\s*=>\s*$", prefix)
                    if assoc_match:
                        context = assoc_match.group(2)
                
                # 3. Method call: where('status', 'active')
                if not context:
                    # Look for something like where('attr', '
                    call_match = re.search(r"([a-zA-Z0-9_]+)\s*\(\s*(['\"])([a-zA-Z0-9_]+)\2\s*,\s*$", prefix)
                    if call_match:
                        method_name = call_match.group(1)
                        if method_name in ["where", "orWhere", "whereIn", "update", "create", "firstOrCreate"]:
                            context = call_match.group(3)

                # 4. Comparison: $status === 'active' or $order->status == 'active'
                if not context:
                    comparison_match = re.search(
                        r"(?:->([a-zA-Z0-9_]+)|\$([a-zA-Z0-9_]+)|\[['\"]?([a-zA-Z0-9_]+)['\"]?\])\s*(?:===|==|!==|!=)\s*$",
                        prefix,
                    )
                    if comparison_match:
                        context = comparison_match.group(1) or comparison_match.group(3) or comparison_match.group(2)

                # Skip array keys: 'key' => 'value' (already handled in original code)
                rest = line[match.end():]
                if re.match(r"\s*=>", rest):
                    continue
                
                # Skip common non-enum strings
                if value.lower() in ["id", "name", "email", "password", "created_at", "updated_at"]:
                    continue
                
                # Track occurrence with context
                occurrence = StringOccurrence(
                    file_path=file_path,
                    line_number=i + 1,
                    context=context
                )
                
                if value not in local_literals:
                    local_literals[value] = []
                local_literals[value].append(occurrence)
                
        if local_literals:
            with self._lock:
                for value, occurrences in local_literals.items():
                    existing = next(
                        (l for l in self._facts.string_literals if l.value == value),
                        None
                    )
                    if existing:
                        existing.occurrences.extend(occurrences)
                    else:
                        self._facts.string_literals.append(StringLiteral(
                            value=value,
                            occurrences=occurrences
                        ))

    def _collect_duplicate_candidate(self, file_path: str, start_line: int, end_line: int, code: str) -> None:
        """Collect token windows for duplication (fallback when Tree-sitter isn't available)."""
        import re
        import hashlib as _hashlib

        if not code:
            return

        # Remove comments but keep newlines for a stable fallback line range.
        stripped = re.sub(r"/\\*.*?\\*/", "", code, flags=re.DOTALL)
        stripped = re.sub(r"//.*?$", "", stripped, flags=re.MULTILINE)
        stripped = re.sub(r"#.*?$", "", stripped, flags=re.MULTILINE)

        # Approximate tokenization.
        raw_tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\\d+|\"[^\"]*\"|'[^']*'|\\S", stripped)
        if not raw_tokens:
            return

        def _norm(tok: str) -> str:
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", tok):
                return "ID"
            if re.match(r"^\\d+$", tok):
                return "NUM"
            if (tok.startswith("'") and tok.endswith("'")) or (tok.startswith('"') and tok.endswith('"')):
                return "STR"
            return tok

        tokens = [_norm(t) for t in raw_tokens]
        token_count = len(tokens)
        chunk_size = int(getattr(self, "_dup_chunk_size", 50))
        step = int(getattr(self, "_dup_step", 25))
        if token_count < chunk_size or chunk_size <= 0 or step <= 0:
            return

        method_key = f"{file_path}:{start_line}:{end_line}"
        self._dup_method_token_counts[method_key] = token_count
        self._dup_method_file[method_key] = file_path

        snippet = re.sub(r"\\s+", " ", stripped).strip()[:400]

        for i in range(0, token_count - chunk_size + 1, step):
            window = tokens[i : i + chunk_size]
            h = _hashlib.sha1((" ".join(window)).encode("utf-8", errors="ignore")).hexdigest()[:16]
            with self._lock:
                self._token_hashes.setdefault(h, []).append((file_path, start_line, end_line, snippet, chunk_size, method_key, i))
    
    def _process_js_file(self, file_path: Path):
        """Process JavaScript/React file and extract facts."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            file_hash = self._get_file_hash(content)
            rel_path = normalize_rel_path(str(file_path.relative_to(self.project_path)))

            with self._lock:
                if rel_path not in self._facts.files:
                    self._facts.files.append(rel_path)
                self._facts.file_hashes[rel_path] = file_hash

            # Tree-sitter is primary for JS structure when available.
            ext = file_path.suffix.lower().lstrip(".")
            js_parser, js_lang = self._get_treesitter_js(ext)

            parsed = False
            if js_parser and js_lang:
                try:
                    parsed = self._parse_react_treesitter(rel_path, content, file_hash, js_parser, js_lang)
                except Exception as e:
                    logger.warning(f"Tree-sitter JS parsing failed for {rel_path}: {e}")

            if not parsed:
                # Fallback: regex-based parsing (allowed fallback).
                self._parse_react_basic(rel_path, content, file_hash)

            # Build lightweight frontend symbol graph for cross-file hook/import analysis.
            self._collect_frontend_symbol_graph(rel_path, content)
            
        except Exception as e:
            logger.warning(f"Error processing {file_path}: {e}")
            with self._lock:
                self.progress.errors.append(f"{file_path}: {e}")

    def _parse_react_treesitter(self, file_path: str, content: str, file_hash: str, parser, lang) -> bool:
        """Tree-sitter-based React component parsing (JS/JSX/TS/TSX)."""
        import tree_sitter
        import re

        tree = parser.parse(content.encode("utf-8", errors="ignore"))
        root = tree.root_node

        # Prefer extracting what we can even if the parse has minor errors.

        # Function components: function Declaration / export function
        q = self._get_query(
            lang,
            """
            (function_declaration) @fn
            (variable_declarator value: (arrow_function)) @var
            """,
        )
        cur = tree_sitter.QueryCursor(q)
        caps = self._get_caps_dict(cur.captures(root))

        # Build candidates from captures
        candidates: list[tuple[str, tree_sitter.Node]] = []

        for node in caps.get("fn", []):
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            name = content[name_node.start_byte:name_node.end_byte]
            if name and name[0].isupper():
                candidates.append((name, node))

        for decl in caps.get("var", []):
            name_node = decl.child_by_field_name("name")
            value_node = decl.child_by_field_name("value")
            if not name_node or not value_node:
                continue
            name = content[name_node.start_byte:name_node.end_byte]
            if name and name[0].isupper():
                # Use the value node for body/LOC, but keep declarator for start line.
                candidates.append((name, decl))

        seen: set[tuple[str, int]] = set()
        extracted = 0
        components_in_file: list[ReactComponentInfo] = []
        for name, node in candidates:
            value_node = node
            if node.type == "variable_declarator":
                value_node = node.child_by_field_name("value") or node

            line_start = node.start_point.row + 1
            if (name, line_start) in seen:
                continue
            seen.add((name, line_start))

            line_end = value_node.end_point.row + 1
            body_text = content[value_node.start_byte:value_node.end_byte]

            has_api_calls = any(p in body_text for p in ["fetch(", "axios.", "useSWR", "useQuery"])
            state_count = body_text.count("useState")
            effect_count = body_text.count("useEffect")
            has_inline_logic = state_count > 3 or effect_count > 2
            hooks_used = sorted(set(re.findall(r"\b(use[A-Z][A-Za-z0-9_]*)\s*\(", body_text)))

            comp = ReactComponentInfo(
                name=name,
                file_path=file_path,
                file_hash=file_hash,
                is_function_component=True,
                is_class_component=False,
                line_start=line_start,
                line_end=line_end,
                loc=line_end - line_start + 1,
                hooks_used=hooks_used,
                imports=[],
                has_api_calls=has_api_calls,
                has_inline_state_logic=has_inline_logic,
            )
            with self._lock:
                self._facts.react_components.append(comp)
            components_in_file.append(comp)
            extracted += 1

        # -------------------------------------------------------------------
        # File-level SRP checks: run additional Tree-sitter passes to detect
        # inline type/interface definitions and camelCase helper functions.
        # These flags are set on every component in the file so rules can
        # report them via the standard `analyze()` / facts.react_components path
        # (AST-primary, no regex fallback needed for these signals).
        # -------------------------------------------------------------------
        if components_in_file:
            try:
                # 1. Type / Interface declarations
                # Tree-sitter node types differ slightly per grammar version.
                # We try both common node names; the query engine silently skips unknowns.
                type_names: list[str] = []
                for q_str in [
                    "(type_alias_declaration name: (type_identifier) @tname)",
                    "(interface_declaration name: (type_identifier) @tname)",
                ]:
                    try:
                        tq = self._get_query(lang, q_str)
                        tcur = tree_sitter.QueryCursor(tq)
                        tcaps = self._get_caps_dict(tcur.captures(root))
                        for n in tcaps.get("tname", []):
                            raw = content[n.start_byte:n.end_byte]
                            if raw and raw[0].isupper() and raw not in type_names:
                                type_names.append(raw)
                    except Exception:
                        pass  # Grammar may not support this node type; skip gracefully

                # 2. Helper function declarations (camelCase top-level, non-hook, non-component)
                helper_names: list[str] = []
                helper_q_strs = [
                    # `function helperName(...)`
                    "(function_declaration name: (identifier) @fname)",
                    # `const helperName = (...) =>` — variable_declarator with arrow_function value
                    "(variable_declarator name: (identifier) @vname value: (arrow_function))",
                ]
                for q_str in helper_q_strs:
                    try:
                        hq = self._get_query(lang, q_str)
                        hcur = tree_sitter.QueryCursor(hq)
                        hcaps = self._get_caps_dict(hcur.captures(root))
                        cap_key = "fname" if "fname" in hcaps else "vname"
                        for n in hcaps.get(cap_key, []):
                            raw = content[n.start_byte:n.end_byte]
                            if not raw:
                                continue
                            # Must start with lowercase
                            if raw[0].isupper():
                                continue
                            # Exclude hooks
                            if raw.startswith("use"):
                                continue
                            # Exclude very common React utility names (event handlers, memo fns)
                            if raw in {"memo", "forwardRef", "createContext", "lazy"}:
                                continue
                            if raw not in helper_names:
                                helper_names.append(raw)
                    except Exception:
                        pass

                # Apply flags to all components in this file
                if type_names or helper_names:
                    for comp in components_in_file:
                        if type_names:
                            comp.has_inline_type_defs = True
                            comp.inline_type_names = list(type_names)
                        if helper_names:
                            comp.has_inline_helper_fns = True
                            comp.inline_helper_names = list(helper_names)
            except Exception:
                pass  # SRP flags are supplemental; never break core extraction

        if extracted == 0 and root.has_error:
            return False
        return extracted > 0

    
    def _parse_react_basic(self, file_path: str, content: str, file_hash: str):
        """Basic regex-based React component parsing."""
        import re
        
        lines = content.split("\n")
        
        # Find function components
        component_patterns = [
            # export function ComponentName
            re.compile(r"export\s+(?:default\s+)?function\s+(\w+)\s*\("),
            # export const ComponentName = 
            re.compile(r"export\s+(?:default\s+)?const\s+(\w+)\s*="),
            # function ComponentName (capitalized = component)
            re.compile(r"function\s+([A-Z]\w+)\s*\("),
        ]
        
        for pattern in component_patterns:
            for match in pattern.finditer(content):
                name = match.group(1)
                
                # Must start with uppercase (React convention)
                if not name[0].isupper():
                    continue
                
                line_start = content[:match.start()].count("\n") + 1
                
                # Estimate component end
                remaining = content[match.end():]
                brace_count = 0
                line_end = line_start
                
                for i, char in enumerate(remaining):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            line_end = line_start + remaining[:i].count("\n")
                            break
                
                # Extract component body for analysis
                component_body = content[match.start():match.end() + i] if brace_count == 0 else content[match.start():]
                
                # Check for API calls
                has_api_calls = any(p in component_body for p in [
                    "fetch(", "axios.", "useSWR", "useQuery"
                ])
                
                # Check for complex state logic
                state_count = component_body.count("useState")
                effect_count = component_body.count("useEffect")
                has_inline_logic = state_count > 3 or effect_count > 2
                hooks_used = sorted(set(re.findall(r"\b(use[A-Z][A-Za-z0-9_]*)\s*\(", component_body)))
                
                component = ReactComponentInfo(
                    name=name,
                    file_path=file_path,
                    file_hash=file_hash,
                    line_start=line_start,
                    line_end=line_end,
                    loc=line_end - line_start + 1,
                    hooks_used=hooks_used,
                    has_api_calls=has_api_calls,
                    has_inline_state_logic=has_inline_logic,
                    imports=[],  # Would need more parsing
                )
                
                with self._lock:
                    self._facts.react_components.append(component)

    def _collect_frontend_symbol_graph(self, file_path: str, content: str) -> None:
        """Collect per-file import/hook graph for React/TS code."""
        import re

        graph = getattr(self._facts, "_frontend_symbol_graph", None)
        if not isinstance(graph, dict):
            graph = {"files": {}, "edges": []}

        import_from = re.findall(r"^\s*import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]", content, flags=re.MULTILINE)
        import_dyn = re.findall(r"\bimport\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", content)
        imports = sorted(set([*import_from, *import_dyn]))

        hooks = sorted(set(re.findall(r"\b(use[A-Z][A-Za-z0-9_]*)\s*\(", content)))

        comps = []
        with self._lock:
            current_components = list(self._facts.react_components)
            
        for c in current_components:
            if c.file_path != file_path:
                continue
            comps.append({"name": c.name, "hooks": sorted(set(c.hooks_used or []))})

        with self._lock:
            files_map = graph.get("files", {})
            files_map[file_path] = {
                "imports": imports,
                "hooks": hooks,
                "components": comps,
            }
            graph["files"] = files_map

        edges = graph.get("edges")
        if not isinstance(edges, list):
            edges = []
        existing = {(str(e.get("from", "")), str(e.get("to", ""))) for e in edges if isinstance(e, dict)}
        for imp in imports:
            key = (file_path, imp)
            if key in existing:
                continue
            existing.add(key)
            edges.append({"from": file_path, "to": imp, "type": "import"})
        graph["edges"] = edges

        self._facts._frontend_symbol_graph = graph
    
    def _process_blade_file(self, file_path: Path):
        """Process Blade template for queries and issues."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            file_hash = self._get_file_hash(content)
            rel_path = normalize_rel_path(str(file_path.relative_to(self.project_path)))

            with self._lock:
                if rel_path not in self._facts.files:
                    self._facts.files.append(rel_path)
                self._facts.file_hashes[rel_path] = file_hash
            
            # Detect queries and echoes outside the lock (inner methods have their own locks).
            self._detect_blade_queries(rel_path, content)
            self._detect_blade_raw_echoes(rel_path, content)
            
        except Exception as e:
            logger.warning(f"Error processing {file_path}: {e}")
            with self._lock:
                self.progress.errors.append(f"{file_path}: {e}")
    
    def _detect_blade_queries(self, file_path: str, content: str):
        """Detect database queries in Blade templates."""
        import re
        
        # Patterns that indicate queries in templates
        methods = r"(?:where|find|all|get|first|count|sum|avg|max|min|pluck|exists|paginate|query)"
        # Blade templates often reference models as `\\App\\Models\\User` or just `User`.
        model = r"(?:\\?App\\Models\\)?[A-Z]\w*"
        query_patterns = [
            rf"{model}::(?:{methods})",
            rf"\{{\{{\s*{model}::(?:{methods})",
            rf"@foreach\s*\(\s*{model}::(?:{methods})",
            rf"DB::(?:table|select|statement|raw)",
            rf"\{{\{{\s*DB::(?:table|select|statement|raw)",
            rf"@foreach\s*\(\s*DB::(?:table|select|statement|raw)",
        ]
        
        for pattern in query_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                
                blade_query = BladeQuery(
                    file_path=file_path,
                    line_number=line_num,
                    query_snippet=match.group(0)[:100],
                )
                with self._lock:
                    self._facts.blade_queries.append(blade_query)

    def _detect_blade_raw_echoes(self, file_path: str, content: str) -> None:
        """Detect `{!! ... !!}` raw output usages and mark request-derived ones."""
        import re

        pat = re.compile(r"\{\!\!\s*(?P<expr>.*?)\s*\!\!\}", re.DOTALL)
        reqish = re.compile(r"(\$request\b|request\s*\(|\$_(get|post|request)\b|old\s*\()", re.IGNORECASE)

        for m in pat.finditer(content):
            expr = (m.group("expr") or "").strip()
            if not expr:
                continue

            line_num = content[: m.start()].count("\n") + 1
            is_req = bool(reqish.search(expr))
            snippet = ("{!! " + expr + " !!}")[:200]

            with self._lock:
                self._facts.blade_raw_echos.append(
                    BladeRawEcho(
                        file_path=file_path,
                        line_number=line_num,
                        expression=expr[:200],
                        snippet=snippet,
                        is_request_derived=is_req,
                    )
                )
    
    def _detect_duplicates(self):
        """Analyze collected token windows and merge into duplicated segments.

        We use overlapping token windows (chunks) and then merge consecutive matches between the
        same two method bodies into a longer duplicated segment. This avoids emitting one finding
        per window (noise) and enables stable per-file duplication percentage.
        """
        import hashlib as _hashlib

        chunk_size = int(getattr(self, "_dup_chunk_size", 50))
        step = int(getattr(self, "_dup_step", 25))
        if chunk_size <= 0 or step <= 0:
            self._facts._duplication = {}
            return

        # Collect window matches between method pairs.
        # match tuple: (idx_a, idx_b, occ_a, occ_b, chunk_hash)
        pair_matches: dict[tuple[str, str], list[tuple[int, int, tuple, tuple, str]]] = {}

        for hash_val, occs in self._token_hashes.items():
            if len(occs) < 2:
                continue

            # Cap per-hash occurrences to prevent pathological blowups.
            occs = list(occs)
            if len(occs) > 16:
                occs = occs[:16]

            pairs_emitted = 0
            max_pairs_per_hash = 80

            for i in range(len(occs)):
                for j in range(i + 1, len(occs)):
                    if pairs_emitted >= max_pairs_per_hash:
                        break

                    a = occs[i]
                    b = occs[j]
                    # occurrence tuple: (file, ln0, ln1, snippet, token_count, method_key, start_token_idx)
                    ma = a[5]
                    mb = b[5]
                    if not ma or not mb or ma == mb:
                        continue

                    if ma < mb:
                        key = (ma, mb)
                        pair_matches.setdefault(key, []).append((a[6], b[6], a, b, hash_val))
                    else:
                        key = (mb, ma)
                        pair_matches.setdefault(key, []).append((b[6], a[6], b, a, hash_val))

                    pairs_emitted += 1

        candidate_duplicates: list[DuplicateBlock] = []
        method_intervals: dict[str, list[tuple[int, int]]] = {}

        def _merge_intervals(xs: list[tuple[int, int]]) -> list[tuple[int, int]]:
            if not xs:
                return []
            xs = sorted(xs, key=lambda t: (t[0], t[1]))
            merged: list[tuple[int, int]] = []
            cur_s, cur_e = xs[0]
            for s, e in xs[1:]:
                if s <= cur_e:
                    cur_e = max(cur_e, e)
                else:
                    merged.append((cur_s, cur_e))
                    cur_s, cur_e = s, e
            merged.append((cur_s, cur_e))
            return merged

        # Merge consecutive window matches into segments (require at least 2 windows -> >= 75 tokens with defaults).
        for (ma, mb), matches in pair_matches.items():
            seen: set[tuple[int, int, str]] = set()
            uniq: list[tuple[int, int, tuple, tuple, str]] = []
            for m in matches:
                k = (int(m[0]), int(m[1]), str(m[4]))
                if k in seen:
                    continue
                seen.add(k)
                uniq.append(m)

            uniq.sort(key=lambda t: (t[0], t[1], t[4]))
            if not uniq:
                continue

            seq: list[tuple[int, int, tuple, tuple, str]] = []
            for m in uniq:
                if not seq:
                    seq = [m]
                    continue
                prev = seq[-1]
                if int(m[0]) == int(prev[0]) + step and int(m[1]) == int(prev[1]) + step:
                    seq.append(m)
                    continue

                # finalize previous seq
                if len(seq) >= 2:
                    span_tokens = chunk_size + (len(seq) - 1) * step
                    a0 = seq[0][2]
                    b0 = seq[0][3]
                    aN = seq[-1][2]
                    bN = seq[-1][3]

                    seg_hash = _hashlib.sha1(("|".join([x[4] for x in seq])).encode("utf-8")).hexdigest()[:16]

                    candidate_duplicates.append(
                        DuplicateBlock(
                            hash=seg_hash,
                            token_count=span_tokens,
                            occurrences=[
                                (a0[0], int(a0[1]), int(aN[2])),
                                (b0[0], int(b0[1]), int(bN[2])),
                            ],
                            code_snippet=(str(a0[3])[:200] if a0[3] else ""),
                        )
                    )

                    # Mark duplicated token spans for per-file duplication percentage.
                    a_start = int(seq[0][0])
                    b_start = int(seq[0][1])
                    a_len = int(self._dup_method_token_counts.get(ma, 0) or 0)
                    b_len = int(self._dup_method_token_counts.get(mb, 0) or 0)
                    if a_len > 0:
                        method_intervals.setdefault(ma, []).append((a_start, min(a_len, a_start + span_tokens)))
                    if b_len > 0:
                        method_intervals.setdefault(mb, []).append((b_start, min(b_len, b_start + span_tokens)))

                seq = [m]

            # finalize last seq
            if len(seq) >= 2:
                span_tokens = chunk_size + (len(seq) - 1) * step
                a0 = seq[0][2]
                b0 = seq[0][3]
                aN = seq[-1][2]
                bN = seq[-1][3]

                seg_hash = _hashlib.sha1(("|".join([x[4] for x in seq])).encode("utf-8")).hexdigest()[:16]
                candidate_duplicates.append(
                    DuplicateBlock(
                        hash=seg_hash,
                        token_count=span_tokens,
                        occurrences=[
                            (a0[0], int(a0[1]), int(aN[2])),
                            (b0[0], int(b0[1]), int(bN[2])),
                        ],
                        code_snippet=(str(a0[3])[:200] if a0[3] else ""),
                    )
                )

                a_start = int(seq[0][0])
                b_start = int(seq[0][1])
                a_len = int(self._dup_method_token_counts.get(ma, 0) or 0)
                b_len = int(self._dup_method_token_counts.get(mb, 0) or 0)
                if a_len > 0:
                    method_intervals.setdefault(ma, []).append((a_start, min(a_len, a_start + span_tokens)))
                if b_len > 0:
                    method_intervals.setdefault(mb, []).append((b_start, min(b_len, b_start + span_tokens)))

        def _normalize_duplicate_blocks(blocks: list[DuplicateBlock]) -> list[DuplicateBlock]:
            """
            Collapse pairwise duplicate segments into unique duplicate blocks.

            Window matching can produce repeated hashes across many method-pairs
            and overlapping ranges in the same file. We normalize by hash and
            merge overlapping line ranges per file to keep one stable block.
            """
            grouped: dict[str, list[DuplicateBlock]] = {}
            for block in blocks:
                grouped.setdefault(str(block.hash), []).append(block)

            normalized: list[DuplicateBlock] = []
            for hash_val, members in grouped.items():
                token_count = max(int(getattr(m, "token_count", 0) or 0) for m in members)
                snippet = ""
                by_file: dict[str, list[tuple[int, int]]] = {}

                for member in members:
                    cur_snippet = str(getattr(member, "code_snippet", "") or "")
                    if len(cur_snippet) > len(snippet):
                        snippet = cur_snippet

                    for occ in (getattr(member, "occurrences", None) or []):
                        if len(occ) != 3:
                            continue
                        fp = str(occ[0] or "")
                        if not fp:
                            continue
                        s = int(occ[1])
                        e = int(occ[2])
                        if s > e:
                            s, e = e, s
                        by_file.setdefault(fp, []).append((s, e))

                merged_occurrences: list[tuple[str, int, int]] = []
                for fp, intervals in by_file.items():
                    for s, e in _merge_intervals(intervals):
                        merged_occurrences.append((fp, int(s), int(e)))

                if len(merged_occurrences) < 2:
                    continue

                merged_occurrences.sort(key=lambda o: (o[0], int(o[1]), int(o[2])))
                normalized.append(
                    DuplicateBlock(
                        hash=hash_val,
                        token_count=token_count,
                        occurrences=merged_occurrences,
                        code_snippet=snippet[:200],
                    )
                )

            return normalized

        # Keep a bounded set of duplicate segments to avoid noise in the report.
        candidate_duplicates = _normalize_duplicate_blocks(candidate_duplicates)
        candidate_duplicates.sort(key=lambda d: (-int(d.token_count or 0), -len(d.occurrences or []), d.hash))
        max_dups = 200
        self._facts.duplicates.extend(candidate_duplicates[:max_dups])

        # Per-file duplication percentage (derived; stored as a private attr on Facts).
        total_tokens_by_file: dict[str, int] = {}
        dup_tokens_by_file: dict[str, int] = {}

        for mkey, total in self._dup_method_token_counts.items():
            fp = self._dup_method_file.get(mkey, "")
            if not fp:
                continue
            total_tokens_by_file[fp] = total_tokens_by_file.get(fp, 0) + int(total or 0)

            intervals = _merge_intervals(method_intervals.get(mkey, []))
            dup_len = sum(max(0, e - s) for s, e in intervals)
            dup_tokens_by_file[fp] = dup_tokens_by_file.get(fp, 0) + dup_len

        duplication: dict[str, dict] = {}
        for fp, total in total_tokens_by_file.items():
            if total <= 0:
                continue
            dup = int(dup_tokens_by_file.get(fp, 0) or 0)
            pct = (dup / total) * 100.0
            duplication[fp] = {
                "duplicated_tokens": dup,
                "total_tokens": int(total),
                "duplication_pct": float(pct),
                "duplicate_blocks": len([d for d in self._facts.duplicates if any(o[0] == fp for o in d.occurrences)]),
            }

        self._facts._duplication = duplication
    
    def _analyze_string_literals(self):
        """Mark string literals that are enum candidates."""
        # Known enum value patterns
        enum_patterns = {
            "status": [
                "pending", "approved", "rejected", "cancelled", "completed", "active", "inactive",
                # Common SaaS workflow states.
                "open", "closed", "planned", "scheduled", "confirmed", "rescheduled", "no_show",
                # Common billing/payment states.
                "paid", "unpaid", "partially_paid", "received",
            ],
            "role": ["admin", "user", "guest", "moderator", "editor"],
            "type": ["primary", "secondary", "default", "danger", "warning", "success"],
            "state": ["draft", "published", "archived", "deleted"],
            "priority": ["low", "medium", "high", "urgent", "critical"],
            "channel": ["email", "sms", "whatsapp", "push", "in_app"],
            
            # Game-specific patterns
            "game_status": ["waiting", "in_progress", "finished", "paused", "cancelled", "staging"],
            "game_phase": ["day", "night", "discussion", "voting", "action", "setup", "reveal"],
            "player_status": ["alive", "dead", "spectator", "disconnected", "eliminated"],
            "werewolf_role": ["villager", "wolf", "doc", "seer", "witch", "hunter", "cupid", "amor", "bodyguard", "lycan"],
            "action_type": ["vote", "kill", "save", "poison", "check", "protect", "link"],
        }
        
        for literal in self._facts.string_literals:
            value_lower = literal.value.lower()
            
            # Check if it matches known patterns
            for enum_name, values in enum_patterns.items():
                if value_lower in values:
                    literal.is_enum_candidate = True
                    literal.suggested_enum_name = f"{enum_name.title()}Enum"
                    break
            # Important: do NOT mark literals as enum candidates solely due to frequency.
            # That creates a lot of noise for config keys, cache drivers, etc. We only mark
            # known domain-like values here; rules can still group/score by patterns.
