"""
Raw Facts Schema - AST-level extraction only, no derived metrics.
This is the single source of truth for codebase structure.
"""
import hashlib
from pydantic import BaseModel, Field, PrivateAttr, field_validator


class ClassInfo(BaseModel):
    """Extracted class information (raw AST data)."""
    name: str
    fqcn: str  # Fully qualified class name
    file_path: str
    file_hash: str  # SHA1 for stable identification
    namespace: str = ""
    
    # Relationships
    extends: str | None = None
    implements: list[str] = Field(default_factory=list)
    traits: list[str] = Field(default_factory=list)
    
    # Structure
    properties: list[str] = Field(default_factory=list)
    constants: list[str] = Field(default_factory=list)
    
    # Class modifiers
    is_abstract: bool = False
    is_final: bool = False
    
    # Position
    line_start: int = 0
    line_end: int = 0
    
    # Stable ID for deduplication across runs
    @property
    def node_id(self) -> str:
        return f"{self.fqcn}@{self.file_hash[:8]}"


class MethodInfo(BaseModel):
    """Extracted method information (raw AST data only)."""
    name: str
    class_name: str
    class_fqcn: str | None = None  # Prefer for disambiguation across namespaces
    file_path: str
    file_hash: str
    
    # Signature
    parameters: list[str] = Field(default_factory=list)
    return_type: str | None = None
    visibility: str = "public"  # public, protected, private
    is_static: bool = False
    is_abstract: bool = False
    
    # Position
    line_start: int = 0
    line_end: int = 0
    loc: int = 0  # Lines of code
    
    # Raw call sites (for derived analysis)
    call_sites: list[str] = Field(default_factory=list)
    instantiations: list[str] = Field(default_factory=list)  # new ClassName
    throws: list[str] = Field(default_factory=list)          # throw new ClassName
    
    # Raw imports used in method
    imports_used: list[str] = Field(default_factory=list)
    
    # Stable ID
    @property
    def method_fqn(self) -> str:
        cls = self.class_fqcn or self.class_name
        return f"{cls}::{self.name}"

    @property
    def node_id(self) -> str:
        return f"{self.method_fqn}@{self.file_hash[:8]}:{self.line_start}"


class RouteInfo(BaseModel):
    """Extracted route information."""
    method: str  # GET, POST, PUT, DELETE, etc.
    uri: str
    name: str | None = None
    
    # Controller binding
    controller: str | None = None
    action: str | None = None
    
    # Middleware
    middleware: list[str] = Field(default_factory=list)
    
    # Source
    file_path: str = ""
    line_number: int = 0
    
    # Source of truth
    source: str = "static"  # "static" (parsed) or "artisan" (route:list)


class ValidationUsage(BaseModel):
    """Detected validation call."""
    file_path: str
    line_number: int
    method_name: str = ""  # Which method contains this validation
    
    # Rules (field -> rule list)
    rules: dict[str, list[str]] = Field(default_factory=dict)
    
    # Type of validation
    validation_type: str = "inline"  # inline, form_request, validator_make
    form_request_class: str | None = None


class QueryUsage(BaseModel):
    """Detected Eloquent/DB query."""
    file_path: str
    line_number: int
    method_name: str = ""
    
    # Query details
    model: str | None = None
    method_chain: str = ""  # e.g., "where->orderBy->get"
    
    # Query type for distinguishing SELECT vs INSERT/UPDATE/DELETE
    query_type: str = "select"  # select, insert, update, delete, other
    
    # Flags
    is_raw: bool = False  # DB::raw or raw queries
    has_eager_loading: bool = False  # with(), load()
    
    # N+1 risk with confidence
    n_plus_one_risk: str = "none"  # none, low, medium, high
    n_plus_one_reason: str | None = None


class DuplicateBlock(BaseModel):
    """Detected duplicate code block."""
    hash: str  # Content hash for matching
    token_count: int = 0
    
    # All occurrences: (file, start_line, end_line)
    occurrences: list[tuple[str, int, int]] = Field(default_factory=list)
    
    # Sample of the duplicated code
    code_snippet: str = ""


class StringOccurrence(BaseModel):
    """Detailed occurrence of a string literal with context."""
    file_path: str
    line_number: int
    context: str | None = None  # e.g., variable name, array key, or method param name


class StringLiteral(BaseModel):
    """Tracked string literal for enum detection."""
    value: str
    occurrences: list[StringOccurrence] = Field(default_factory=list)
    
    # Heuristic: is this an enum candidate?
    is_enum_candidate: bool = False
    suggested_enum_name: str | None = None

    @field_validator("occurrences", mode="before")
    @classmethod
    def coerce_occurrences(cls, value):
        """Accept legacy `(file_path, line_number[, context])` tuples used in tests and fixtures."""
        if value is None:
            return []
        if not isinstance(value, list):
            return value

        normalized: list[object] = []
        for item in value:
            if isinstance(item, (StringOccurrence, dict)):
                normalized.append(item)
                continue
            if isinstance(item, (tuple, list)) and len(item) >= 2:
                normalized.append(
                    {
                        "file_path": str(item[0]),
                        "line_number": int(item[1]),
                        "context": str(item[2]) if len(item) >= 3 and item[2] is not None else None,
                    }
                )
                continue
            normalized.append(item)
        return normalized


class BladeQuery(BaseModel):
    """Query detected in Blade template."""
    file_path: str
    line_number: int
    query_snippet: str = ""


class BladeRawEcho(BaseModel):
    """Raw Blade echo usage `{!! ... !!}` (potential XSS if untrusted)."""
    file_path: str
    line_number: int
    expression: str = ""
    is_request_source: bool = False
    snippet: str = ""


class EnvUsage(BaseModel):
    """Direct `env()` access detected in PHP code."""
    file_path: str
    line_number: int
    snippet: str = ""


class ReactComponentInfo(BaseModel):
    """Extracted React component info."""
    name: str
    file_path: str
    file_hash: str
    
    # Type
    is_function_component: bool = True
    is_class_component: bool = False
    
    # Size
    line_start: int = 0
    line_end: int = 0
    loc: int = 0
    
    # Dependencies
    hooks_used: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    
    # Inline logic detection (raw)
    has_api_calls: bool = False
    has_inline_state_logic: bool = False
    # Separation of concerns detection (raw — populated by Tree-sitter pass)
    has_inline_type_defs: bool = False       # type/interface declarations in the file
    inline_type_names: list[str] = Field(default_factory=list)
    has_inline_helper_fns: bool = False      # camelCase helper fns (non-hook, non-component)
    inline_helper_names: list[str] = Field(default_factory=list)


class RelationAccess(BaseModel):
    """Potential lazy-loaded relation access (for N+1 detection heuristics)."""
    file_path: str
    line_number: int
    method_name: str = ""
    class_fqcn: str | None = None

    base_var: str = ""   # e.g., "$user"
    relation: str = ""   # e.g., "posts"
    loop_kind: str = ""  # foreach, collection_each, collection_map, etc.
    access_type: str = "property"  # property|method


class AssocArrayLiteral(BaseModel):
    """Associative array literal detected in code (raw AST fact)."""
    file_path: str
    line_number: int
    method_name: str = ""
    class_fqcn: str | None = None

    key_count: int = 0
    used_as: str = ""  # assignment|argument|return|unknown
    target: str | None = None  # variable name or call name (best effort)
    snippet: str = ""

class ConfigUsage(BaseModel):
    """`config()` call usage (raw)."""
    file_path: str
    line_number: int
    method_name: str = ""
    class_fqcn: str | None = None
    in_loop: bool = False
    snippet: str = ""


class UseImport(BaseModel):
    """Top-level PHP `use` import statement (raw AST fact)."""

    file_path: str
    line_number: int = 0

    # Fully-qualified import target, without a leading "\".
    fqcn: str

    # Optional alias (e.g., `use Foo\\Bar as Baz;` -> alias="Baz")
    alias: str | None = None

    # class|function|const (we currently only extract class-like imports)
    import_type: str = "class"


class FqcnReference(BaseModel):
    """Reference to a fully-qualified class name in PHP code (raw AST fact)."""

    file_path: str
    line_number: int

    # Normalized FQCN without a leading "\".
    fqcn: str

    # Optional raw text including leading "\" (when present).
    raw: str = ""

    # Best-effort classification (new|static_call|class_const|type|other)
    kind: str = "other"

    # Small code snippet for UX (kept short to avoid bloating facts).
    snippet: str = ""


class ClassConstAccess(BaseModel):
    """Reference to a class constant access expression (e.g. `Foo::class`) in PHP code (raw AST fact)."""

    file_path: str
    line_number: int

    # Raw expression text (kept short).
    expression: str = ""


class ProjectContext(BaseModel):
    """Derived project-level context signals used to reduce false positives."""

    tenant_mode: str = "unknown"  # tenant | non_tenant | unknown
    tenant_signals: list[str] = Field(default_factory=list)

    react_structure_mode: str = "unknown"  # feature-first | category-based | hybrid | unknown
    react_shared_roots: list[str] = Field(default_factory=list)

    has_i18n: bool = False
    i18n_helpers: list[str] = Field(default_factory=list)

    custom_head_wrappers: list[str] = Field(default_factory=list)
    auth_flow_paths: list[str] = Field(default_factory=list)
    shared_infra_roots: list[str] = Field(default_factory=list)


class Facts(BaseModel):
    """
    Normalized representation of the entire codebase.
    Contains ONLY raw AST facts - no derived metrics.
    Rules read from this, never parse files directly.
    """
    project_path: str
    scan_id: str = ""

    # --- Quality Gate / Project-level signals ---
    # These are raw structural facts about the repository layout (not derived metrics).
    has_tests: bool = False
    test_files_count: int = 0
    
    # All files scanned (relative paths)
    files: list[str] = Field(default_factory=list)
    file_hashes: dict[str, str] = Field(default_factory=dict)  # path -> hash
    project_context: ProjectContext = Field(default_factory=ProjectContext)

    # --- PHP File Metadata ---
    # Namespace per PHP file (relative path -> namespace string without leading "\"), if present.
    php_namespaces: dict[str, str] = Field(default_factory=dict)
    # Top-level `use` imports per file.
    use_imports: list[UseImport] = Field(default_factory=list)
    # Fully-qualified class references found in code (e.g., `new \\App\\...`, `\\App\\...::class`).
    fqcn_references: list[FqcnReference] = Field(default_factory=list)
    # Class constant access expressions found in code (e.g., `Foo::class`, `App\\Foo::class`).
    # This is important for Laravel container binding maps in service providers.
    class_const_accesses: list[ClassConstAccess] = Field(default_factory=list)
    
    # --- PHP Classes by Type ---
    classes: list[ClassInfo] = Field(default_factory=list)
    controllers: list[ClassInfo] = Field(default_factory=list)
    models: list[ClassInfo] = Field(default_factory=list)
    services: list[ClassInfo] = Field(default_factory=list)
    form_requests: list[ClassInfo] = Field(default_factory=list)
    enums: list[ClassInfo] = Field(default_factory=list)
    contracts: list[ClassInfo] = Field(default_factory=list)  # Interfaces
    repositories: list[ClassInfo] = Field(default_factory=list)
    exceptions: list[ClassInfo] = Field(default_factory=list)
    middleware: list[ClassInfo] = Field(default_factory=list)
    jobs: list[ClassInfo] = Field(default_factory=list)
    events: list[ClassInfo] = Field(default_factory=list)
    listeners: list[ClassInfo] = Field(default_factory=list)
    policies: list[ClassInfo] = Field(default_factory=list)
    commands: list[ClassInfo] = Field(default_factory=list)
    
    # All methods flattened
    methods: list[MethodInfo] = Field(default_factory=list)
    
    # --- Routing ---
    routes: list[RouteInfo] = Field(default_factory=list)
    
    # --- Validation ---
    validations: list[ValidationUsage] = Field(default_factory=list)
    
    # --- Database Queries ---
    queries: list[QueryUsage] = Field(default_factory=list)
    
    # --- Duplication ---
    duplicates: list[DuplicateBlock] = Field(default_factory=list)
    
    # --- String Literals (for enum detection) ---
    string_literals: list[StringLiteral] = Field(default_factory=list)
    
    # --- Blade ---
    blade_files: list[str] = Field(default_factory=list)
    blade_queries: list[BladeQuery] = Field(default_factory=list)
    blade_raw_echos: list[BladeRawEcho] = Field(default_factory=list)

    # --- Config / Environment ---
    env_usages: list[EnvUsage] = Field(default_factory=list)
    
    # --- React/Inertia ---
    react_components: list[ReactComponentInfo] = Field(default_factory=list)

    # --- Eloquent / Layering Heuristics ---
    relation_accesses: list[RelationAccess] = Field(default_factory=list)
    assoc_arrays: list[AssocArrayLiteral] = Field(default_factory=list)
    config_usages: list[ConfigUsage] = Field(default_factory=list)

    # Private cached indexes (not part of the serialized Facts schema)
    _call_graph_index: object | None = PrivateAttr(default=None)
    _dependency_graph: object | None = PrivateAttr(default=None)
    _coverage: object | None = PrivateAttr(default=None)
    _duplication: object | None = PrivateAttr(default=None)
    _frontend_symbol_graph: object | None = PrivateAttr(default=None)
    
    def get_file_hash(self, path: str) -> str:
        """Get or compute file hash."""
        if path in self.file_hashes:
            return self.file_hashes[path]
        return ""


def compute_file_hash(content: bytes) -> str:
    """Compute SHA1 hash for file content."""
    return hashlib.sha1(content).hexdigest()
