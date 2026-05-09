"""
Derived Metrics Schema - Computed from raw Facts by analyzers.
Keeps heuristics separate from parsing.
"""
from pydantic import BaseModel, Field


class MethodMetrics(BaseModel):
    """Derived metrics for a method (computed by analyzers)."""
    method_fqn: str  # Class::method
    file_path: str
    
    # Complexity
    cyclomatic_complexity: int = 1
    cognitive_complexity: int = 0
    nesting_depth: int = 0
    
    # Behavior flags (derived from call_sites)
    has_validation: bool = False
    has_query: bool = False
    has_business_logic: bool = False
    has_http_response: bool = False
    has_file_operations: bool = False
    has_external_api_calls: bool = False
    
    # Confidence scores (0-1) for heuristic flags
    business_logic_confidence: float = 0.0
    
    # Counts
    query_count: int = 0
    validation_count: int = 0
    conditional_count: int = 0
    loop_count: int = 0


class FileMetrics(BaseModel):
    """Aggregated metrics for a file."""
    file_path: str
    file_hash: str
    
    # Size
    total_lines: int = 0
    code_lines: int = 0
    comment_lines: int = 0
    blank_lines: int = 0
    
    # Classes and methods
    class_count: int = 0
    method_count: int = 0
    
    # Aggregate complexity
    avg_method_complexity: float = 0.0
    max_method_complexity: int = 0
    
    # Issues count (filled after rules run)
    issue_count: int = 0


class ProjectMetrics(BaseModel):
    """Project-wide derived metrics."""
    total_files: int = 0
    total_classes: int = 0
    total_methods: int = 0
    total_lines: int = 0
    
    # By type counts
    controller_count: int = 0
    model_count: int = 0
    service_count: int = 0
    form_request_count: int = 0
    repository_count: int = 0
    
    # Aggregate metrics
    avg_file_size: float = 0.0
    avg_method_complexity: float = 0.0
    
    # Coverage indicators
    validation_coverage: float = 0.0  # % of controllers using FormRequest
    service_coverage: float = 0.0  # % of controllers using services
    repository_coverage: float = 0.0  # % of models with repositories
    
    # DRY metrics
    duplicate_block_count: int = 0
    enum_candidate_count: int = 0
