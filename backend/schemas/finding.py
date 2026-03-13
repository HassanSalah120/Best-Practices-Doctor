"""
Finding Schema - Standardized issue format with fingerprints for deduplication.
"""
import hashlib
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Issue severity levels."""
    CRITICAL = "critical"  # Must fix - security/data issues
    HIGH = "high"          # Should fix - architecture problems
    MEDIUM = "medium"      # Consider fixing
    LOW = "low"            # Nice to have
    INFO = "info"          # Informational


class Category(str, Enum):
    """Issue categories."""
    DRY = "dry"
    SRP = "srp"  # Single Responsibility Principle
    VALIDATION = "validation"
    ARCHITECTURE = "architecture"
    PERFORMANCE = "performance"
    SECURITY = "security"
    ACCESSIBILITY = "accessibility"
    LARAVEL_BEST_PRACTICE = "laravel_best_practice"
    REACT_BEST_PRACTICE = "react_best_practice"
    COMPLEXITY = "complexity"
    MAINTAINABILITY = "maintainability"


class FindingClassification(str, Enum):
    """High-level issue intent for UX and prioritization."""
    DEFECT = "defect"
    RISK = "risk"
    ADVISORY = "advisory"


class Finding(BaseModel):
    """
    A detected issue in the codebase.
    All rules output this standardized format.
    """
    # Identity
    id: str = ""  # Auto-generated
    rule_id: str
    fingerprint: str = ""  # Stable hash for deduplication across runs
    context: str = ""      # Specific context (e.g. method name) for fingerprint stability
    
    # Classification
    title: str
    category: Category
    severity: Severity
    classification: FindingClassification = FindingClassification.RISK
    
    # Location
    file: str  # Relative path
    line_start: int
    line_end: int | None = None
    
    # Explanation (the "senior architect" value)
    description: str
    why_it_matters: str
    suggested_fix: str
    
    # Code example (before/after)
    code_example: str | None = None
    
    # Scoring
    score_impact: int = 0  # Points deducted (0-10)
    
    # Related items
    related_files: list[str] = Field(default_factory=list)
    related_methods: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    evidence_signals: list[str] = Field(default_factory=list)
    metadata: dict[str, object] = Field(default_factory=dict)
    
    # Confidence for heuristic-based findings
    confidence: float = 1.0  # 0-1
    
    def compute_fingerprint(self) -> str:
        """
        Compute stable fingerprint for deduplication across runs.
        Based on rule, file, and context - not line numbers (which shift).
        """
        content = f"{self.rule_id}:{self.file}:{self.context or self.title}"
        return hashlib.sha1(content.encode()).hexdigest()[:12]
    
    def model_post_init(self, __context) -> None:
        """Auto-generate ID and fingerprint if not set."""
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()
        if not self.id:
            self.id = f"finding_{self.fingerprint}"


# Severity weights for scoring
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

CLASSIFICATION_WEIGHTS: dict[FindingClassification, float] = {
    FindingClassification.DEFECT: 1.0,
    FindingClassification.RISK: 1.0,
    FindingClassification.ADVISORY: 0.35,
}


def get_severity_weight(severity: Severity) -> int:
    """Get score impact weight for a severity level."""
    return SEVERITY_WEIGHTS.get(severity, 0)


def get_classification_weight(classification: FindingClassification) -> float:
    """Get scoring multiplier for a finding classification."""
    return CLASSIFICATION_WEIGHTS.get(classification, 0.35)
