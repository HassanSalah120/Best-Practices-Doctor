"""
Base Rule Class
All rules extend this and implement the analyze method.
Rules are pure functions that read Facts and return Findings.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from schemas.facts import Facts
from schemas.metrics import MethodMetrics, ProjectMetrics
from schemas.finding import Finding, FindingClassification, Category, Severity
from core.ruleset import RuleConfig
from core.finding_templates import get_fix_template


@dataclass
class RuleResult:
    """Result from running a rule."""
    rule_id: str
    findings: list[Finding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    execution_time_ms: float = 0.0


class Rule(ABC):
    """
    Base class for all analysis rules.
    
    Rules must be:
    - Independent: No dependencies on other rules
    - Pure: Only read from Facts, no side effects
    - Configurable: Use thresholds from RuleConfig
    """
    
    # Override these in subclasses
    id: str = "base-rule"
    name: str = "Base Rule"
    description: str = "Base rule description"
    category: Category = Category.ARCHITECTURE
    default_severity: Severity = Severity.MEDIUM
    default_classification: FindingClassification | None = None
    # Rule execution type:
    # - "ast": uses Facts/Metrics only (structural/semantic rules)
    # - "regex": lightweight file-content scans (non-structural lint rules)
    type: str = "ast"
    # File extensions scanned for regex rules. AST rules ignore this.
    # Keep PHP as default to preserve existing behavior.
    regex_file_extensions: list[str] = [".php"]
    
    # Project types this rule applies to (empty = all)
    applicable_project_types: list[str] = []
    
    def __init__(self, config: RuleConfig | None = None):
        self.config = config or RuleConfig()
        self.enabled = self.config.enabled

        # Allow ruleset to override category (useful for legacy "laravel"/"react" buckets).
        if self.config.category:
            cat_raw = str(self.config.category).strip().lower()
            aliases = {
                "laravel": Category.LARAVEL_BEST_PRACTICE.value,
                "react": Category.REACT_BEST_PRACTICE.value,
                "best_practices": Category.MAINTAINABILITY.value,
            }
            cat_raw = aliases.get(cat_raw, cat_raw)
            try:
                self.category = Category(cat_raw)
            except Exception:
                # Keep the rule's declared category if the config is invalid.
                pass
        
        # Override severity if configured
        if self.config.severity:
            try:
                self.severity = Severity(self.config.severity)
            except ValueError:
                self.severity = self.default_severity
        else:
            self.severity = self.default_severity
    
    def get_threshold(self, key: str, default: Any = None) -> Any:
        """Get a threshold value from config."""
        return self.config.thresholds.get(key, default)
    
    def is_applicable(self, facts: Facts, project_type: str = "") -> bool:
        """
        Check if this rule should run for the given project.
        Override for custom applicability logic.
        """
        if not self.enabled:
            return False
        
        if self.applicable_project_types and project_type:
            return project_type in self.applicable_project_types
        
        return True
    
    @abstractmethod
    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        """
        Analyze facts and return findings.
        
        Args:
            facts: Raw facts about the codebase
            metrics: Optional derived metrics (keyed by method_fqn)
        
        Returns:
            List of findings (issues detected)
        """
        pass

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        """
        Regex-based analysis hook for lightweight lint rules.

        Default: no findings.
        Regex rules should override this and keep `analyze()` minimal.
        """
        return []

    def analyze_ast(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        """
        AST-based analysis hook for structural rules.

        Default: no findings.
        AST rules should override this for accurate context-aware analysis.
        Use rules.react.ast_utils for React-specific AST utilities.
        """
        return []
    
    def run(
        self,
        facts: Facts,
        project_type: str = "",
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> RuleResult:
        """
        Execute the rule with proper checks and timing.
        
        Returns RuleResult with findings and metadata.
        """
        import time
        
        result = RuleResult(rule_id=self.id)
        
        # Check applicability
        if not self.is_applicable(facts, project_type):
            result.skipped = True
            if not self.enabled:
                result.skip_reason = "Disabled"
            else:
                result.skip_reason = "Not applicable to this project type"
            return result
        
        # Run analysis
        start = time.perf_counter()
        try:
            result.findings = self.analyze(facts, metrics)
        except Exception as e:
            result.skipped = True
            result.skip_reason = f"Error: {str(e)}"
        finally:
            result.execution_time_ms = (time.perf_counter() - start) * 1000
        
        return result
    
    def create_finding(
        self,
        title: str,
        file: str,
        line_start: int,
        description: str,
        why_it_matters: str,
        suggested_fix: str,
        line_end: int | None = None,
        context: str = "",
        code_example: str | None = None,
        severity: Severity | None = None,
        classification: FindingClassification | None = None,
        confidence: float = 1.0,
        related_files: list[str] | None = None,
        related_methods: list[str] | None = None,
        tags: list[str] | None = None,
        evidence_signals: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        score_impact: int = 0,
    ) -> Finding:
        """Helper to create a Finding with rule context."""
        resolved_severity = severity or self.severity
        resolved_classification = classification or self._default_finding_classification(resolved_severity)
        evidence: list[str] = []
        for s in evidence_signals or []:
            x = str(s or "").strip()
            if not x:
                continue
            if x not in evidence:
                evidence.append(x)

        fix = str(suggested_fix or "").strip()
        if not fix:
            fix = get_fix_template(self.id)

        why = str(why_it_matters or "").strip()
        if evidence:
            evidence_txt = ", ".join(evidence)
            if why:
                why = f"{why}\nEvidence signals: {evidence_txt}"
            else:
                why = f"Evidence signals: {evidence_txt}"

        return Finding(
            rule_id=self.id,
            title=title,
            context=context,
            category=self.category,
            severity=resolved_severity,
            classification=resolved_classification,
            file=file,
            line_start=line_start,
            line_end=line_end,
            description=description,
            why_it_matters=why,
            suggested_fix=fix,
            code_example=code_example,
            score_impact=max(0, int(round(score_impact))),
            confidence=confidence,
            related_files=related_files or [],
            related_methods=related_methods or [],
            tags=tags or [],
            evidence_signals=evidence,
            metadata=metadata or {},
        )

    def _default_finding_classification(self, severity: Severity) -> FindingClassification:
        """Infer a stable default classification when a rule does not set one explicitly."""
        if self.default_classification is not None:
            return self.default_classification

        if self.category == Category.SECURITY:
            return FindingClassification.RISK
        if self.category in {Category.ACCESSIBILITY, Category.VALIDATION} and severity in {
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
        }:
            return FindingClassification.DEFECT
        if severity in {Severity.LOW, Severity.INFO}:
            return FindingClassification.ADVISORY
        if self.category in {
            Category.ARCHITECTURE,
            Category.DRY,
            Category.SRP,
            Category.LARAVEL_BEST_PRACTICE,
            Category.REACT_BEST_PRACTICE,
            Category.PERFORMANCE,
            Category.MAINTAINABILITY,
        }:
            return FindingClassification.ADVISORY
        return FindingClassification.RISK
