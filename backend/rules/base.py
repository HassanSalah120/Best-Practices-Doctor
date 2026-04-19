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
        for signal in self._runtime_context_evidence_signals(resolved_severity):
            if signal not in evidence:
                evidence.append(signal)

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

        metadata_payload = dict(metadata or {})
        runtime_profile = self._runtime_decision_profile(resolved_severity)
        if runtime_profile:
            existing_profile = metadata_payload.get("decision_profile")
            if isinstance(existing_profile, dict):
                merged_profile = dict(runtime_profile)
                merged_profile.update(existing_profile)
                metadata_payload["decision_profile"] = merged_profile
            else:
                metadata_payload["decision_profile"] = runtime_profile

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
            metadata=metadata_payload,
        )

    def _runtime_context_evidence_signals(self, resolved_severity: Severity) -> list[str]:
        profile = self._runtime_decision_profile(resolved_severity)
        if not profile:
            return []
        signals: list[str] = []
        framework = str(profile.get("backend_framework", "") or "").strip()
        architecture = str(profile.get("architecture_profile", "") or "").strip()
        project_type = str(profile.get("project_type", "") or "").strip()
        severity_from = str(profile.get("severity_from", "") or "").strip()
        severity_to = str(profile.get("severity_to", "") or "").strip()
        if framework:
            signals.append(f"framework={framework}")
        if architecture:
            signals.append(f"architecture_style={architecture}")
        if project_type:
            signals.append(f"project_type={project_type}")
        if severity_from and severity_to:
            signals.append(f"severity_effect={severity_from}->{severity_to}")
        calibration_signals = profile.get("calibration_signals")
        if isinstance(calibration_signals, list):
            for signal in calibration_signals[:4]:
                text = str(signal or "").strip()
                if text:
                    signals.append(f"context_signal={text}")
        return signals

    def _runtime_decision_profile(self, resolved_severity: Severity) -> dict[str, object]:
        effective_context = getattr(self, "_runtime_effective_context", None)
        calibration = getattr(self, "_context_calibration", None)
        if effective_context is None and not isinstance(calibration, dict):
            return {}

        project_type = str(getattr(effective_context, "project_type", "unknown") or "unknown")
        architecture_profile = str(getattr(effective_context, "architecture_profile", "unknown") or "unknown")
        backend_framework = str(getattr(effective_context, "framework", "laravel") or "laravel")
        profile_confidence = float(getattr(effective_context, "architecture_profile_confidence", 0.0) or 0.0)
        profile_confidence_kind = str(getattr(effective_context, "architecture_profile_confidence_kind", "unknown") or "unknown")

        capabilities: list[str] = []
        for key, state in (getattr(effective_context, "capabilities", {}) or {}).items():
            if bool(getattr(state, "enabled", False)):
                capabilities.append(str(key))

        team_standards: list[str] = []
        for key, state in (getattr(effective_context, "team_expectations", {}) or {}).items():
            if bool(getattr(state, "enabled", False)):
                team_standards.append(str(key))

        calibration_signals = []
        if isinstance(calibration, dict):
            calibration_signals = [str(s) for s in (calibration.get("signals") or []) if str(s or "").strip()]

        severity_from = str(getattr(self.default_severity, "value", self.default_severity) or "")
        severity_to = str(getattr(resolved_severity, "value", resolved_severity) or "")
        severity_adjusted = bool(severity_from and severity_to and severity_from != severity_to)

        recommendation_basis: list[str] = []
        if project_type and project_type != "unknown":
            recommendation_basis.append(f"project_type={project_type}")
        if architecture_profile and architecture_profile != "unknown":
            recommendation_basis.append(f"architecture_style={architecture_profile}")
        if capabilities:
            recommendation_basis.append(f"capabilities={','.join(sorted(capabilities))}")
        if team_standards:
            recommendation_basis.append(f"team_expectations={','.join(sorted(team_standards))}")

        decision_summary = (
            f"emit under {architecture_profile or 'unknown'} profile for {project_type or 'unknown'} project type"
        )
        if severity_adjusted:
            decision_summary += f"; severity calibrated from {severity_from} to {severity_to}"
        if calibration_signals:
            decision_summary += f" using {', '.join(calibration_signals[:3])}"

        decision_reasons = ["context-calibrated", "project-aware-recommendation"]
        if severity_adjusted:
            decision_reasons.append("severity-adjusted-by-context")

        return {
            "backend_framework": backend_framework,
            "project_type": project_type,
            "project_business_context": project_type,
            "architecture_profile": architecture_profile,
            "architecture_style": architecture_profile,
            "profile_confidence": round(profile_confidence, 2),
            "profile_confidence_kind": profile_confidence_kind,
            "capabilities": sorted(set(capabilities)),
            "team_standards": sorted(set(team_standards)),
            "decision": "emit",
            "decision_summary": decision_summary,
            "decision_reasons": decision_reasons,
            "calibration_signals": calibration_signals,
            "severity_from": severity_from,
            "severity_to": severity_to,
            "severity_adjusted": severity_adjusted,
            "severity_reason": (
                f"Context matrix calibration changed severity from {severity_from} to {severity_to}"
                if severity_adjusted
                else "Context matrix did not change severity"
            ),
            "recommendation_basis": recommendation_basis,
        }

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
