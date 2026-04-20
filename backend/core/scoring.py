"""
Scoring Engine

Computes quality scores from findings and metrics.
"""
import logging
from dataclasses import dataclass, field
from enum import Enum

from schemas.facts import Facts
from schemas.finding import (
    Finding,
    FindingClassification,
    Category,
    Severity,
    get_classification_weight,
)
from schemas.report import CategoryScore, QualityScores, ScanReport
from core.ruleset import Ruleset
from core.fix_intelligence import get_fix_strategy
from core.project_memory import ProjectIntelligenceManager

logger = logging.getLogger(__name__)


# Default weights for categories
DEFAULT_CATEGORY_WEIGHTS = {
    Category.ARCHITECTURE: 20,
    Category.DRY: 15,
    Category.LARAVEL_BEST_PRACTICE: 20,
    Category.COMPLEXITY: 15,
    Category.SECURITY: 15,
    Category.ACCESSIBILITY: 5,
    Category.MAINTAINABILITY: 10,
    Category.SRP: 10,
    Category.VALIDATION: 5,
    Category.PERFORMANCE: 10,
    Category.REACT_BEST_PRACTICE: 10,
}

# Penalty per finding by severity
DEFAULT_SEVERITY_PENALTIES = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

DEFAULT_CLASSIFICATION_MULTIPLIERS = {
    FindingClassification.DEFECT: 1.0,
    FindingClassification.RISK: 1.0,
    FindingClassification.ADVISORY: 0.35,
}


@dataclass
class ScoringResult:
    """Result of scoring calculation."""
    overall_score: float
    category_scores: dict[str, CategoryScore]
    grade: str
    improvement_potential: float  # How many points could be gained by fixing issues


class ScoringEngine:
    """
    Calculates quality scores from findings.
    
    Scoring methodology:
    1. Start at 100 for each category
    2. Subtract penalties based on findings
    3. Weight categories and aggregate
    4. Apply minimum score floor of 0
    """
    
    def __init__(self, ruleset: Ruleset | None = None):
        self.ruleset = ruleset
        self._weights_explicit = False
        
        # Load weights from ruleset or use defaults
        if ruleset and ruleset.scoring:
            self.category_weights, self._weights_explicit = self._normalize_category_weights(ruleset.scoring.weights)
            self.severity_penalties = ruleset.scoring.severity_penalties
            self.classification_multipliers = ruleset.scoring.classification_multipliers
        else:
            self.category_weights = DEFAULT_CATEGORY_WEIGHTS
            self.severity_penalties = DEFAULT_SEVERITY_PENALTIES
            self.classification_multipliers = {
                cls.value: weight for cls, weight in DEFAULT_CLASSIFICATION_MULTIPLIERS.items()
            }

    def _normalize_category_weights(self, weights: dict) -> tuple[dict, bool]:
        """Normalize weights keys and scale to 0-100 if user provided fractions.

        Returns:
            (normalized_weights, weights_explicit)
            where weights_explicit means "user weights were valid and should zero-out missing categories".
        """
        if not isinstance(weights, dict) or not weights:
            return (DEFAULT_CATEGORY_WEIGHTS, False)

        aliases = {
            # Historical / user-friendly keys
            "laravel": Category.LARAVEL_BEST_PRACTICE.value,
            "react": Category.REACT_BEST_PRACTICE.value,
            "best_practices": Category.MAINTAINABILITY.value,
        }

        normalized: dict[str, float] = {}
        valid_keys = {c.value for c in Category}
        for k, v in weights.items():
            key = k.value if isinstance(k, Category) else str(k)
            key = key.strip()
            key_lc = key.lower()
            key_lc = aliases.get(key_lc, key_lc)

            if key_lc not in valid_keys:
                logger.warning(f"Ignoring unknown scoring weight key: {key!r}")
                continue
            try:
                normalized[key_lc] = float(v)
            except Exception:
                continue

        if not normalized:
            return (DEFAULT_CATEGORY_WEIGHTS, False)

        max_w = max(normalized.values())
        sum_w = sum(normalized.values())
        # Heuristic: treat weights as fractions if they look like they sum ~1.0.
        if max_w <= 1.0 and sum_w <= 2.0:
            normalized = {k: v * 100.0 for k, v in normalized.items()}

        return (normalized, True)
    
    def calculate(
        self,
        findings: list[Finding],
        file_count: int = 0,
        method_count: int = 0,
    ) -> ScoringResult:
        """
        Calculate quality scores from findings.
        
        Args:
            findings: List of detected findings
            file_count: Total files analyzed (for normalization)
            method_count: Total methods analyzed (for normalization)
        
        Returns:
            ScoringResult with overall and category scores
        """
        # Group findings by category
        category_findings: dict[Category, list[Finding]] = {}
        for finding in findings:
            if finding.category not in category_findings:
                category_findings[finding.category] = []
            category_findings[finding.category].append(finding)
        
        # Calculate per-category scores
        category_scores: dict[str, CategoryScore] = {}
        total_weighted_score = 0.0
        total_weight = 0.0
        total_improvement = 0.0
        
        for category in Category:
            cat_findings = category_findings.get(category, [])
            raw_score = self._calculate_category_score(cat_findings, file_count)
            
            # Get weight for this category
            weight = self._get_weight(category)
            has_weight = weight > 0
            
            category_scores[category.value] = CategoryScore(
                category=category.value,
                score=raw_score if has_weight else None,
                raw_score=raw_score,
                weight=weight,
                has_weight=has_weight,
                finding_count=len(cat_findings),
            )
            
            total_weighted_score += raw_score * weight
            total_weight += weight
            
            # Calculate improvement potential
            improvement = (100 - raw_score) * (weight / 100)
            total_improvement += improvement
        
        # Calculate overall score
        overall_score = total_weighted_score / total_weight if total_weight > 0 else 100.0
        overall_score = min(100, max(0, overall_score))
        
        # Determine grade
        grade = self._calculate_grade(overall_score)
        
        return ScoringResult(
            overall_score=round(overall_score, 1),
            category_scores=category_scores,
            grade=grade,
            improvement_potential=round(total_improvement, 1),
        )
    
    def _calculate_category_score(
        self,
        findings: list[Finding],
        file_count: int,
    ) -> float:
        """Calculate score for a single category."""
        if not findings:
            return 100.0
        
        # Calculate total penalty
        total_penalty = 0.0
        cap_low_info = bool(getattr(getattr(self.ruleset, "scoring", None), "cap_low_info_per_file_rule", True))
        low_info_caps: dict[tuple[str, str], float] = {}

        for finding in findings:
            # Use score_impact if set, otherwise calculate from severity
            if finding.score_impact > 0:
                penalty = float(finding.score_impact)
            else:
                penalty = float(self._get_severity_penalty(finding.severity))
            penalty *= self._get_classification_multiplier(getattr(finding, "classification", FindingClassification.ADVISORY))

            # For LOW/INFO severities, apply once per (file, rule) using max penalty.
            if cap_low_info and finding.severity in {Severity.LOW, Severity.INFO}:
                key = (finding.file, finding.rule_id)
                prev = low_info_caps.get(key, 0.0)
                if penalty > prev:
                    low_info_caps[key] = penalty
                continue

            total_penalty += penalty

        if cap_low_info and low_info_caps:
            total_penalty += sum(low_info_caps.values())
        
        # Normalize by file count if available
        if file_count > 0:
            # More lenient for larger codebases
            normalization_factor = min(1.0, 50 / file_count)
            total_penalty *= normalization_factor
        
        # Cap penalty at 100
        score = max(0, 100 - total_penalty)
        
        return round(score, 1)
    
    def _get_weight(self, category: Category) -> float:
        """Get weight for a category."""
        if isinstance(self.category_weights, dict):
            # Check for Category enum keys
            if category in self.category_weights:
                return self.category_weights[category]
            # Check for string keys
            if category.value in self.category_weights:
                return self.category_weights[category.value]

            # If user provided weights, missing categories should default to 0
            # (otherwise a "must sum to 1.0" weights file can't behave predictably).
            if self._weights_explicit:
                return 0.0

        return DEFAULT_CATEGORY_WEIGHTS.get(category, 10)
    
    def _get_severity_penalty(self, severity: Severity) -> float:
        """Get penalty for a severity level."""
        if isinstance(self.severity_penalties, dict):
            if severity in self.severity_penalties:
                return self.severity_penalties[severity]
            if severity.value in self.severity_penalties:
                return self.severity_penalties[severity.value]
        
        return DEFAULT_SEVERITY_PENALTIES.get(severity, 2)

    def _get_classification_multiplier(self, classification: FindingClassification | str) -> float:
        """Get scoring multiplier for a finding classification."""
        key = classification.value if isinstance(classification, FindingClassification) else str(classification or "").strip().lower()
        if isinstance(self.classification_multipliers, dict):
            raw = self.classification_multipliers.get(key)
            if raw is not None:
                try:
                    return max(0.0, float(raw))
                except Exception:
                    pass
        try:
            enum_value = classification if isinstance(classification, FindingClassification) else FindingClassification(key)
            return get_classification_weight(enum_value)
        except Exception:
            return 0.35
    
    def _calculate_grade(self, score: float) -> str:
        """Calculate letter grade from score."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def create_quality_scores(self, result: ScoringResult) -> QualityScores:
        """Convert ScoringResult to QualityScores schema."""
        return QualityScores(
            overall=result.overall_score,
            grade=result.grade,
            architecture=result.category_scores.get("architecture", CategoryScore(category="architecture")).raw_score,
            dry=result.category_scores.get("dry", CategoryScore(category="dry")).raw_score,
            laravel=result.category_scores.get("laravel_best_practice", CategoryScore(category="laravel_best_practice")).raw_score,
            react=result.category_scores.get("react_best_practice", CategoryScore(category="react_best_practice")).raw_score,
            complexity=result.category_scores.get("complexity", CategoryScore(category="complexity")).raw_score,
            security=result.category_scores.get("security", CategoryScore(category="security")).raw_score,
            maintainability=result.category_scores.get("maintainability", CategoryScore(category="maintainability")).raw_score,
            srp=result.category_scores.get("srp", CategoryScore(category="srp")).raw_score,
            validation=result.category_scores.get("validation", CategoryScore(category="validation")).raw_score,
            performance=result.category_scores.get("performance", CategoryScore(category="performance")).raw_score,
        )

    def generate_report(
        self,
        job_id: str,
        project_path: str,
        findings: list[Finding],
        facts: Facts,
        project_info=None,
        ruleset_path: str | None = None,
        rules_executed: list[str] | None = None,
    ) -> ScanReport:
        """
        Generate a full ScanReport from findings and facts.
        """
        from datetime import datetime, timezone
        import hashlib
        from schemas.report import ScanReport, FileSummary, ActionItem, TriageItem
        from schemas.project_type import ProjectInfo
        
        # Calculate scores
        scoring_result = self.calculate(
            findings,
            # Use scanned file count for normalization. Classes/routes can be 0 for non-Laravel projects
            # or when structural extraction is partially disabled by ignore globs.
            file_count=len(getattr(facts, "files", []) or []),
            method_count=len(facts.methods)
        )
        
        scores = self.create_quality_scores(scoring_result)

        # Generate File Summaries
        file_map: dict[str, FileSummary] = {}
        for finding in findings:
            if finding.file not in file_map:
                file_map[finding.file] = FileSummary(path=finding.file)
            
            summary = file_map[finding.file]
            summary.finding_count += 1
            summary.issue_count += 1
            
            if finding.severity == Severity.CRITICAL:
                summary.critical_count += 1
            elif finding.severity == Severity.HIGH:
                summary.high_count += 1
            elif finding.severity == Severity.MEDIUM:
                summary.medium_count += 1
            elif finding.severity == Severity.LOW:
                summary.low_count += 1
        
        # Sort files by finding count (descending)
        file_summaries = sorted(file_map.values(), key=lambda x: x.finding_count, reverse=True)

        # Build a deterministic action plan from findings (derived layer; does not touch Facts).
        # Group by rule_id to produce "do this next" tasks that remain stable across refactors.
        # Priority is a weighted estimate based on severities and category weights.
        severity_rank = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        classification_rank = {
            FindingClassification.DEFECT: 3,
            FindingClassification.RISK: 2,
            FindingClassification.ADVISORY: 1,
        }

        by_rule: dict[str, list[Finding]] = {}
        for f in findings:
            by_rule.setdefault(f.rule_id, []).append(f)

        action_plan: list[ActionItem] = []
        triage_plan: list[TriageItem] = []
        memory_manager = ProjectIntelligenceManager()
        project_memory = memory_manager.get_project(project_path)
        triage_weights = dict(getattr(getattr(self.ruleset, "scoring", None), "triage_weights", {}) or {})
        w_impact = float(triage_weights.get("impact", 1.0) or 1.0)
        w_risk = float(triage_weights.get("risk", 1.0) or 1.0)
        w_effort = float(triage_weights.get("effort", 1.0) or 1.0)
        w_context = float(triage_weights.get("context", 1.0) or 1.0)
        effort_discount = float(triage_weights.get("effort_discount", 0.6) or 0.6)
        effort_discount = min(0.95, max(0.0, effort_discount))
        project_context = (
            facts.project_context.model_dump()
            if getattr(facts, "project_context", None) is not None
            else {}
        )
        for rule_id, fs in by_rule.items():
            fs_sorted = sorted(fs, key=lambda f: (f.file, f.context, f.fingerprint))
            sample = fs_sorted[0]
            cat_key = sample.category.value
            cat_score = scoring_result.category_scores.get(cat_key)
            cat_weight = float(cat_score.weight) if cat_score else float(self._get_weight(sample.category))

            total_penalty = 0.0
            for f in fs_sorted:
                if f.score_impact > 0:
                    penalty = float(f.score_impact)
                else:
                    penalty = float(self._get_severity_penalty(f.severity))
                penalty *= self._get_classification_multiplier(getattr(f, "classification", FindingClassification.ADVISORY))
                total_penalty += penalty

            # Weighted "impact points". Keep rounding stable across platforms.
            priority = round(total_penalty * (cat_weight / 100.0), 2)
            max_sev = max(fs_sorted, key=lambda f: severity_rank.get(f.severity, 0)).severity
            max_classification = max(
                fs_sorted,
                key=lambda f: classification_rank.get(
                    getattr(f, "classification", FindingClassification.ADVISORY),
                    0,
                ),
            ).classification

            fingerprints = sorted({f.fingerprint for f in fs_sorted})
            files = sorted({f.file for f in fs_sorted})
            aid_src = f"{rule_id}:{cat_key}:" + "|".join(fingerprints)
            aid = hashlib.sha1(aid_src.encode("utf-8", errors="ignore")).hexdigest()[:12]

            action_plan.append(
                ActionItem(
                    id=f"action_{aid}",
                    rule_id=rule_id,
                    category=cat_key,
                    title=sample.title,
                    why_it_matters=sample.why_it_matters,
                    suggested_fix=sample.suggested_fix,
                    priority=priority,
                    max_severity=max_sev,
                    classification=max_classification,
                    finding_fingerprints=fingerprints,
                    files=files,
                )
            )

            # Multi-factor triage scoring (additive; action_plan stays unchanged)
            occurrences = len(fs_sorted)
            mean_conf = sum(float(getattr(f, "confidence", 0.0) or 0.0) for f in fs_sorted) / max(1, occurrences)
            occurrence_density = min(1.0, occurrences / 8.0)

            severity_norm = {
                Severity.CRITICAL: 1.0,
                Severity.HIGH: 0.82,
                Severity.MEDIUM: 0.62,
                Severity.LOW: 0.38,
                Severity.INFO: 0.2,
            }.get(max_sev, 0.4)
            impact = min(1.0, 0.55 * severity_norm + 0.30 * min(1.0, total_penalty / 20.0) + 0.15 * occurrence_density)

            cls_norm = {
                FindingClassification.DEFECT: 0.92,
                FindingClassification.RISK: 0.78,
                FindingClassification.ADVISORY: 0.46,
            }.get(max_classification, 0.5)
            security_boost = 0.12 if cat_key == Category.SECURITY.value else 0.0
            public_surface_boost = 0.0
            for finding in fs_sorted:
                dp = (finding.metadata or {}).get("decision_profile", {})
                if isinstance(dp, dict):
                    caps = dp.get("capabilities")
                    if isinstance(caps, list) and "public_surface" in {str(x) for x in caps}:
                        public_surface_boost = 0.08
                        break
            risk = min(1.0, 0.60 * cls_norm + 0.30 * mean_conf + security_boost + public_surface_boost)

            strategy = get_fix_strategy(rule_id)
            base_effort = {"safe": 0.2, "risky": 0.55, "refactor": 0.8}.get(strategy, 0.55)
            spread_factor = min(0.2, (max(0, len(files) - 1) / 5.0) * 0.2)
            avg_span = 1.0
            spans = []
            for finding in fs_sorted:
                ls = int(getattr(finding, "line_start", 1) or 1)
                le = int(getattr(finding, "line_end", ls) or ls)
                spans.append(max(1, le - ls + 1))
            if spans:
                avg_span = sum(spans) / len(spans)
            span_factor = min(0.2, (avg_span / 40.0) * 0.2)
            effort = min(1.0, base_effort + spread_factor + span_factor)

            context_multiplier = 1.0
            if cat_key == Category.SECURITY.value:
                context_multiplier += 0.10
            project_type = str(project_context.get("project_type") or project_context.get("project_business_context") or "").strip().lower()
            if cat_key == Category.SECURITY.value and project_type in {"fintech_platform", "healthcare_platform", "marketplace_platform"}:
                context_multiplier += 0.05
            context_multiplier *= float(memory_manager.get_rule_memory_factor(project_path, rule_id))
            context_multiplier = max(0.7, min(1.35, context_multiplier))

            triage_score = 100.0 * (impact ** w_impact) * (risk ** w_risk) * (1.0 - effort_discount * (effort ** w_effort)) * (context_multiplier ** w_context)
            triage_score = round(max(0.0, min(100.0, triage_score)), 2)

            if triage_score >= 60.0:
                recommendation = "fix_now"
            elif triage_score >= 35.0:
                recommendation = "schedule_next"
            elif cat_key != Category.SECURITY.value or max_classification != FindingClassification.DEFECT:
                recommendation = "ignore_safely_candidate"
            else:
                recommendation = "schedule_next"

            triage_id_src = f"{rule_id}:{cat_key}:{strategy}:{'|'.join(fingerprints)}"
            triage_id = hashlib.sha1(triage_id_src.encode("utf-8", errors="ignore")).hexdigest()[:12]
            rationale = (
                f"impact={impact:.2f}, risk={risk:.2f}, effort={effort:.2f}, "
                f"context_multiplier={context_multiplier:.2f}"
            )
            triage_plan.append(
                TriageItem(
                    id=f"triage_{triage_id}",
                    rule_id=rule_id,
                    category=cat_key,
                    title=sample.title,
                    strategy=strategy,
                    recommendation=recommendation,
                    impact=round(impact, 4),
                    risk=round(risk, 4),
                    effort=round(effort, 4),
                    context_multiplier=round(context_multiplier, 4),
                    triage_score=triage_score,
                    rationale=rationale,
                    max_severity=max_sev,
                    classification=max_classification,
                    finding_fingerprints=fingerprints,
                    files=files,
                )
            )

        action_plan.sort(key=lambda a: (-a.priority, a.category, a.rule_id, a.id))
        triage_plan.sort(key=lambda t: (-t.triage_score, t.category, t.rule_id, t.id))
        top_5_first = [item.id for item in triage_plan[:5]]
        safe_to_defer = [item.id for item in triage_plan if item.recommendation == "ignore_safely_candidate"]
        
        report = ScanReport(
            id=job_id,
            project_path=project_path,
            project_info=project_info if project_info is not None else ProjectInfo(root_path=project_path),
            scanned_at=datetime.now(timezone.utc),
            duration_ms=0, # Filled by job manager usually
            files_scanned=len(facts.files) if getattr(facts, "files", None) else 0,
            classes_found=len(facts.classes),
            methods_found=len(facts.methods),
            findings=findings,
            scores=scores,
            category_breakdown=scoring_result.category_scores,
            file_summaries=file_summaries,
            action_plan=action_plan,
            triage_plan=triage_plan,
            top_5_first=top_5_first,
            safe_to_defer=safe_to_defer,
            ruleset_path=ruleset_path,
            rules_executed=rules_executed or [],
            analysis_debug={
                "project_context": project_context,
                "project_memory": {
                    "project_hash": project_memory.project_hash,
                    "updated_at": project_memory.updated_at,
                },
            },
        )
        
        # Populate other computed fields
        report.compute_groups()
        
        return report
