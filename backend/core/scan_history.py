"""
Scan History Manager

Tracks scan history over time for trend analysis and visualization.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from schemas.report import ScanReport


@dataclass
class ScanSummary:
    """Summary of a single scan for history tracking."""
    job_id: str
    project_path: str
    project_hash: str  # Hash of project path for grouping
    timestamp: datetime
    overall_score: float
    grade: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    category_scores: dict[str, float]
    files_scanned: int
    execution_time_ms: float
    profile: str
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "job_id": self.job_id,
            "project_path": self.project_path,
            "project_hash": self.project_hash,
            "timestamp": self.timestamp.isoformat(),
            "overall_score": self.overall_score,
            "grade": self.grade,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "category_scores": self.category_scores,
            "files_scanned": self.files_scanned,
            "execution_time_ms": self.execution_time_ms,
            "profile": self.profile,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanSummary:
        """Create from dictionary."""
        timestamp = data.get("timestamp", "")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()
        
        return cls(
            job_id=data.get("job_id", ""),
            project_path=data.get("project_path", ""),
            project_hash=data.get("project_hash", ""),
            timestamp=timestamp,
            overall_score=data.get("overall_score", 0.0),
            grade=data.get("grade", "F"),
            total_findings=data.get("total_findings", 0),
            critical_count=data.get("critical_count", 0),
            high_count=data.get("high_count", 0),
            medium_count=data.get("medium_count", 0),
            low_count=data.get("low_count", 0),
            info_count=data.get("info_count", 0),
            category_scores=data.get("category_scores", {}),
            files_scanned=data.get("files_scanned", 0),
            execution_time_ms=data.get("execution_time_ms", 0.0),
            profile=data.get("profile", "startup"),
        )
    
    @classmethod
    def from_report(cls, report: ScanReport, profile: str = "startup") -> ScanSummary:
        """Create from a ScanReport."""
        project_hash = hashlib.sha256(report.project_path.encode()).hexdigest()[:16]
        
        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in report.findings:
            sev = str(finding.severity).lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Get category scores
        category_scores = {}
        if hasattr(report, "quality_scores") and report.quality_scores:
            for cat_score in report.quality_scores.category_scores:
                category_scores[cat_score.category] = cat_score.score
        
        return cls(
            job_id=report.job_id,
            project_path=report.project_path,
            project_hash=project_hash,
            timestamp=datetime.now(),
            overall_score=report.quality_scores.overall_score if report.quality_scores else 0.0,
            grade=report.quality_scores.grade if report.quality_scores else "F",
            total_findings=len(report.findings),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            info_count=severity_counts["info"],
            category_scores=category_scores,
            files_scanned=len(report.file_summaries) if report.file_summaries else 0,
            execution_time_ms=report.execution_time_ms if hasattr(report, "execution_time_ms") else 0.0,
            profile=profile,
        )


@dataclass
class ScanHistory:
    """Collection of scan summaries for a project."""
    project_hash: str
    project_path: str
    scans: list[ScanSummary] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "project_hash": self.project_hash,
            "project_path": self.project_path,
            "scans": [s.to_dict() for s in self.scans],
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanHistory:
        """Create from dictionary."""
        scans = [ScanSummary.from_dict(s) for s in data.get("scans", [])]
        return cls(
            project_hash=data.get("project_hash", ""),
            project_path=data.get("project_path", ""),
            scans=scans,
        )


class ScanHistoryManager:
    """
    Manages scan history for trend analysis.
    
    History is stored in:
    - App data directory: scan_history/{project_hash}.json
    
    Features:
    - Track multiple scans per project
    - Calculate trends (improving/regressing)
    - Compare scores over time
    """
    
    HISTORY_DIR = "scan_history"
    MAX_SCANS_PER_PROJECT = 50  # Keep last 50 scans
    
    def __init__(self, app_data_dir: str | Path | None = None):
        if app_data_dir:
            self.history_dir = Path(app_data_dir) / self.HISTORY_DIR
        else:
            # Default to user home or temp
            import os
            app_data = os.environ.get("BPD_APP_DATA_DIR")
            if app_data:
                self.history_dir = Path(app_data) / self.HISTORY_DIR
            else:
                self.history_dir = Path.home() / ".bpd" / self.HISTORY_DIR
        
        self.history_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_history_file(self, project_hash: str) -> Path:
        """Get the history file path for a project."""
        return self.history_dir / f"{project_hash}.json"
    
    def add_scan(self, report: ScanReport, profile: str = "startup") -> ScanSummary:
        """
        Add a scan to history.
        
        Returns:
            The created ScanSummary
        """
        summary = ScanSummary.from_report(report, profile)
        
        # Load existing history
        history = self.get_history(summary.project_hash)
        
        # Update project path if needed
        if not history.project_path:
            history.project_path = summary.project_path
        
        # Add new scan
        history.scans.append(summary)
        
        # Trim to max scans
        if len(history.scans) > self.MAX_SCANS_PER_PROJECT:
            history.scans = history.scans[-self.MAX_SCANS_PER_PROJECT:]
        
        # Save
        self._save_history(history)
        
        return summary
    
    def get_history(self, project_hash: str) -> ScanHistory:
        """Get scan history for a project."""
        file_path = self._get_history_file(project_hash)
        
        if file_path.exists():
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
                return ScanHistory.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                pass
        
        return ScanHistory(project_hash=project_hash, project_path="")
    
    def get_history_by_path(self, project_path: str) -> ScanHistory:
        """Get scan history by project path."""
        project_hash = hashlib.sha256(project_path.encode()).hexdigest()[:16]
        return self.get_history(project_hash)
    
    def _save_history(self, history: ScanHistory) -> None:
        """Save history to file."""
        file_path = self._get_history_file(history.project_hash)
        file_path.write_text(
            json.dumps(history.to_dict(), indent=2),
            encoding="utf-8"
        )
    
    def get_trend(self, project_hash: str, limit: int = 10) -> dict[str, Any]:
        """
        Get trend analysis for a project.
        
        Returns:
            Dict with trend data:
            - direction: "improving", "regressing", "stable"
            - score_change: change in score from first to last
            - recent_scans: list of recent scan summaries
            - chart_data: data suitable for charting
        """
        history = self.get_history(project_hash)
        
        if len(history.scans) < 2:
            return {
                "direction": "insufficient_data",
                "score_change": 0.0,
                "recent_scans": [s.to_dict() for s in history.scans[-limit:]],
                "chart_data": [],
            }
        
        recent = history.scans[-limit:]
        
        first_score = recent[0].overall_score
        last_score = recent[-1].overall_score
        score_change = last_score - first_score
        
        # Determine direction
        if score_change > 5:
            direction = "improving"
        elif score_change < -5:
            direction = "regressing"
        else:
            direction = "stable"
        
        # Prepare chart data
        chart_data = [
            {
                "date": s.timestamp.isoformat(),
                "score": s.overall_score,
                "findings": s.total_findings,
                "grade": s.grade,
            }
            for s in recent
        ]
        
        return {
            "direction": direction,
            "score_change": round(score_change, 2),
            "recent_scans": [s.to_dict() for s in recent],
            "chart_data": chart_data,
            "first_scan": recent[0].to_dict(),
            "last_scan": recent[-1].to_dict(),
        }
    
    def get_category_trend(self, project_hash: str, category: str, limit: int = 10) -> dict[str, Any]:
        """Get trend for a specific category."""
        history = self.get_history(project_hash)
        
        recent = history.scans[-limit:]
        
        chart_data = [
            {
                "date": s.timestamp.isoformat(),
                "score": s.category_scores.get(category, 0),
            }
            for s in recent
            if category in s.category_scores
        ]
        
        return {
            "category": category,
            "chart_data": chart_data,
        }
    
    def clear_history(self, project_hash: str) -> bool:
        """Clear history for a project."""
        file_path = self._get_history_file(project_hash)
        if file_path.exists():
            file_path.unlink()
            return True
        return False
    
    def list_projects(self) -> list[dict[str, Any]]:
        """List all projects with scan history."""
        projects = []
        
        for file_path in self.history_dir.glob("*.json"):
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
                projects.append({
                    "project_hash": data.get("project_hash", ""),
                    "project_path": data.get("project_path", ""),
                    "scan_count": len(data.get("scans", [])),
                    "last_scan": data.get("scans", [{}])[-1].get("timestamp") if data.get("scans") else None,
                })
            except (json.JSONDecodeError, KeyError):
                continue
        
        return projects
