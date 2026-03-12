"""
Finding Suppression Manager

Manages suppression rules for findings - allows ignoring specific findings
by rule ID, file pattern, or line number with optional expiration dates.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from schemas.finding import Finding


@dataclass
class SuppressionRule:
    """A single suppression rule."""
    id: str = ""
    rule_id: str = ""  # Rule to suppress (or "*" for all)
    file_pattern: str = ""  # Glob pattern for file path
    line_start: int | None = None  # Specific line (optional)
    line_end: int | None = None  # Line range end (optional)
    reason: str = ""  # Why this is suppressed
    until: date | None = None  # Expiration date (optional)
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""  # Author (optional)
    
    def matches(self, finding: Finding) -> bool:
        """Check if this suppression matches a finding."""
        # Check rule ID
        if self.rule_id != "*" and self.rule_id != finding.rule_id:
            return False
        
        # Check file pattern
        if self.file_pattern:
            file_path = str(finding.file or "")
            if not self._matches_pattern(file_path, self.file_pattern):
                return False
        
        # Check line range
        if self.line_start is not None:
            finding_line = finding.line_start or 0
            if self.line_end is not None:
                if not (self.line_start <= finding_line <= self.line_end):
                    return False
            else:
                if finding_line != self.line_start:
                    return False
        
        # Check expiration
        if self.until and date.today() > self.until:
            return False
        
        return True
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches glob pattern."""
        import fnmatch
        # Normalize paths
        norm_path = path.replace("\\", "/")
        norm_pattern = pattern.replace("\\", "/")
        return fnmatch.fnmatch(norm_path.lower(), norm_pattern.lower())
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "file_pattern": self.file_pattern,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "reason": self.reason,
            "until": self.until.isoformat() if self.until else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by": self.created_by,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SuppressionRule:
        """Create from dictionary."""
        until = None
        if data.get("until"):
            try:
                until = date.fromisoformat(data["until"])
            except (ValueError, TypeError):
                pass
        
        created_at = datetime.now()
        if data.get("created_at"):
            try:
                created_at = datetime.fromisoformat(data["created_at"])
            except (ValueError, TypeError):
                pass
        
        return cls(
            id=data.get("id", ""),
            rule_id=data.get("rule_id", "*"),
            file_pattern=data.get("file_pattern", ""),
            line_start=data.get("line_start"),
            line_end=data.get("line_end"),
            reason=data.get("reason", ""),
            until=until,
            created_at=created_at,
            created_by=data.get("created_by", ""),
        )


@dataclass
class SuppressionFile:
    """Represents a .bpd-suppressions.json file."""
    version: str = "1.0"
    suppressions: list[SuppressionRule] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": self.version,
            "suppressions": [s.to_dict() for s in self.suppressions],
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SuppressionFile:
        """Create from dictionary."""
        suppressions = [
            SuppressionRule.from_dict(s)
            for s in data.get("suppressions", [])
        ]
        return cls(
            version=data.get("version", "1.0"),
            suppressions=suppressions,
        )


class SuppressionManager:
    """
    Manages finding suppressions for a project.
    
    Suppressions are stored in:
    - Project root: .bpd-suppressions.json
    - App data: suppressions/{project_hash}.json (global suppressions)
    
    Suppression file format:
    {
        "version": "1.0",
        "suppressions": [
            {
                "id": "suppress-001",
                "rule_id": "no-dangerously-set-inner-html",
                "file_pattern": "src/components/LegacyHtml.tsx",
                "reason": "Legacy component, scheduled for refactor",
                "until": "2025-12-31"
            }
        ]
    }
    """
    
    FILE_NAME = ".bpd-suppressions.json"
    
    def __init__(self, project_path: str | Path):
        self.project_path = Path(project_path).resolve()
        self.suppression_file: SuppressionFile | None = None
        self._load()
    
    def _load(self) -> None:
        """Load suppressions from file."""
        file_path = self.project_path / self.FILE_NAME
        if file_path.exists():
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
                self.suppression_file = SuppressionFile.from_dict(data)
            except (json.JSONDecodeError, KeyError) as e:
                import logging
                logging.warning(f"Failed to load suppressions: {e}")
                self.suppression_file = SuppressionFile()
        else:
            self.suppression_file = SuppressionFile()
    
    def save(self) -> None:
        """Save suppressions to file."""
        if not self.suppression_file:
            return
        
        file_path = self.project_path / self.FILE_NAME
        file_path.write_text(
            json.dumps(self.suppression_file.to_dict(), indent=2),
            encoding="utf-8"
        )
    
    def is_suppressed(self, finding: Finding) -> tuple[bool, SuppressionRule | None]:
        """
        Check if a finding is suppressed.
        
        Returns:
            (is_suppressed, matching_rule or None)
        """
        if not self.suppression_file:
            return (False, None)
        
        for rule in self.suppression_file.suppressions:
            if rule.matches(finding):
                return (True, rule)
        
        return (False, None)
    
    def add_suppression(
        self,
        rule_id: str,
        file_pattern: str = "",
        line_start: int | None = None,
        line_end: int | None = None,
        reason: str = "",
        until: date | None = None,
        created_by: str = "",
    ) -> SuppressionRule:
        """Add a new suppression rule."""
        import uuid
        
        rule = SuppressionRule(
            id=f"suppress-{uuid.uuid4().hex[:8]}",
            rule_id=rule_id,
            file_pattern=file_pattern,
            line_start=line_start,
            line_end=line_end,
            reason=reason,
            until=until,
            created_by=created_by,
        )
        
        if not self.suppression_file:
            self.suppression_file = SuppressionFile()
        
        self.suppression_file.suppressions.append(rule)
        self.save()
        
        return rule
    
    def remove_suppression(self, suppression_id: str) -> bool:
        """Remove a suppression by ID."""
        if not self.suppression_file:
            return False
        
        original_count = len(self.suppression_file.suppressions)
        self.suppression_file.suppressions = [
            s for s in self.suppression_file.suppressions
            if s.id != suppression_id
        ]
        
        if len(self.suppression_file.suppressions) < original_count:
            self.save()
            return True
        
        return False
    
    def list_suppressions(self) -> list[SuppressionRule]:
        """List all suppression rules."""
        return list(self.suppression_file.suppressions) if self.suppression_file else []
    
    def clear_expired(self) -> int:
        """Remove expired suppressions. Returns count removed."""
        if not self.suppression_file:
            return 0
        
        original_count = len(self.suppression_file.suppressions)
        self.suppression_file.suppressions = [
            s for s in self.suppression_file.suppressions
            if not (s.until and date.today() > s.until)
        ]
        
        removed = original_count - len(self.suppression_file.suppressions)
        if removed > 0:
            self.save()
        
        return removed
    
    def apply_to_findings(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """
        Apply suppressions to a list of findings.
        
        Returns:
            (active_findings, suppressed_findings)
        """
        active: list[Finding] = []
        suppressed: list[Finding] = []
        
        for finding in findings:
            is_suppressed, rule = self.is_suppressed(finding)
            if is_suppressed:
                # Add suppression info to finding metadata
                if hasattr(finding, "metadata") and finding.metadata is not None:
                    finding.metadata["suppressed_by"] = rule.id if rule else None
                suppressed.append(finding)
            else:
                active.append(finding)
        
        return (active, suppressed)
