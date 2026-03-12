"""
Incremental Scan Manager

Tracks file changes and enables scanning only modified files
for improved performance on large codebases.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class FileFingerprint:
    """Fingerprint for a single file."""
    path: str  # Relative path
    size: int
    modified_time: float
    content_hash: str  # MD5 hash of content
    last_scanned: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "modified_time": self.modified_time,
            "content_hash": self.content_hash,
            "last_scanned": self.last_scanned.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileFingerprint:
        last_scanned = datetime.now()
        if data.get("last_scanned"):
            try:
                last_scanned = datetime.fromisoformat(data["last_scanned"])
            except (ValueError, TypeError):
                pass
        
        return cls(
            path=data.get("path", ""),
            size=data.get("size", 0),
            modified_time=data.get("modified_time", 0.0),
            content_hash=data.get("content_hash", ""),
            last_scanned=last_scanned,
        )


@dataclass
class ScanManifest:
    """Manifest tracking all scanned files for a project."""
    project_path: str
    project_hash: str
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    files: dict[str, FileFingerprint] = field(default_factory=dict)
    total_files: int = 0
    total_size: int = 0
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "project_hash": self.project_hash,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "files": {k: v.to_dict() for k, v in self.files.items()},
            "total_files": self.total_files,
            "total_size": self.total_size,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanManifest:
        files = {
            k: FileFingerprint.from_dict(v)
            for k, v in data.get("files", {}).items()
        }
        
        created_at = datetime.now()
        if data.get("created_at"):
            try:
                created_at = datetime.fromisoformat(data["created_at"])
            except (ValueError, TypeError):
                pass
        
        updated_at = datetime.now()
        if data.get("updated_at"):
            try:
                updated_at = datetime.fromisoformat(data["updated_at"])
            except (ValueError, TypeError):
                pass
        
        return cls(
            project_path=data.get("project_path", ""),
            project_hash=data.get("project_hash", ""),
            created_at=created_at,
            updated_at=updated_at,
            files=files,
            total_files=data.get("total_files", 0),
            total_size=data.get("total_size", 0),
        )


class IncrementalScanManager:
    """
    Manages incremental scanning by tracking file fingerprints.
    
    Features:
    - Track file content hashes for change detection
    - Detect added, modified, and deleted files
    - Support for git-based change detection
    - Manifest persistence for cross-session tracking
    
    Usage:
        manager = IncrementalScanManager(project_path)
        
        # First scan - builds manifest
        changed = manager.detect_changes(all_files)
        
        # Subsequent scans - only changed files
        changed = manager.detect_changes(all_files)
        
        # Update manifest after scan
        manager.update_manifest(scanned_files)
    """
    
    MANIFEST_DIR = "scan_manifests"
    MANIFEST_FILE = "manifest.json"
    
    def __init__(self, project_path: str | Path):
        self.project_path = Path(project_path).resolve()
        self.project_hash = hashlib.sha256(str(self.project_path).encode()).hexdigest()[:16]
        self.manifest: ScanManifest | None = None
        self._load_manifest()
    
    def _get_manifest_path(self) -> Path:
        """Get the manifest file path."""
        # Store in app data directory
        app_data = os.environ.get("BPD_APP_DATA_DIR")
        if app_data:
            manifest_dir = Path(app_data) / self.MANIFEST_DIR
        else:
            manifest_dir = Path.home() / ".bpd" / self.MANIFEST_DIR
        
        manifest_dir.mkdir(parents=True, exist_ok=True)
        return manifest_dir / f"{self.project_hash}.json"
    
    def _load_manifest(self) -> None:
        """Load manifest from disk."""
        manifest_path = self._get_manifest_path()
        
        if manifest_path.exists():
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                self.manifest = ScanManifest.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                self.manifest = None
        
        if not self.manifest:
            self.manifest = ScanManifest(
                project_path=str(self.project_path),
                project_hash=self.project_hash,
            )
    
    def _save_manifest(self) -> None:
        """Save manifest to disk."""
        if not self.manifest:
            return
        
        manifest_path = self._get_manifest_path()
        manifest_path.write_text(
            json.dumps(self.manifest.to_dict(), indent=2),
            encoding="utf-8"
        )
    
    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute MD5 hash of file content."""
        try:
            content = file_path.read_bytes()
            return hashlib.md5(content).hexdigest()
        except Exception:
            return ""
    
    def _get_file_info(self, rel_path: str) -> FileFingerprint | None:
        """Get fingerprint for a file."""
        full_path = self.project_path / rel_path
        
        if not full_path.exists():
            return None
        
        try:
            stat = full_path.stat()
            content_hash = self._compute_file_hash(full_path)
            
            return FileFingerprint(
                path=rel_path,
                size=stat.st_size,
                modified_time=stat.st_mtime,
                content_hash=content_hash,
            )
        except Exception:
            return None
    
    def detect_changes(
        self,
        current_files: list[str],
        use_git: bool = False,
        git_ref: str = "HEAD",
    ) -> dict[str, list[str]]:
        """
        Detect file changes since last scan.
        
        Args:
            current_files: List of all files in project
            use_git: Use git to detect changes (faster for git repos)
            git_ref: Git reference to compare against
        
        Returns:
            Dict with keys:
            - 'added': New files not in manifest
            - 'modified': Files with changed content
            - 'deleted': Files in manifest but not in current
            - 'unchanged': Files with same content hash
        """
        result = {
            "added": [],
            "modified": [],
            "deleted": [],
            "unchanged": [],
        }
        
        if not self.manifest:
            # First scan - all files are "added"
            result["added"] = list(current_files)
            return result
        
        current_set = set(current_files)
        manifest_set = set(self.manifest.files.keys())
        
        # Detect added files
        result["added"] = list(current_set - manifest_set)
        
        # Detect deleted files
        result["deleted"] = list(manifest_set - current_set)
        
        # Check for modifications in existing files
        for rel_path in current_set & manifest_set:
            current_info = self._get_file_info(rel_path)
            if not current_info:
                continue
            
            manifest_info = self.manifest.files.get(rel_path)
            if not manifest_info:
                result["added"].append(rel_path)
            elif current_info.content_hash != manifest_info.content_hash:
                result["modified"].append(rel_path)
            else:
                result["unchanged"].append(rel_path)
        
        return result
    
    def get_changed_files(
        self,
        current_files: list[str],
        include_added: bool = True,
        include_modified: bool = True,
    ) -> list[str]:
        """
        Get list of files that need to be scanned.
        
        Args:
            current_files: List of all files in project
            include_added: Include newly added files
            include_modified: Include modified files
        
        Returns:
            List of files that need scanning
        """
        changes = self.detect_changes(current_files)
        
        result = []
        if include_added:
            result.extend(changes["added"])
        if include_modified:
            result.extend(changes["modified"])
        
        return result
    
    def update_manifest(self, scanned_files: list[str]) -> None:
        """
        Update manifest with scanned files.
        
        Call this after a scan completes to record the new state.
        """
        if not self.manifest:
            self.manifest = ScanManifest(
                project_path=str(self.project_path),
                project_hash=self.project_hash,
            )
        
        for rel_path in scanned_files:
            file_info = self._get_file_info(rel_path)
            if file_info:
                self.manifest.files[rel_path] = file_info
        
        self.manifest.updated_at = datetime.now()
        self.manifest.total_files = len(self.manifest.files)
        self.manifest.total_size = sum(f.size for f in self.manifest.files.values())
        
        self._save_manifest()
    
    def clear_manifest(self) -> None:
        """Clear the manifest (force full rescan)."""
        manifest_path = self._get_manifest_path()
        if manifest_path.exists():
            manifest_path.unlink()
        
        self.manifest = ScanManifest(
            project_path=str(self.project_path),
            project_hash=self.project_hash,
        )
    
    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the manifest."""
        if not self.manifest:
            return {
                "exists": False,
                "total_files": 0,
                "total_size": 0,
            }
        
        return {
            "exists": True,
            "project_path": self.manifest.project_path,
            "total_files": self.manifest.total_files,
            "total_size": self.manifest.total_size,
            "total_size_mb": round(self.manifest.total_size / (1024 * 1024), 2),
            "created_at": self.manifest.created_at.isoformat(),
            "updated_at": self.manifest.updated_at.isoformat(),
        }
    
    def get_git_changed_files(self, base_ref: str = "HEAD~1") -> list[str]:
        """
        Get files changed in git since a reference.
        
        This is faster than content hashing for git repos.
        """
        import subprocess
        
        try:
            # Get changed files from git
            result = subprocess.run(
                ["git", "diff", "--name-only", base_ref],
                cwd=str(self.project_path),
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        except Exception:
            pass
        
        return []
    
    def get_git_staged_files(self) -> list[str]:
        """Get files staged for commit."""
        import subprocess
        
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                cwd=str(self.project_path),
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        except Exception:
            pass
        
        return []
