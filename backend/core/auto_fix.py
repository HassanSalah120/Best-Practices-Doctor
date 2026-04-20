"""
Auto-Fix Engine

Generates fix suggestions and diffs for common code issues.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.fix_intelligence import evaluate_fix_confidence, get_fix_strategy
from schemas.finding import Finding


@dataclass
class FixSuggestion:
    """A suggested fix for a finding."""
    rule_id: str
    title: str
    description: str
    original_code: str
    fixed_code: str
    line_start: int
    line_end: int
    confidence: float = 0.8
    auto_applicable: bool = False  # Can this be auto-applied?
    strategy: str = "risky"  # safe|risky|refactor
    confidence_breakdown: dict[str, float] = field(default_factory=dict)
    why_correct_for_project: str = ""
    risk_notes: str = ""
    requires_human_review: bool = True
    
    def to_diff(self) -> str:
        """Generate a unified diff for this fix."""
        original_lines = self.original_code.splitlines()
        fixed_lines = self.fixed_code.splitlines()
        
        diff_lines = [
            f"--- original (line {self.line_start})",
            f"+++ fixed",
            f"@@ -{self.line_start},{len(original_lines)} +{self.line_start},{len(fixed_lines)} @@",
        ]
        
        for line in original_lines:
            diff_lines.append(f"-{line}")
        
        for line in fixed_lines:
            diff_lines.append(f"+{line}")
        
        return "\n".join(diff_lines)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "original_code": self.original_code,
            "fixed_code": self.fixed_code,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "confidence": self.confidence,
            "auto_applicable": self.auto_applicable,
            "strategy": self.strategy,
            "confidence_breakdown": dict(self.confidence_breakdown),
            "why_correct_for_project": self.why_correct_for_project,
            "risk_notes": self.risk_notes,
            "requires_human_review": self.requires_human_review,
            "diff": self.to_diff(),
        }


class AutoFixEngine:
    """
    Generates fix suggestions for common code issues.
    
    Supports auto-fix for:
    - Missing imports
    - Simple refactoring patterns
    - Common Laravel patterns
    - Common React patterns
    """
    
    # Fix patterns for different rules
    _FIX_PATTERNS = {
        # Laravel: Missing Form Request
        "missing-form-request": {
            "pattern": r"public function (store|update)\s*\([^)]*\$request[^)]*\)",
            "fix_template": "public function {method}({form_request} $request)",
            "description": "Use Form Request for validation",
        },
        
        # Laravel: Env outside config
        "env-outside-config": {
            "pattern": r"env\(['\"]([A-Z_]+)['\"]\)",
            "fix_template": "config('app.{key}')",
            "description": "Move env() to config file and use config()",
        },
        
        # Laravel: No log debug in app
        "no-log-debug-in-app": {
            "pattern": r"Log::debug\(",
            "fix_template": "Log::info(",
            "description": "Use Log::info() instead of Log::debug() in production code",
        },
        
        # React: No array index key
        "react-no-array-index-key": {
            "pattern": r"key=\{\s*(?:index|i)\s*\}",
            "fix_template": 'key={item.id || `item-${index}`}',
            "description": "Use stable key from data instead of array index",
        },
        
        # React: Missing key on list render
        "missing-key-on-list-render": {
            "pattern": r"<(\w+)(?![^>]*key=)[^>]*>\s*\{[^}]*\}",
            "fix_template": '<$1 key={item.id}>$2</$1>',
            "description": "Add unique key prop to list items",
        },
        
        # React: Hooks in conditional
        "hooks-in-conditional-or-loop": {
            "pattern": r"(if\s*\([^)]*\)\s*\{[^}]*)(use[A-Z]\w+\()",
            "fix_template": "// Move hook to top of component\n$2",
            "description": "Move hooks to top level of component",
        },
        
        # React: No dangerously set inner HTML
        "no-dangerously-set-inner-html": {
            "pattern": r"dangerouslySetInnerHTML=\{\{__html:\s*([^}]+)\}\}",
            "fix_template": "{/* Use text content or DOMPurify */}\n{DOMPurify.sanitize($1)}",
            "description": "Sanitize HTML with DOMPurify or use text content",
        },
        
        # PHP: Prefer imports
        "prefer-imports": {
            "pattern": r"\\([A-Z][a-zA-Z0-9\\]+)::",
            "fix_template": "use $1;\n... $2::",
            "description": "Add use statement instead of FQCN",
        },
    }
    
    def __init__(
        self,
        project_path: str | Path | None = None,
        *,
        project_context: dict[str, Any] | None = None,
    ):
        self.project_path = Path(project_path) if project_path else None
        self.project_context = dict(project_context or {})
    
    def get_fix_suggestion(self, finding: Finding, file_content: str) -> FixSuggestion | None:
        """
        Generate a fix suggestion for a finding.
        
        Args:
            finding: The finding to fix
            file_content: The content of the file containing the issue
        
        Returns:
            FixSuggestion or None if no fix is available
        """
        rule_id = finding.rule_id
        
        # Get fix pattern for this rule
        fix_config = self._FIX_PATTERNS.get(rule_id)
        if not fix_config:
            return None
        
        # Extract the problematic code
        lines = file_content.splitlines()
        line_start = finding.line_start or 1
        line_end = finding.line_end or line_start
        
        if line_start < 1 or line_start > len(lines):
            return None
        
        original_code = "\n".join(lines[line_start - 1 : line_end])
        
        # Apply rule-specific fix logic
        fixed_code = self._apply_fix(rule_id, original_code, finding)
        if not fixed_code:
            return None
        
        strategy = get_fix_strategy(rule_id)
        confidence, breakdown, fit_reason, risk_notes = evaluate_fix_confidence(
            finding=finding,
            original_code=original_code,
            fixed_code=fixed_code,
            strategy=strategy,
            project_context=self.project_context,
        )
        auto_applicable = self._is_auto_applicable(rule_id, strategy)

        return FixSuggestion(
            rule_id=rule_id,
            title=f"Fix: {finding.title}",
            description=fix_config.get("description", ""),
            original_code=original_code,
            fixed_code=fixed_code,
            line_start=line_start,
            line_end=line_end,
            confidence=confidence,
            auto_applicable=auto_applicable,
            strategy=strategy,
            confidence_breakdown=breakdown,
            why_correct_for_project=fit_reason,
            risk_notes=risk_notes,
            requires_human_review=(strategy != "safe" or not auto_applicable),
        )
    
    def _apply_fix(self, rule_id: str, code: str, finding: Finding) -> str | None:
        """Apply rule-specific fix logic."""
        
        if rule_id == "env-outside-config":
            # Replace env() with config()
            match = re.search(r"env\(['\"]([A-Z_]+)['\"]\)", code)
            if match:
                key = match.group(1).lower()
                return re.sub(
                    r"env\(['\"][A-Z_]+['\"]\)",
                    f"config('app.{key}')",
                    code,
                    count=1
                )
        
        elif rule_id == "no-log-debug-in-app":
            # Replace Log::debug with Log::info
            return code.replace("Log::debug(", "Log::info(")
        
        elif rule_id == "react-no-array-index-key":
            # Suggest using stable key
            if "key={index}" in code or "key={i}" in code:
                # This is a suggestion, not auto-fixable
                return code.replace(
                    "key={index}",
                    "key={item.id || `item-${index}`}"
                ).replace(
                    "key={i}",
                    "key={item.id || `item-${i}`}"
                )
        
        elif rule_id == "no-dangerously-set-inner-html":
            # Add DOMPurify suggestion
            match = re.search(r"dangerouslySetInnerHTML=\{\{__html:\s*([^}]+)\}\}", code)
            if match:
                var = match.group(1).strip()
                return f"{{/* Sanitize HTML before rendering */}}\n{{{{ DOMPurify.sanitize({var}) }}}}"
        
        elif rule_id == "prefer-imports":
            # Extract FQCN and suggest import
            match = re.search(r"\\([A-Z][a-zA-Z0-9\\]+)(?:::|$)", code)
            if match:
                fqn = match.group(1)
                class_name = fqn.split("\\")[-1]
                # Return the import suggestion
                return f"use {fqn};\n\n// Then use: {class_name}::"
        
        return None
    
    def _is_auto_applicable(self, rule_id: str, strategy: str) -> bool:
        """Check if fix can be auto-applied safely."""
        safe_rules = {"no-log-debug-in-app"}
        return strategy == "safe" and rule_id in safe_rules
    
    def get_fixes_for_findings(
        self,
        findings: list[Finding],
        project_path: str | Path,
    ) -> dict[str, list[FixSuggestion]]:
        """
        Get fix suggestions for multiple findings.
        
        Returns:
            Dict mapping file path to list of fix suggestions
        """
        fixes: dict[str, list[FixSuggestion]] = {}
        project = Path(project_path)
        
        # Group findings by file
        by_file: dict[str, list[Finding]] = {}
        for f in findings:
            if f.file:
                by_file.setdefault(f.file, []).append(f)
        
        # Get fixes for each file
        for rel_path, file_findings in by_file.items():
            try:
                file_path = project / rel_path
                content = file_path.read_text(encoding="utf-8", errors="replace")
                
                for finding in file_findings:
                    fix = self.get_fix_suggestion(finding, content)
                    if fix:
                        fixes.setdefault(rel_path, []).append(fix)
            except Exception:
                continue
        
        return fixes
    
    def apply_fix(
        self,
        file_path: str | Path,
        fix: FixSuggestion,
        dry_run: bool = True,
    ) -> tuple[bool, str]:
        """
        Apply a fix to a file.
        
        Args:
            file_path: Path to the file
            fix: The fix to apply
            dry_run: If True, don't actually modify the file
        
        Returns:
            (success, new_content_or_error_message)
        """
        try:
            path = Path(file_path)
            content = path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            
            # Replace the lines
            start_idx = fix.line_start - 1
            end_idx = fix.line_end
            
            new_lines = (
                lines[:start_idx]
                + fix.fixed_code.splitlines()
                + lines[end_idx:]
            )
            
            new_content = "\n".join(new_lines)
            
            if not dry_run:
                path.write_text(new_content, encoding="utf-8")
            
            return (True, new_content)
        
        except Exception as e:
            return (False, str(e))
