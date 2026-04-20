"""Scan pipeline error hierarchy with stage-aware context."""

from __future__ import annotations


class ScanError(Exception):
    """Base scan pipeline error."""

    def __init__(self, message: str, *, stage: str, context: dict[str, object] | None = None):
        super().__init__(message)
        self.stage = stage
        self.context = dict(context or {})

    def __str__(self) -> str:
        base = super().__str__()
        if not self.context:
            return f"[{self.stage}] {base}"
        ctx = ", ".join(f"{k}={v}" for k, v in sorted(self.context.items()))
        return f"[{self.stage}] {base} ({ctx})"


class ProjectDetectionError(ScanError):
    """Critical failure while detecting project type."""


class FactBuildError(ScanError):
    """Critical failure while building facts."""


class RuleExecutionError(ScanError):
    """Critical failure while executing rules."""


class ScoringError(ScanError):
    """Critical failure while generating a scored report."""


class ReportingError(ScanError):
    """Failure while applying optional reporting enrichments."""

