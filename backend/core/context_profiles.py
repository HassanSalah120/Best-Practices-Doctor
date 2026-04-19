"""
Laravel Context Profile Matrix

Loads and resolves architecture profile/capability/team-toggle context with explicit
selection precedence over auto-detection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ContextSignalState(BaseModel):
    enabled: bool = False
    confidence: float = 0.0
    source: str = "default"  # explicit|detected|default
    evidence: list[str] = Field(default_factory=list)


class EffectiveContext(BaseModel):
    framework: str = "laravel"
    project_type: str = "unknown"
    project_type_confidence: float = 0.0
    project_type_confidence_kind: str = "unknown"  # structural|heuristic|unknown
    project_type_source: str = "default"
    architecture_profile: str = "unknown"
    architecture_profile_confidence: float = 0.0
    architecture_profile_confidence_kind: str = "unknown"  # structural|heuristic|unknown
    architecture_profile_source: str = "default"
    capabilities: dict[str, ContextSignalState] = Field(default_factory=dict)
    team_expectations: dict[str, ContextSignalState] = Field(default_factory=dict)


class ContextProfileMatrix(BaseModel):
    schema_version: int = 1
    framework: str = "laravel"
    description: str = ""
    project_types: dict[str, dict[str, Any]] = Field(default_factory=dict)
    profiles: dict[str, dict[str, Any]] = Field(default_factory=dict)
    capabilities: dict[str, dict[str, Any]] = Field(default_factory=dict)
    team_expectations: dict[str, dict[str, Any]] = Field(default_factory=dict)
    rule_behavior: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "ContextProfileMatrix":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Context profile matrix not found: {p}")
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls(**data)

    @classmethod
    def load_default(cls) -> "ContextProfileMatrix":
        backend_root = Path(__file__).resolve().parents[1]
        return cls.load(backend_root / "rulesets" / "laravel_context_matrix.yaml")

    def resolve_context(
        self,
        explicit_project_type: str | None = None,
        detected_project_type: str | None = None,
        detected_project_type_confidence: float = 0.0,
        detected_project_type_confidence_kind: str = "unknown",
        explicit_profile: str | None = None,
        detected_profile: str | None = None,
        detected_profile_confidence: float = 0.0,
        detected_profile_confidence_kind: str = "unknown",
        explicit_capabilities: dict[str, bool] | None = None,
        detected_capabilities: dict[str, tuple[bool, float, list[str]]] | None = None,
        explicit_expectations: dict[str, bool] | None = None,
        detected_expectations: dict[str, tuple[bool, float, list[str]]] | None = None,
    ) -> EffectiveContext:
        effective = EffectiveContext(framework=self.framework)

        project_types = set(self.project_types.keys())
        if explicit_project_type and explicit_project_type in project_types:
            effective.project_type = explicit_project_type
            effective.project_type_source = "explicit"
            effective.project_type_confidence = 1.0
            effective.project_type_confidence_kind = "structural"
        elif detected_project_type and detected_project_type in project_types:
            effective.project_type = detected_project_type
            effective.project_type_source = "detected"
            effective.project_type_confidence = max(0.0, min(1.0, float(detected_project_type_confidence or 0.0)))
            kind = str(detected_project_type_confidence_kind or "unknown").strip().lower()
            effective.project_type_confidence_kind = kind if kind in {"structural", "heuristic", "unknown"} else "unknown"
        else:
            effective.project_type = "unknown"
            effective.project_type_source = "default"
            effective.project_type_confidence = 0.0
            effective.project_type_confidence_kind = "unknown"

        profiles = set(self.profiles.keys())
        if explicit_profile and explicit_profile in profiles:
            effective.architecture_profile = explicit_profile
            effective.architecture_profile_source = "explicit"
            effective.architecture_profile_confidence = 1.0
            effective.architecture_profile_confidence_kind = "structural"
        elif detected_profile and detected_profile in profiles:
            effective.architecture_profile = detected_profile
            effective.architecture_profile_source = "detected"
            effective.architecture_profile_confidence = max(0.0, min(1.0, float(detected_profile_confidence or 0.0)))
            kind = str(detected_profile_confidence_kind or "unknown").strip().lower()
            effective.architecture_profile_confidence_kind = kind if kind in {"structural", "heuristic", "unknown"} else "unknown"
        else:
            effective.architecture_profile = "unknown"
            effective.architecture_profile_source = "default"
            effective.architecture_profile_confidence = 0.0
            effective.architecture_profile_confidence_kind = "unknown"

        exp_caps = explicit_capabilities or {}
        det_caps = detected_capabilities or {}
        for key in self.capabilities.keys():
            if key in exp_caps:
                effective.capabilities[key] = ContextSignalState(
                    enabled=bool(exp_caps[key]),
                    confidence=1.0,
                    source="explicit",
                    evidence=[],
                )
            elif key in det_caps:
                enabled, confidence, evidence = det_caps[key]
                effective.capabilities[key] = ContextSignalState(
                    enabled=bool(enabled),
                    confidence=max(0.0, min(1.0, float(confidence or 0.0))),
                    source="detected",
                    evidence=list(evidence or []),
                )
            else:
                effective.capabilities[key] = ContextSignalState(enabled=False, confidence=0.0, source="default", evidence=[])

        exp_expects = explicit_expectations or {}
        det_expects = detected_expectations or {}
        for key, spec in self.team_expectations.items():
            default_value = bool(spec.get("default", False))
            if key in exp_expects:
                effective.team_expectations[key] = ContextSignalState(
                    enabled=bool(exp_expects[key]),
                    confidence=1.0,
                    source="explicit",
                    evidence=[],
                )
            elif key in det_expects:
                enabled, confidence, evidence = det_expects[key]
                effective.team_expectations[key] = ContextSignalState(
                    enabled=bool(enabled),
                    confidence=max(0.0, min(1.0, float(confidence or 0.0))),
                    source="detected",
                    evidence=list(evidence or []),
                )
            else:
                effective.team_expectations[key] = ContextSignalState(
                    enabled=default_value,
                    confidence=1.0 if default_value else 0.0,
                    source="default",
                    evidence=[],
                )

        return effective

    def calibrate_rule(self, rule_id: str, context: EffectiveContext) -> dict[str, Any]:
        """
        Resolve effective rule behavior from context layers.

        Merge order:
        1. defaults
        2. by_profile
        3. by_project_type
        4. by_capability (for enabled capabilities)
        5. by_team_expectation (for enabled standards)
        """
        behavior = dict(self.rule_behavior.get(rule_id, {}) or {})
        defaults = dict(behavior.get("defaults", {}) or {})
        resolved: dict[str, Any] = {
            "enabled": defaults.get("enabled"),
            "severity": defaults.get("severity"),
            "thresholds": dict(defaults.get("thresholds", {}) or {}),
            "signals": [],
        }

        def _merge_patch(patch: dict[str, Any], signal: str) -> None:
            if not patch:
                return
            if "enabled" in patch:
                resolved["enabled"] = patch.get("enabled")
            if "severity" in patch:
                resolved["severity"] = patch.get("severity")
            if isinstance(patch.get("thresholds"), dict):
                merged = dict(resolved.get("thresholds", {}) or {})
                merged.update(dict(patch.get("thresholds", {}) or {}))
                resolved["thresholds"] = merged
            resolved["signals"].append(signal)

        profile_key = str(context.architecture_profile or "unknown")
        project_type_key = str(context.project_type or "unknown")
        by_profile = dict(behavior.get("by_profile", {}) or {})
        by_project_type = dict(behavior.get("by_project_type", {}) or {})
        by_capability = dict(behavior.get("by_capability", {}) or {})
        by_team_expectation = dict(behavior.get("by_team_expectation", {}) or {})

        _merge_patch(dict(by_profile.get(profile_key, {}) or {}), f"profile:{profile_key}")
        _merge_patch(dict(by_project_type.get(project_type_key, {}) or {}), f"project_type:{project_type_key}")

        for capability_key, state in (context.capabilities or {}).items():
            if not bool(getattr(state, "enabled", False)):
                continue
            patch = dict(by_capability.get(capability_key, {}) or {})
            _merge_patch(patch, f"capability:{capability_key}")

        for expectation_key, state in (context.team_expectations or {}).items():
            if not bool(getattr(state, "enabled", False)):
                continue
            patch = dict(by_team_expectation.get(expectation_key, {}) or {})
            _merge_patch(patch, f"team:{expectation_key}")

        return resolved
