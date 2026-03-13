"""
Ruleset YAML Configuration
Loads and validates rule configuration with versioning and defaults.
"""
from pathlib import Path
from typing import Any
import os
import logging
import yaml
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


class RuleConfig(BaseModel):
    """Configuration for a single rule."""
    enabled: bool = True
    severity: str | None = None  # Override default severity
    category: str | None = None  # Rule category (laravel, security, etc.)
    version: int = 1  # Per-rule version for compatibility
    thresholds: dict[str, Any] = Field(default_factory=dict)
    
    # Example thresholds:
    # fat-controller: { max_method_loc: 30, max_queries: 3 }
    # enum-suggestion: { min_occurrences: 3 }
    # large-react-component: { max_lines: 200 }


class ScanConfig(BaseModel):
    """Scan configuration including ignore patterns."""
    ignore: list[str] = Field(default_factory=lambda: [
        "vendor/**",
        "node_modules/**",
        "storage/**",
        "bootstrap/cache/**",
        # Laravel SSR build outputs (can contain huge/minified JS bundles).
        "bootstrap/ssr/**",
        "public/build/**",
        # Seeders are frequently imperative and not representative of app architecture.
        "database/seeders/**",
        "database/seeds/**",
        # Framework generated: migrations/factories are often noisy and don't reflect app architecture.
        "database/migrations/**",
        "database/factories/**",
        ".git/**",
        "tests/**",
        "*.min.js",
        "*.min.css",
    ])
    max_file_size_kb: int = 500
    max_files: int = 5000


class ScoringConfig(BaseModel):
    """Scoring weights configuration."""
    weights: dict[str, float] = Field(default_factory=lambda: {
        # Fractions are supported (auto-scaled to 0-100). Keep a complete set so
        # categories aren't accidentally given a zero weight when weights are explicit.
        "architecture": 0.15,
        "dry": 0.10,
        "laravel_best_practice": 0.15,
        "react_best_practice": 0.05,
        "accessibility": 0.05,
        "complexity": 0.15,
        "security": 0.10,
        "maintainability": 0.10,
        "srp": 0.05,
        "validation": 0.05,
        "performance": 0.05,
    })
    severity_penalties: dict[str, float] = Field(default_factory=lambda: {
        # Calibrated defaults: LOW/INFO should not dominate category scores.
        "info": 0.25,
        "low": 0.75,
        "medium": 5.0,
        "high": 15.0,
        "critical": 40.0,
    })
    classification_multipliers: dict[str, float] = Field(default_factory=lambda: {
        "defect": 1.0,
        "risk": 1.0,
        "advisory": 0.35,
    })
    # Noise reduction: for LOW/INFO findings, only apply the worst penalty once per file per rule.
    # This prevents e.g. long-method (low) from nuking a category due to many occurrences.
    cap_low_info_per_file_rule: bool = True


class Ruleset(BaseModel):
    """
    Complete ruleset configuration.
    Loaded from ruleset.yaml with validation and defaults.
    """
    schema_version: int = 1
    name: str = "default"
    description: str = ""
    
    # Rule configurations
    rules: dict[str, RuleConfig] = Field(default_factory=dict)
    
    # Scan settings
    scan: ScanConfig = Field(default_factory=ScanConfig)
    
    # Scoring weights
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    
    # Limit to specific project types (empty = all)
    project_types: list[str] = Field(default_factory=list)
    
    @field_validator("schema_version")
    @classmethod
    def validate_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError(f"Unsupported schema version: {v}. Expected: 1")
        return v
    
    @classmethod
    def load(cls, path: str | Path) -> "Ruleset":
        """Load ruleset from YAML file."""
        path = Path(path)
        if not path.exists():
            if path.name == "ruleset.default.yaml":
                try:
                    backend_root = Path(__file__).resolve().parents[1]
                    fallback = backend_root / "ruleset.default.yaml"
                    if fallback.exists():
                        path = fallback
                    else:
                        raise FileNotFoundError(f"Ruleset not found: {path}")
                except Exception:
                    raise FileNotFoundError(f"Ruleset not found: {path}")
            else:
                raise FileNotFoundError(f"Ruleset not found: {path}")
        
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        
        return cls(**data)
    
    @classmethod
    def load_with_fallback(cls, path: str | Path | None, default_path: str | Path) -> "Ruleset":
        """Load ruleset with fallback to default if invalid."""
        if path:
            try:
                return cls.load(path)
            except Exception:
                pass  # Fall through to default
        
        try:
            return cls.load(default_path)
        except Exception:
            return cls()  # Built-in defaults

    @classmethod
    def load_default(cls, override_path: str | Path | None = None) -> "Ruleset":
        """Load the effective default ruleset.

        Precedence:
        1. `override_path` (if provided)
        2. User ruleset in app data dir (when `BPD_APP_DATA_DIR` is set, i.e., Tauri runtime)
        3. Active ruleset profile YAML (startup/balanced/strict)
        4. `ruleset.default.yaml` in current working directory (legacy fallback)
        5. `backend/ruleset.default.yaml` (packaged legacy fallback)
        6. Built-in defaults (`Ruleset.default()`), then `Ruleset()` as last resort
        """
        candidates: list[Path] = []

        if override_path:
            candidates.append(Path(override_path))

        # Persisted user ruleset (Tauri sets BPD_APP_DATA_DIR for the sidecar).
        app_data_dir = os.environ.get("BPD_APP_DATA_DIR")
        if app_data_dir:
            try:
                candidates.append(Path(app_data_dir) / "ruleset.yaml")
            except Exception:
                pass

        # Active profile YAML (user-scoped via settings.json, stored in app data dir).
        try:
            from core.app_settings import get_active_ruleset_profile
            from core.ruleset_profiles import get_profile_path

            active = get_active_ruleset_profile(default="startup")
            p = get_profile_path(active)
            if p:
                candidates.append(p)
        except Exception:
            pass

        candidates.append(Path("ruleset.default.yaml"))

        # Packaged/committed fallback relative to this module (backend/ruleset.default.yaml)
        try:
            backend_root = Path(__file__).resolve().parents[1]
            candidates.append(backend_root / "ruleset.default.yaml")
        except Exception:
            pass

        for p in candidates:
            try:
                if p.exists():
                    rs = cls.load(p)
                    # Backward-compatible migration for older default rulesets that omitted
                    # SRP/Validation/Performance weights (which would otherwise become 0).
                    try:
                        if rs._maybe_migrate_legacy_scoring_weights():
                            logger.info(f"Migrated legacy scoring weights in ruleset: {p}")
                    except Exception:
                        pass
                    return rs
            except Exception:
                continue

        try:
            return cls.default()
        except Exception:
            return cls()

    def _maybe_migrate_legacy_scoring_weights(self) -> bool:
        """Upgrade older default-style scoring weights to include missing categories.

        Historically, our default weights covered only a subset of categories. Because scoring treats
        provided weights as explicit, omitted categories become weight=0 (and action priorities can
        misleadingly show p=0.00). If the weights look exactly like the older default set, augment
        them with SRP/Validation/Performance and renormalize fractions to sum ~1.0.
        """
        try:
            weights = getattr(getattr(self, "scoring", None), "weights", None)
        except Exception:
            weights = None

        if not isinstance(weights, dict) or not weights:
            return False

        def norm_key(k: object) -> str:
            s = (k.value if hasattr(k, "value") else str(k)).strip().lower()
            # Keep compatibility with older keys.
            if s == "best_practices":
                return "maintainability"
            return s

        normalized_items: dict[str, float] = {}
        for k, v in weights.items():
            nk = norm_key(k)
            try:
                normalized_items[nk] = float(v)
            except Exception:
                continue

        if not normalized_items:
            return False

        # Detect the old default key set (pre v1.0.1-ish).
        legacy_keys_with_react = {
            "architecture",
            "dry",
            "laravel",
            "react",
            "complexity",
            "security",
            "maintainability",
        }
        legacy_keys_no_react = {
            "architecture",
            "dry",
            "laravel",
            "complexity",
            "security",
            "maintainability",
        }
        if set(normalized_items.keys()) not in {legacy_keys_with_react, legacy_keys_no_react}:
            return False

        # Add missing categories with small defaults.
        normalized_items.setdefault("react", 0.10)
        normalized_items.setdefault("accessibility", 0.05)
        normalized_items.setdefault("srp", 0.05)
        normalized_items.setdefault("validation", 0.05)
        normalized_items.setdefault("performance", 0.05)

        # Renormalize fractional weights (keep behavior predictable).
        max_w = max(normalized_items.values()) if normalized_items else 0.0
        sum_w = sum(normalized_items.values()) if normalized_items else 0.0
        if max_w <= 1.0 and sum_w > 0:
            scale = 1.0 / sum_w
            normalized_items = {k: v * scale for k, v in normalized_items.items()}

        # Persist back to the model (use canonical keys).
        try:
            self.scoring.weights = normalized_items
        except Exception:
            return False

        return True
    
    def get_rule_config(self, rule_id: str) -> RuleConfig:
        """Get config for a rule, with defaults if not specified."""
        if rule_id in self.rules:
            return self.rules[rule_id]
        if self.rules:
            return RuleConfig(enabled=False)
        return RuleConfig()
    
    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled."""
        config = self.get_rule_config(rule_id)
        return config.enabled
    
    def get_threshold(self, rule_id: str, key: str, default: Any = None) -> Any:
        """Get a threshold value for a rule."""
        config = self.get_rule_config(rule_id)
        return config.thresholds.get(key, default)
    
    def should_ignore(self, path: str) -> bool:
        """Check if a path should be ignored based on patterns."""
        from fnmatch import fnmatch
        for pattern in self.scan.ignore:
            if fnmatch(path, pattern):
                return True
        return False
    
    @classmethod
    def default(cls) -> "Ruleset":
        """Return the default ruleset with all standard rules."""
        return Ruleset(
            name="default",
            description="Default Best Practices Doctor ruleset",
            rules={
                "fat-controller": RuleConfig(enabled=True, severity="high", category="laravel", thresholds={"max_methods": 10, "max_method_loc": 20}),
                "missing-form-request": RuleConfig(enabled=True, severity="medium", category="laravel", thresholds={"max_validator_rules": 2}),
                "service-extraction": RuleConfig(enabled=True, severity="high", category="laravel", thresholds={"min_public_methods": 3}),
                "enum-suggestion": RuleConfig(enabled=True, severity="low", category="laravel", thresholds={"min_occurrences": 3}),
                "blade-queries": RuleConfig(enabled=True, severity="medium", category="laravel"),
                "repository-suggestion": RuleConfig(enabled=True, severity="medium", category="laravel", thresholds={"min_complexity": 3}),
                "contract-suggestion": RuleConfig(enabled=True, severity="medium", category="laravel"),
                "custom-exception-suggestion": RuleConfig(enabled=True, severity="low", category="laravel", thresholds={"min_confidence": 0.7}),
                "eager-loading": RuleConfig(enabled=True, severity="medium", category="laravel"),
                "n-plus-one-risk": RuleConfig(enabled=True, severity="medium", category="performance", thresholds={"min_confidence": 0.6}),
                "env-outside-config": RuleConfig(enabled=True, severity="medium", category="laravel"),
                "ioc-instead-of-new": RuleConfig(enabled=True, severity="medium", category="laravel", thresholds={"max_instantiations": 0}),
                "controller-query-direct": RuleConfig(enabled=True, severity="high", category="laravel_best_practice", thresholds={"max_queries_per_method": 0}),
                "controller-business-logic": RuleConfig(enabled=True, severity="high", category="architecture", thresholds={"min_cyclomatic": 8, "min_loc": 60, "min_confidence": 0.6}),
                "controller-inline-validation": RuleConfig(enabled=True, severity="medium", category="validation", thresholds={"high_if_rules_ge": 6, "min_confidence": 0.65}),
                "mass-assignment-risk": RuleConfig(enabled=True, severity="high", category="security"),
                "unsafe-file-upload": RuleConfig(enabled=True, severity="high", category="security"),
                "user-model-missing-must-verify-email": RuleConfig(enabled=True, severity="high", category="security"),
                "registration-missing-registered-event": RuleConfig(enabled=True, severity="high", category="security"),
                "sensitive-routes-missing-verified-middleware": RuleConfig(enabled=True, severity="high", category="security"),
                "tenant-access-middleware-missing": RuleConfig(enabled=True, severity="high", category="security"),
                "signed-routes-missing-signature-middleware": RuleConfig(enabled=True, severity="high", category="security"),
                "unsafe-external-redirect": RuleConfig(enabled=True, severity="high", category="security"),
                "authorization-missing-on-sensitive-reads": RuleConfig(enabled=True, severity="high", category="security"),
                "insecure-session-cookie-config": RuleConfig(enabled=True, severity="high", category="security"),
                "unsafe-csp-policy": RuleConfig(enabled=True, severity="high", category="security"),
                "job-missing-idempotency-guard": RuleConfig(enabled=True, severity="medium", category="security"),
                "composer-dependency-below-secure-version": RuleConfig(enabled=True, severity="high", category="security"),
                "npm-dependency-below-secure-version": RuleConfig(enabled=True, severity="high", category="security"),
                "inertia-shared-props-sensitive-data": RuleConfig(enabled=True, severity="high", category="security"),
                "inertia-shared-props-eager-query": RuleConfig(enabled=True, severity="medium", category="performance"),
                "job-missing-retry-policy": RuleConfig(enabled=True, severity="medium", category="security"),
                "job-http-call-missing-timeout": RuleConfig(enabled=True, severity="medium", category="security"),
                "no-json-encode-in-controllers": RuleConfig(enabled=True, severity="medium", category="laravel_best_practice"),
                "api-resource-usage": RuleConfig(enabled=True, severity="medium", category="laravel_best_practice"),
                "no-log-debug-in-app": RuleConfig(enabled=True, severity="low", category="maintainability"),
                "no-closure-routes": RuleConfig(enabled=True, severity="medium", category="architecture"),
                "heavy-logic-in-routes": RuleConfig(enabled=True, severity="medium", category="architecture"),
                "duplicate-route-definition": RuleConfig(enabled=True, severity="high", category="architecture"),
                "missing-throttle-on-auth-api-routes": RuleConfig(enabled=True, severity="medium", category="security"),
                "missing-auth-on-mutating-api-routes": RuleConfig(enabled=True, severity="high", category="security"),
                "policy-coverage-on-mutations": RuleConfig(enabled=True, severity="high", category="security"),
                "authorization-bypass-risk": RuleConfig(enabled=True, severity="high", category="security"),
                "transaction-required-for-multi-write": RuleConfig(enabled=True, severity="high", category="architecture", thresholds={"min_write_calls": 2}),
                "tenant-scope-enforcement": RuleConfig(enabled=True, severity="high", category="security", thresholds={"min_project_signals": 5, "min_method_queries": 1}),
                "dto-suggestion": RuleConfig(enabled=True, severity="medium", category="maintainability", thresholds={"min_keys": 6}),
                "action-class-suggestion": RuleConfig(enabled=True, severity="low", category="architecture"),
                "massive-model": RuleConfig(enabled=True, severity="medium", category="maintainability", thresholds={"max_methods": 15, "max_loc": 400}),
                "blade-xss-risk": RuleConfig(enabled=True, severity="high", category="security"),
                "dry-violation": RuleConfig(enabled=True, severity="medium", category="dry", thresholds={"min_token_count": 50, "min_occurrences": 2}),
                "high-complexity": RuleConfig(enabled=True, severity="high", category="complexity", thresholds={"max_cyclomatic": 10}),
                "long-method": RuleConfig(enabled=True, severity="medium", category="complexity", thresholds={"max_loc": 50}),
                "god-class": RuleConfig(enabled=True, severity="critical", category="complexity", thresholds={"max_loc": 300, "max_methods": 20}),
                "too-many-dependencies": RuleConfig(enabled=True, severity="medium", category="maintainability", thresholds={"max_dependencies": 5}),
                "raw-sql": RuleConfig(enabled=True, severity="high", category="security"),
                "config-in-loop": RuleConfig(enabled=True, severity="low", category="performance"),
                "static-helper-abuse": RuleConfig(enabled=True, severity="low", category="maintainability"),
                "unused-private-method": RuleConfig(enabled=True, severity="low", category="maintainability"),
                "circular-dependency": RuleConfig(enabled=True, severity="high", category="architecture"),
                "high-coupling-class": RuleConfig(enabled=True, severity="medium", category="architecture", thresholds={"max_outgoing": 12}),
                "prefer-imports": RuleConfig(enabled=True, severity="low", category="maintainability", thresholds={"root_namespaces": ["App\\"]}),
                "unsafe-eval": RuleConfig(enabled=True, severity="high", category="security"),
                "unsafe-unserialize": RuleConfig(enabled=True, severity="high", category="security"),
                "command-injection-risk": RuleConfig(enabled=True, severity="critical", category="security"),
                "sql-injection-risk": RuleConfig(enabled=True, severity="critical", category="security"),
                "tests-missing": RuleConfig(enabled=True, severity="medium", category="maintainability", thresholds={"min_test_files": 3}),
                "low-coverage-files": RuleConfig(enabled=True, severity="medium", category="maintainability", thresholds={"min_pct": 60, "max_findings": 50}),
                "large-react-component": RuleConfig(enabled=True, severity="medium", category="react_best_practice", thresholds={"max_loc": 200}),
                "inline-api-logic": RuleConfig(enabled=True, severity="high", category="react_best_practice"),
                "react-useeffect-deps": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "react-no-array-index-key": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "hooks-in-conditional-or-loop": RuleConfig(enabled=True, severity="high", category="react_best_practice"),
                "missing-key-on-list-render": RuleConfig(enabled=True, severity="high", category="react_best_practice"),
                "hardcoded-user-facing-strings": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "interactive-element-a11y": RuleConfig(enabled=True, severity="high", category="react_best_practice"),
                "form-label-association": RuleConfig(enabled=True, severity="high", category="react_best_practice"),
                "no-inline-types": RuleConfig(enabled=True, severity="medium", category="maintainability"),
                "no-inline-services": RuleConfig(enabled=True, severity="medium", category="maintainability"),
                "inertia-page-missing-head": RuleConfig(enabled=True, severity="medium", category="react_best_practice", thresholds={"min_confidence": 0.65}),
                "inertia-internal-link-anchor": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "inertia-form-uses-fetch": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "anonymous-default-export-component": RuleConfig(enabled=True, severity="medium", category="maintainability"),
                "multiple-exported-react-components": RuleConfig(enabled=True, severity="low", category="maintainability"),
                "context-provider-inline-value": RuleConfig(enabled=True, severity="medium", category="performance"),
                "react-useeffect-fetch-without-abort": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
            }
        )
    
    @classmethod
    def from_file(cls, path: str | Path) -> "Ruleset":
        """Alias for load() - load ruleset from YAML file."""
        return cls.load(path)
    
    def to_yaml(self) -> str:
        """Export ruleset to YAML string."""
        return yaml.safe_dump(self.model_dump(), default_flow_style=False)
    
    def save(self, path: str | Path) -> None:
        """Save ruleset to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_yaml())

    def save_default(self, path: str | Path | None = None) -> None:
        """Save the default ruleset (used by the API when persisting user edits)."""
        self.save(path or "ruleset.default.yaml")


# Default ruleset for reference
DEFAULT_RULESET = Ruleset.default()
