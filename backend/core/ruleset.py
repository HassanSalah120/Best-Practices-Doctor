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
        "**/tests/**",
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
    # Optional weights for triage scoring (additive; defaults preserve current behavior).
    triage_weights: dict[str, float] = Field(default_factory=lambda: {
        "impact": 1.0,
        "risk": 1.0,
        "effort": 1.0,
        "context": 1.0,
        "effort_discount": 0.6,
    })


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
    def _overlay_user_ruleset_on_base(cls, base: "Ruleset", user: "Ruleset") -> "Ruleset":
        """Overlay a user ruleset on top of a base profile.

        This keeps new rules from the base profile while preserving explicit
        user overrides.
        """
        merged = base.model_copy(deep=True)

        # Rule-level overrides are merged key-by-key so missing user entries
        # still inherit current profile defaults.
        merged.rules = {**base.rules, **user.rules}

        # Only replace top-level settings when the user ruleset explicitly set
        # those fields in YAML.
        if "name" in user.model_fields_set:
            merged.name = user.name
        if "description" in user.model_fields_set:
            merged.description = user.description
        if "scan" in user.model_fields_set:
            merged.scan = user.scan
        if "scoring" in user.model_fields_set:
            merged.scoring = user.scoring
        if "project_types" in user.model_fields_set:
            merged.project_types = user.project_types

        return merged
    
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
        2. User ruleset overlaid on active profile (when app-data ruleset exists)
        3. Active ruleset profile YAML (startup/balanced/strict)
        4. `ruleset.default.yaml` in current working directory (legacy fallback)
        5. `backend/ruleset.default.yaml` (packaged legacy fallback)
        6. Built-in defaults (`Ruleset.default()`), then `Ruleset()` as last resort
        """
        # 1) Explicit override path always wins.
        if override_path:
            try:
                p = Path(override_path)
                if p.exists():
                    rs = cls.load(p)
                    try:
                        if rs._maybe_migrate_legacy_scoring_weights():
                            logger.info(f"Migrated legacy scoring weights in ruleset: {p}")
                    except Exception:
                        pass
                    return rs
            except Exception:
                pass

        user_ruleset_path: Path | None = None
        active_profile_path: Path | None = None

        # Persisted user ruleset (Tauri sets BPD_APP_DATA_DIR for the sidecar).
        app_data_dir = os.environ.get("BPD_APP_DATA_DIR")
        if app_data_dir:
            try:
                user_ruleset_path = Path(app_data_dir) / "ruleset.yaml"
            except Exception:
                user_ruleset_path = None

        # Active profile YAML (user-scoped via settings.json, stored in app data dir).
        try:
            from core.app_settings import get_active_ruleset_profile
            from core.ruleset_profiles import get_profile_path

            active = get_active_ruleset_profile(default="startup")
            p = get_profile_path(active)
            if p:
                active_profile_path = p
        except Exception:
            active_profile_path = None

        # 2) Overlay user ruleset on top of active profile so newly added rules
        # in the profile are inherited by older user rulesets.
        try:
            if user_ruleset_path and user_ruleset_path.exists() and active_profile_path and active_profile_path.exists():
                base = cls.load(active_profile_path)
                user = cls.load(user_ruleset_path)
                rs = cls._overlay_user_ruleset_on_base(base, user)
                try:
                    if rs._maybe_migrate_legacy_scoring_weights():
                        logger.info(
                            "Migrated legacy scoring weights in merged user/profile ruleset"
                        )
                except Exception:
                    pass
                return rs
        except Exception:
            pass

        # 3) Backward-compatible fallback to standalone user ruleset.
        try:
            if user_ruleset_path and user_ruleset_path.exists():
                rs = cls.load(user_ruleset_path)
                try:
                    if rs._maybe_migrate_legacy_scoring_weights():
                        logger.info(f"Migrated legacy scoring weights in ruleset: {user_ruleset_path}")
                except Exception:
                    pass
                return rs
        except Exception:
            pass

        # 4+) Fallback candidates.
        candidates: list[Path] = []
        if active_profile_path:
            candidates.append(active_profile_path)
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
                "controller-index-filter-duplication": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="architecture",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.74},
                ),
                "mass-assignment-risk": RuleConfig(enabled=True, severity="high", category="security"),
                "unsafe-file-upload": RuleConfig(enabled=True, severity="high", category="security"),
                "user-model-missing-must-verify-email": RuleConfig(enabled=True, severity="high", category="security"),
                "registration-missing-registered-event": RuleConfig(enabled=True, severity="high", category="security"),
                "missing-foreign-key-in-migration": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="laravel_best_practice",
                    thresholds={"min_confidence": 0.78},
                ),
                "missing-index-on-lookup-columns": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="performance",
                    thresholds={"min_confidence": 0.74},
                ),
                "destructive-migration-without-safety-guard": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="laravel_best_practice",
                    thresholds={"min_confidence": 0.84},
                ),
                "model-hidden-sensitive-attributes-missing": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"min_confidence": 0.82},
                ),
                "sensitive-model-appends-risk": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"min_confidence": 0.86},
                ),
                "sensitive-routes-missing-verified-middleware": RuleConfig(enabled=True, severity="high", category="security"),
                "tenant-access-middleware-missing": RuleConfig(enabled=True, severity="high", category="security"),
                "signed-routes-missing-signature-middleware": RuleConfig(enabled=True, severity="high", category="security"),
                "unsafe-external-redirect": RuleConfig(enabled=True, severity="high", category="security"),
                "ssrf-risk-http-client": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_external_integrations_capability": True, "min_confidence": 0.82},
                ),
                "path-traversal-file-access": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"min_confidence": 0.84},
                ),
                "insecure-file-download-response": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_auth_or_ownership_guard": True, "min_confidence": 0.84},
                ),
                "webhook-signature-missing": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_external_integrations_capability": True, "min_confidence": 0.84},
                ),
                "idor-risk-missing-ownership-check": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_multi_role_portal_capability": True, "min_confidence": 0.8},
                ),
                "sensitive-route-rate-limit-missing": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_public_surface_capability": True, "min_confidence": 0.8},
                ),
                "sanctum-token-scope-missing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="security",
                    thresholds={
                        "require_sanctum_signal": True,
                        "require_multi_role_portal_capability": True,
                        "min_confidence": 0.8,
                    },
                ),
                "session-fixation-regenerate-missing": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"min_confidence": 0.82},
                ),
                "weak-password-policy-validation": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="security",
                    thresholds={"min_required_length": 8, "min_confidence": 0.76},
                ),
                "upload-mime-extension-mismatch": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_upload_capability": True, "min_confidence": 0.82},
                ),
                "archive-upload-zip-slip-risk": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_upload_capability": True, "min_confidence": 0.84},
                ),
                "upload-size-limit-missing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="security",
                    thresholds={"require_upload_capability": True, "min_confidence": 0.76},
                ),
                "csrf-exception-wildcard-risk": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"min_confidence": 0.85},
                ),
                "host-header-poisoning-risk": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"min_confidence": 0.8},
                ),
                "xml-xxe-risk": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"min_confidence": 0.78},
                ),
                "zip-bomb-risk": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_upload_capability": True, "min_confidence": 0.8},
                ),
                "sensitive-response-cache-control-missing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="security",
                    thresholds={"min_confidence": 0.75},
                ),
                "password-reset-token-hardening-missing": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"min_confidence": 0.8},
                ),
                "security-headers-baseline-missing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="security",
                    thresholds={"min_confidence": 0.74},
                ),
                "webhook-replay-protection-missing": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_external_integrations_capability": True, "min_confidence": 0.8},
                ),
                "authorization-missing-on-sensitive-reads": RuleConfig(enabled=True, severity="high", category="security"),
                "insecure-session-cookie-config": RuleConfig(enabled=True, severity="high", category="security"),
                "unsafe-csp-policy": RuleConfig(enabled=True, severity="high", category="security"),
                "job-missing-idempotency-guard": RuleConfig(enabled=True, severity="medium", category="security"),
                "composer-dependency-below-secure-version": RuleConfig(enabled=True, severity="high", category="security"),
                "npm-dependency-below-secure-version": RuleConfig(enabled=True, severity="high", category="security"),
                "inertia-shared-props-sensitive-data": RuleConfig(enabled=True, severity="high", category="security"),
                "inertia-shared-props-eager-query": RuleConfig(enabled=True, severity="medium", category="performance"),
                "inertia-shared-props-payload-budget": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="performance",
                    thresholds={"require_global_share_context": True, "min_confidence": 0.75},
                ),
                "job-missing-retry-policy": RuleConfig(enabled=True, severity="medium", category="security"),
                "job-http-call-missing-timeout": RuleConfig(enabled=True, severity="medium", category="security"),
                "notification-shouldqueue-missing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="performance",
                    thresholds={"min_confidence": 0.8},
                ),
                "listener-shouldqueue-missing-for-io-bound-handler": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="performance",
                    thresholds={"min_confidence": 0.82},
                ),
                "broadcast-channel-authorization-missing": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"min_confidence": 0.84},
                ),
                "observer-heavy-logic": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="architecture",
                    thresholds={"max_method_loc": 35, "max_side_effect_calls": 6},
                ),
                "no-json-encode-in-controllers": RuleConfig(enabled=True, severity="medium", category="laravel_best_practice"),
                "error-pages-missing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="laravel_best_practice",
                    thresholds={
                        "core_4xx_codes": ["404"],
                        "core_5xx_codes": ["500"],
                        "recommended_4xx_codes": ["403", "419", "429"],
                        "recommended_5xx_codes": ["503"],
                        "flag_recommended": True,
                        "flag_recommended_inertia": False,
                        "min_recommended_missing": 2,
                    },
                ),
                "public-api-versioning-missing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="laravel_best_practice",
                    thresholds={"min_confidence": 0.78},
                ),
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
                "action-class-naming-consistency": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="architecture",
                    thresholds={"max_findings_per_file": 20, "min_confidence": 0.8},
                ),
                "massive-model": RuleConfig(enabled=True, severity="medium", category="maintainability", thresholds={"max_methods": 15, "max_loc": 400}),
                "model-cross-model-query": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="architecture",
                    thresholds={"max_findings_per_file": 3, "min_confidence": 0.74},
                ),
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
                "exhaustive-deps-ast": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "usecallback-ast": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "usememo-ast": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "react-no-array-index-key": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "hooks-in-conditional-or-loop": RuleConfig(enabled=True, severity="high", category="react_best_practice"),
                "missing-key-on-list-render": RuleConfig(enabled=True, severity="high", category="react_best_practice"),
                "hardcoded-user-facing-strings": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "interactive-element-a11y": RuleConfig(enabled=True, severity="high", category="react_best_practice"),
                "form-label-association": RuleConfig(enabled=True, severity="high", category="react_best_practice"),
                "modal-trap-focus": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.82},
                ),
                "skip-link-missing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 1, "min_confidence": 0.85},
                ),
                "focus-indicator-missing": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 3, "min_confidence": 0.9},
                ),
                "touch-target-size": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="accessibility",
                    thresholds={"min_touch_target_px": 44, "max_findings_per_file": 3},
                ),
                "semantic-wrapper-breakage": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 3, "min_confidence": 0.9},
                ),
                "interactive-accessible-name-required": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 4, "min_confidence": 0.88},
                ),
                "jsx-aria-attribute-format": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 5, "min_confidence": 0.9},
                ),
                "outside-click-without-keyboard-fallback": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.84},
                ),
                "apg-tabs-keyboard-contract": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.86},
                ),
                "apg-accordion-disclosure-contract": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.84},
                ),
                "apg-menu-button-contract": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.86},
                ),
                "apg-combobox-contract": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.86},
                ),
                "dialog-focus-restore-missing": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.84},
                ),
                "avoid-props-to-state-copy": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.72},
                ),
                "props-state-sync-effect-smell": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.74},
                ),
                "controlled-uncontrolled-input-mismatch": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 3, "min_confidence": 0.82},
                ),
                "usememo-overuse": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.8},
                ),
                "usecallback-overuse": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.8},
                ),
                "context-oversized-provider": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="performance",
                    thresholds={
                        "max_findings_per_file": 2,
                        "max_provider_keys_without_split": 6,
                        "min_confidence": 0.78,
                    },
                ),
                "lazy-without-suspense": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="react_best_practice",
                    thresholds={"min_confidence": 0.84},
                ),
                "suspense-fallback-missing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.82},
                ),
                "stale-closure-in-timer": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.82},
                ),
                "stale-closure-in-listener": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.82},
                ),
                "duplicate-key-source": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.76},
                ),
                "missing-loading-state": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="react_best_practice",
                    thresholds={"min_confidence": 0.7},
                ),
                "missing-empty-state": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="react_best_practice",
                    thresholds={"min_confidence": 0.7},
                ),
                "ref-access-during-render": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.84},
                ),
                "ref-used-as-reactive-state": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 1, "min_confidence": 0.78},
                ),
                "meta-description-missing-or-generic": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="react_best_practice",
                    thresholds={"require_public_surface_signal": True, "min_confidence": 0.8},
                ),
                "canonical-missing-or-invalid": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"require_public_surface_signal": True, "min_confidence": 0.82},
                ),
                "robots-directive-risk": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"require_public_surface_signal": True, "min_confidence": 0.86},
                ),
                "crawlable-internal-navigation-required": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"require_public_surface_signal": True, "min_confidence": 0.78},
                ),
                "jsonld-structured-data-invalid-or-mismatched": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.86},
                ),
                "h1-singleton-violation": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"require_public_surface_signal": True, "min_confidence": 0.8},
                ),
                "page-indexability-conflict": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="react_best_practice",
                    thresholds={"require_public_surface_signal": True, "min_confidence": 0.9},
                ),
                "no-inline-types": RuleConfig(enabled=True, severity="medium", category="maintainability"),
                "no-inline-services": RuleConfig(enabled=True, severity="medium", category="maintainability"),
                "react-parent-child-spacing-overlap": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={
                        "max_findings_per_file": 2,
                        "require_same_value": True,
                        "allowed_responsive_scopes": ["base", "sm", "md", "lg", "xl", "2xl"],
                    },
                ),
                "css-font-size-px": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"min_px": 12, "max_findings_per_file": 3},
                ),
                "css-spacing-px": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"min_px": 8, "max_findings_per_file": 4},
                ),
                "css-fixed-layout-px": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="react_best_practice",
                    thresholds={"min_px": 240, "max_findings_per_file": 3},
                ),
                "tailwind-arbitrary-value-overuse": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"min_arbitrary_count": 3, "max_findings_per_file": 3},
                ),
                "tailwind-arbitrary-text-size": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 3},
                ),
                "tailwind-arbitrary-spacing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 3},
                ),
                "tailwind-arbitrary-layout-size": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="react_best_practice",
                    thresholds={"min_px": 200, "max_findings_per_file": 3},
                ),
                "tailwind-arbitrary-radius-shadow": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 3},
                ),
                "tailwind-motion-reduce-missing": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.88},
                ),
                "tailwind-appearance-none-risk": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 3, "min_confidence": 0.86},
                ),
                "css-focus-outline-without-replacement": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 3, "min_confidence": 0.92},
                ),
                "css-hover-only-interaction": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.84},
                ),
                "css-color-only-state-indicator": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="accessibility",
                    thresholds={"max_findings_per_file": 2, "min_confidence": 0.82},
                ),
                "inertia-page-missing-head": RuleConfig(enabled=True, severity="medium", category="react_best_practice", thresholds={"min_confidence": 0.65}),
                "inertia-internal-link-anchor": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "inertia-form-uses-fetch": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "anonymous-default-export-component": RuleConfig(enabled=True, severity="medium", category="maintainability"),
                "multiple-exported-react-components": RuleConfig(enabled=True, severity="low", category="maintainability"),
                "context-provider-inline-value": RuleConfig(enabled=True, severity="medium", category="performance"),
                "react-useeffect-fetch-without-abort": RuleConfig(enabled=True, severity="medium", category="react_best_practice"),
                "derived-state-in-effect": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"min_set_calls": 1, "max_set_calls": 2, "require_dependency_signal": True},
                ),
                "state-update-in-render": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 3},
                ),
                "large-custom-hook": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="maintainability",
                    thresholds={"max_loc": 280, "min_overflow_lines": 30, "min_logic_signals": 4},
                ),
                "cross-feature-import-boundary": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="architecture",
                    thresholds={"allow_entrypoint_import": True, "max_findings_per_file": 3},
                ),
                "query-key-instability": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="performance",
                    thresholds={"max_findings_per_file": 2},
                ),
                "react-no-random-key": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2},
                ),
                "react-no-props-mutation": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="react_best_practice",
                    thresholds={"require_component_signal": True, "max_findings_per_file": 2},
                ),
                "react-no-state-mutation": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="react_best_practice",
                    thresholds={"max_state_vars": 12, "max_findings_per_file": 3},
                ),
                "react-side-effects-in-render": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 3},
                ),
                "react-event-listener-cleanup-required": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2},
                ),
                "react-timer-cleanup-required": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"include_set_timeout": False, "max_findings_per_file": 2},
                ),
                "inertia-reload-without-only": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="performance",
                    thresholds={"max_findings_per_file": 2},
                ),
                "insecure-postmessage-origin-wildcard": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_public_surface_capability": True, "min_confidence": 0.9},
                ),
                "token-storage-insecure-localstorage": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_public_surface_capability": True, "min_confidence": 0.85},
                ),
                "client-open-redirect-unvalidated-navigation": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_public_surface_capability": True, "min_confidence": 0.82},
                ),
                "postmessage-receiver-origin-not-verified": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"require_public_surface_capability": True, "min_confidence": 0.82},
                ),
                "dangerous-html-sink-without-sanitizer": RuleConfig(
                    enabled=True,
                    severity="high",
                    category="security",
                    thresholds={"min_confidence": 0.82},
                ),
                "effect-event-relay-smell": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2},
                ),
                "route-shell-missing-error-boundary": RuleConfig(
                    enabled=True,
                    severity="low",
                    category="react_best_practice",
                    thresholds={"min_data_signals": 2},
                ),
                "unsafe-async-handler-without-guard": RuleConfig(
                    enabled=True,
                    severity="medium",
                    category="react_best_practice",
                    thresholds={"max_findings_per_file": 2},
                ),
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
