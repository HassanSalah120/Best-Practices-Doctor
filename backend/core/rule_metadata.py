"""
Rule Metadata for UI Grouping

Provides structured metadata about rules for the advanced profile configuration UI.
Rules are grouped by layer (Backend/Frontend) then by category.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class RuleInfo:
    """Metadata for a single rule."""
    id: str
    name: str
    description: str
    category: str
    severity: str
    layer: Literal["backend", "frontend", "shared"]
    tags: list[str] = field(default_factory=list)


# Layer groupings for UI
LAYER_GROUPS = {
    "backend": {
        "label": "Backend (Laravel/PHP)",
        "description": "Server-side architecture, security, and best practices",
        "icon": "Server",
    },
    "frontend": {
        "label": "Frontend (React/Inertia)",
        "description": "Client-side performance, accessibility, and patterns",
        "icon": "Monitor",
    },
    "shared": {
        "label": "Cross-Cutting",
        "description": "Architecture and quality rules that apply to both layers",
        "icon": "Layers",
    },
}

# Category groupings within each layer
CATEGORY_GROUPS = {
    # Backend categories
    "laravel_best_practice": {
        "label": "Laravel Best Practices",
        "description": "Framework-specific patterns and conventions",
        "layer": "backend",
        "order": 1,
    },
    "security": {
        "label": "Security",
        "description": "Vulnerability detection and hardening",
        "layer": "backend",
        "order": 2,
    },
    "architecture": {
        "label": "Architecture",
        "description": "Structure, separation of concerns, and design patterns",
        "layer": "shared",
        "order": 3,
    },
    "performance": {
        "label": "Performance",
        "description": "Query optimization, caching, and efficiency",
        "layer": "backend",
        "order": 4,
    },
    "validation": {
        "label": "Validation",
        "description": "Input validation and form handling",
        "layer": "backend",
        "order": 5,
    },
    # Frontend categories
    "react_best_practice": {
        "label": "React Best Practices",
        "description": "Component patterns, hooks, and performance",
        "layer": "frontend",
        "order": 1,
    },
    "accessibility": {
        "label": "Accessibility (a11y)",
        "description": "WCAG compliance and screen reader support",
        "layer": "frontend",
        "order": 2,
    },
    # Shared categories
    "complexity": {
        "label": "Complexity",
        "description": "Cyclomatic complexity and method length",
        "layer": "shared",
        "order": 6,
    },
    "maintainability": {
        "label": "Maintainability",
        "description": "Code organization and technical debt",
        "layer": "shared",
        "order": 7,
    },
    "dry": {
        "label": "DRY (Don't Repeat Yourself)",
        "description": "Code duplication detection",
        "layer": "shared",
        "order": 8,
    },
    "srp": {
        "label": "Single Responsibility",
        "description": "Class and method focus",
        "layer": "shared",
        "order": 9,
    },
}

# Complete rule metadata for UI
RULE_METADATA: list[RuleInfo] = [
    # === Backend: Laravel Best Practices ===
    RuleInfo(
        id="fat-controller",
        name="Fat Controller",
        description="Controllers with too many methods or business logic",
        category="laravel_best_practice",
        severity="high",
        layer="backend",
        tags=["architecture", "mvc"],
    ),
    RuleInfo(
        id="missing-form-request",
        name="Missing Form Request",
        description="Inline validation instead of Form Request classes",
        category="laravel_best_practice",
        severity="medium",
        layer="backend",
        tags=["validation", "forms"],
    ),
    RuleInfo(
        id="service-extraction",
        name="Service Extraction Opportunity",
        description="Models or controllers that could benefit from service classes",
        category="laravel_best_practice",
        severity="high",
        layer="backend",
        tags=["architecture", "services"],
    ),
    RuleInfo(
        id="enum-suggestion",
        name="Enum Suggestion",
        description="String constants that should be enums",
        category="laravel_best_practice",
        severity="low",
        layer="backend",
        tags=["types", "constants"],
    ),
    RuleInfo(
        id="blade-queries",
        name="Blade Queries",
        description="Database queries in Blade templates",
        category="laravel_best_practice",
        severity="medium",
        layer="backend",
        tags=["performance", "blade"],
    ),
    RuleInfo(
        id="repository-suggestion",
        name="Repository Pattern Suggestion",
        description="Direct model access that could use repository pattern",
        category="laravel_best_practice",
        severity="medium",
        layer="backend",
        tags=["architecture", "data-access"],
    ),
    RuleInfo(
        id="contract-suggestion",
        name="Interface Suggestion",
        description="Services that should implement contracts",
        category="laravel_best_practice",
        severity="medium",
        layer="backend",
        tags=["architecture", "interfaces"],
    ),
    RuleInfo(
        id="custom-exception-suggestion",
        name="Custom Exception Suggestion",
        description="Generic exceptions that should be domain-specific",
        category="laravel_best_practice",
        severity="low",
        layer="backend",
        tags=["error-handling"],
    ),
    RuleInfo(
        id="eager-loading",
        name="Eager Loading Missing",
        description="N+1 query risk from lazy loading relationships",
        category="performance",
        severity="medium",
        layer="backend",
        tags=["performance", "eloquent"],
    ),
    RuleInfo(
        id="env-outside-config",
        name="env() Outside Config",
        description="Environment calls outside config files",
        category="laravel_best_practice",
        severity="medium",
        layer="backend",
        tags=["configuration"],
    ),
    RuleInfo(
        id="ioc-instead-of-new",
        name="IoC Instead of new",
        description="Direct instantiation instead of dependency injection",
        category="laravel_best_practice",
        severity="medium",
        layer="backend",
        tags=["di", "ioc"],
    ),
    RuleInfo(
        id="controller-query-direct",
        name="Direct Query in Controller",
        description="Database queries directly in controllers",
        category="laravel_best_practice",
        severity="high",
        layer="backend",
        tags=["architecture", "data-access"],
    ),
    RuleInfo(
        id="controller-business-logic",
        name="Business Logic in Controller",
        description="Complex business logic in controllers",
        category="architecture",
        severity="high",
        layer="backend",
        tags=["architecture", "mvc"],
    ),
    RuleInfo(
        id="controller-inline-validation",
        name="Inline Validation in Controller",
        description="Validation rules defined in controllers",
        category="validation",
        severity="medium",
        layer="backend",
        tags=["validation"],
    ),
    RuleInfo(
        id="no-json-encode-in-controllers",
        name="JSON Encode in Controller",
        description="Manual JSON encoding instead of API resources",
        category="laravel_best_practice",
        severity="medium",
        layer="backend",
        tags=["api", "responses"],
    ),
    RuleInfo(
        id="api-resource-usage",
        name="API Resource Usage",
        description="Missing API resources for transformations",
        category="laravel_best_practice",
        severity="medium",
        layer="backend",
        tags=["api"],
    ),
    RuleInfo(
        id="no-log-debug-in-app",
        name="Debug Logging in App Code",
        description="dd(), dump(), or log::debug() in production code",
        category="maintainability",
        severity="low",
        layer="backend",
        tags=["debugging"],
    ),
    RuleInfo(
        id="no-closure-routes",
        name="Closure Routes",
        description="Closure-based routes instead of controllers",
        category="architecture",
        severity="medium",
        layer="backend",
        tags=["routing"],
    ),
    RuleInfo(
        id="heavy-logic-in-routes",
        name="Heavy Logic in Routes",
        description="Business logic in route files",
        category="architecture",
        severity="medium",
        layer="backend",
        tags=["routing", "architecture"],
    ),
    RuleInfo(
        id="duplicate-route-definition",
        name="Duplicate Route Definition",
        description="Same route defined multiple times",
        category="architecture",
        severity="high",
        layer="backend",
        tags=["routing"],
    ),
    RuleInfo(
        id="dto-suggestion",
        name="DTO Suggestion",
        description="Large data structures that should be DTOs",
        category="maintainability",
        severity="medium",
        layer="backend",
        tags=["types", "data-transfer"],
    ),
    RuleInfo(
        id="action-class-suggestion",
        name="Action Class Suggestion",
        description="Complex controller methods that could be actions",
        category="architecture",
        severity="low",
        layer="backend",
        tags=["architecture", "actions"],
    ),
    RuleInfo(
        id="massive-model",
        name="Massive Model",
        description="Models with too many methods or lines",
        category="maintainability",
        severity="medium",
        layer="backend",
        tags=["architecture"],
    ),
    
    # === Backend: Security ===
    RuleInfo(
        id="mass-assignment-risk",
        name="Mass Assignment Risk",
        description="Unprotected model mass assignment",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "eloquent"],
    ),
    RuleInfo(
        id="unsafe-file-upload",
        name="Unsafe File Upload",
        description="Missing file upload validation",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "files"],
    ),
    RuleInfo(
        id="user-model-missing-must-verify-email",
        name="Missing Email Verification",
        description="User model without email verification contract",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "authentication"],
    ),
    RuleInfo(
        id="registration-missing-registered-event",
        name="Missing Registered Event",
        description="Registration without event listener",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "events"],
    ),
    RuleInfo(
        id="sensitive-routes-missing-verified-middleware",
        name="Missing Verified Middleware",
        description="Sensitive routes without email verification",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "middleware"],
    ),
    RuleInfo(
        id="tenant-access-middleware-missing",
        name="Missing Tenant Middleware",
        description="Multi-tenant routes without access control",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "multi-tenancy"],
    ),
    RuleInfo(
        id="signed-routes-missing-signature-middleware",
        name="Missing Signature Middleware",
        description="Signed routes without validation",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "routing"],
    ),
    RuleInfo(
        id="unsafe-external-redirect",
        name="Unsafe External Redirect",
        description="Redirects without validation",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "redirects"],
    ),
    RuleInfo(
        id="authorization-missing-on-sensitive-reads",
        name="Missing Authorization on Reads",
        description="Sensitive read endpoints without authorization",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "authorization"],
    ),
    RuleInfo(
        id="insecure-session-cookie-config",
        name="Insecure Session Cookie",
        description="Session cookies without secure flags",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "cookies"],
    ),
    RuleInfo(
        id="unsafe-csp-policy",
        name="Unsafe CSP Policy",
        description="Missing or weak Content Security Policy",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "headers"],
    ),
    RuleInfo(
        id="job-missing-idempotency-guard",
        name="Job Missing Idempotency",
        description="Queue jobs without idempotency protection",
        category="security",
        severity="medium",
        layer="backend",
        tags=["security", "queues"],
    ),
    RuleInfo(
        id="composer-dependency-below-secure-version",
        name="Insecure Composer Dependency",
        description="PHP dependencies with known vulnerabilities",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "dependencies"],
    ),
    RuleInfo(
        id="job-missing-retry-policy",
        name="Job Missing Retry Policy",
        description="Queue jobs without retry configuration",
        category="security",
        severity="medium",
        layer="backend",
        tags=["reliability", "queues"],
    ),
    RuleInfo(
        id="job-http-call-missing-timeout",
        name="HTTP Call Missing Timeout",
        description="HTTP requests without timeout limits",
        category="security",
        severity="medium",
        layer="backend",
        tags=["reliability", "http"],
    ),
    RuleInfo(
        id="missing-throttle-on-auth-api-routes",
        name="Missing Rate Limiting",
        description="Auth routes without throttle middleware",
        category="security",
        severity="medium",
        layer="backend",
        tags=["security", "rate-limiting"],
    ),
    RuleInfo(
        id="missing-auth-on-mutating-api-routes",
        name="Missing Auth on Mutations",
        description="Mutation endpoints without authentication",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "authentication"],
    ),
    RuleInfo(
        id="policy-coverage-on-mutations",
        name="Missing Policy on Mutations",
        description="Mutation endpoints without policy checks",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "authorization"],
    ),
    RuleInfo(
        id="authorization-bypass-risk",
        name="Authorization Bypass Risk",
        description="Potential authorization bypass patterns",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "authorization"],
    ),
    RuleInfo(
        id="transaction-required-for-multi-write",
        name="Missing Transaction",
        description="Multiple writes without transaction wrapper",
        category="architecture",
        severity="high",
        layer="backend",
        tags=["database", "transactions"],
    ),
    RuleInfo(
        id="tenant-scope-enforcement",
        name="Tenant Scope Enforcement",
        description="Missing tenant scoping in queries",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "multi-tenancy"],
    ),
    RuleInfo(
        id="blade-xss-risk",
        name="Blade XSS Risk",
        description="Unescaped output in Blade templates",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "xss"],
    ),
    RuleInfo(
        id="raw-sql",
        name="Raw SQL Usage",
        description="Raw SQL queries without parameterization",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "sql"],
    ),
    RuleInfo(
        id="unsafe-eval",
        name="Unsafe eval() Usage",
        description="Dynamic code evaluation",
        category="security",
        severity="high",
        layer="shared",
        tags=["security"],
    ),
    RuleInfo(
        id="unsafe-unserialize",
        name="Unsafe Unserialize",
        description="Unserialization of untrusted data",
        category="security",
        severity="high",
        layer="shared",
        tags=["security"],
    ),
    RuleInfo(
        id="command-injection-risk",
        name="Command Injection Risk",
        description="Shell commands with user input",
        category="security",
        severity="critical",
        layer="shared",
        tags=["security", "injection"],
    ),
    RuleInfo(
        id="sql-injection-risk",
        name="SQL Injection Risk",
        description="SQL queries with unsanitized input",
        category="security",
        severity="critical",
        layer="shared",
        tags=["security", "injection"],
    ),
    
    # === Backend: Performance ===
    RuleInfo(
        id="n-plus-one-risk",
        name="N+1 Query Risk",
        description="Potential N+1 query patterns",
        category="performance",
        severity="medium",
        layer="backend",
        tags=["performance", "eloquent"],
    ),
    RuleInfo(
        id="inertia-shared-props-eager-query",
        name="Inertia Props Eager Loading",
        description="Shared props causing N+1 queries",
        category="performance",
        severity="medium",
        layer="backend",
        tags=["performance", "inertia"],
    ),
    RuleInfo(
        id="config-in-loop",
        name="Config in Loop",
        description="Config calls inside loops",
        category="performance",
        severity="low",
        layer="backend",
        tags=["performance"],
    ),
    
    # === Frontend: React Best Practices ===
    RuleInfo(
        id="large-react-component",
        name="Large React Component",
        description="Components exceeding size thresholds",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["components", "size"],
    ),
    RuleInfo(
        id="inline-api-logic",
        name="Inline API Logic",
        description="API calls directly in components",
        category="react_best_practice",
        severity="high",
        layer="frontend",
        tags=["api", "architecture"],
    ),
    RuleInfo(
        id="react-useeffect-deps",
        name="useEffect Dependency Issues",
        description="Missing or incorrect useEffect dependencies",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["hooks", "effects"],
    ),
    RuleInfo(
        id="react-no-array-index-key",
        name="Array Index as Key",
        description="Using array index as React key",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["rendering", "keys"],
    ),
    RuleInfo(
        id="hooks-in-conditional-or-loop",
        name="Hooks in Conditionals",
        description="React hooks called conditionally",
        category="react_best_practice",
        severity="high",
        layer="frontend",
        tags=["hooks", "rules"],
    ),
    RuleInfo(
        id="missing-key-on-list-render",
        name="Missing Key in List",
        description="List rendering without keys",
        category="react_best_practice",
        severity="high",
        layer="frontend",
        tags=["rendering", "keys"],
    ),
    RuleInfo(
        id="hardcoded-user-facing-strings",
        name="Hardcoded Strings",
        description="User-facing text without i18n",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["i18n", "strings"],
    ),
    RuleInfo(
        id="interactive-element-a11y",
        name="Interactive Element Accessibility",
        description="Interactive elements missing accessibility",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "interactive"],
    ),
    RuleInfo(
        id="form-label-association",
        name="Form Label Association",
        description="Inputs without associated labels",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "forms"],
    ),
    RuleInfo(
        id="inertia-page-missing-head",
        name="Inertia Page Missing Head",
        description="Inertia pages without Head component",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["inertia", "seo"],
    ),
    RuleInfo(
        id="inertia-internal-link-anchor",
        name="Inertia Internal Link",
        description="Using anchor tags for Inertia navigation",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["inertia", "routing"],
    ),
    RuleInfo(
        id="inertia-form-uses-fetch",
        name="Inertia Form Uses Fetch",
        description="Manual fetch instead of Inertia form",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["inertia", "forms"],
    ),
    RuleInfo(
        id="anonymous-default-export-component",
        name="Anonymous Default Export",
        description="Components without named exports",
        category="maintainability",
        severity="medium",
        layer="frontend",
        tags=["exports", "naming"],
    ),
    RuleInfo(
        id="multiple-exported-react-components",
        name="Multiple Exported Components",
        description="Files with multiple component exports",
        category="maintainability",
        severity="low",
        layer="frontend",
        tags=["exports", "organization"],
    ),
    RuleInfo(
        id="context-provider-inline-value",
        name="Context Provider Inline Value",
        description="Context value created inline causing re-renders",
        category="performance",
        severity="medium",
        layer="frontend",
        tags=["performance", "context"],
    ),
    RuleInfo(
        id="react-useeffect-fetch-without-abort",
        name="Fetch Without Abort",
        description="useEffect fetch without abort controller",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["hooks", "fetch"],
    ),
    
    # === Frontend: Accessibility ===
    RuleInfo(
        id="color-contrast-ratio",
        name="Color Contrast Ratio",
        description="Text with insufficient contrast",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "contrast"],
    ),
    RuleInfo(
        id="page-title-missing",
        name="Page Title Missing",
        description="Pages without proper title elements",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "seo"],
    ),
    RuleInfo(
        id="status-message-announcement",
        name="Status Message Announcement",
        description="Status messages without ARIA live regions",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "aria"],
    ),
    RuleInfo(
        id="button-text-vague",
        name="Vague Button Text",
        description="Buttons with unclear text labels",
        category="accessibility",
        severity="low",
        layer="frontend",
        tags=["a11y", "buttons"],
    ),
    RuleInfo(
        id="modal-trap-focus",
        name="Modal Focus Trap",
        description="Modals without focus trapping",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "modals"],
    ),
    RuleInfo(
        id="error-message-missing",
        name="Error Message Missing",
        description="Form fields without error messages",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "forms"],
    ),
    RuleInfo(
        id="autocomplete-missing",
        name="Autocomplete Missing",
        description="Form fields without autocomplete attributes",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "forms"],
    ),
    RuleInfo(
        id="touch-target-size",
        name="Touch Target Size",
        description="Interactive elements too small for touch",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "touch"],
    ),
    RuleInfo(
        id="focus-indicator-missing",
        name="Focus Indicator Missing",
        description="Elements without visible focus states",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "focus"],
    ),
    
    # === Frontend: TypeScript ===
    RuleInfo(
        id="typescript-type-check",
        name="TypeScript Type Check",
        description="TypeScript type errors and syntax issues",
        category="maintainability",
        severity="high",
        layer="frontend",
        tags=["typescript", "types", "syntax", "tsc"],
    ),
    
    # === Shared: Complexity ===
    RuleInfo(
        id="high-complexity",
        name="High Complexity",
        description="Methods with high cyclomatic complexity",
        category="complexity",
        severity="high",
        layer="shared",
        tags=["complexity", "metrics"],
    ),
    RuleInfo(
        id="long-method",
        name="Long Method",
        description="Methods exceeding length threshold",
        category="complexity",
        severity="medium",
        layer="shared",
        tags=["complexity", "size"],
    ),
    RuleInfo(
        id="god-class",
        name="God Class",
        description="Classes with too many methods or lines",
        category="complexity",
        severity="critical",
        layer="shared",
        tags=["complexity", "size"],
    ),
    
    # === Shared: Maintainability ===
    RuleInfo(
        id="too-many-dependencies",
        name="Too Many Dependencies",
        description="Classes with excessive dependencies",
        category="maintainability",
        severity="medium",
        layer="shared",
        tags=["coupling", "di"],
    ),
    RuleInfo(
        id="static-helper-abuse",
        name="Static Helper Abuse",
        description="Overuse of static helper methods",
        category="maintainability",
        severity="low",
        layer="shared",
        tags=["design", "static"],
    ),
    RuleInfo(
        id="unused-private-method",
        name="Unused Private Method",
        description="Private methods that are never called",
        category="maintainability",
        severity="low",
        layer="shared",
        tags=["dead-code"],
    ),
    RuleInfo(
        id="circular-dependency",
        name="Circular Dependency",
        description="Circular imports between modules",
        category="architecture",
        severity="high",
        layer="shared",
        tags=["architecture", "dependencies"],
    ),
    RuleInfo(
        id="high-coupling-class",
        name="High Coupling Class",
        description="Classes with excessive outgoing coupling",
        category="architecture",
        severity="medium",
        layer="shared",
        tags=["coupling", "architecture"],
    ),
    RuleInfo(
        id="prefer-imports",
        name="Prefer Imports",
        description="FQCN usage instead of imports",
        category="maintainability",
        severity="low",
        layer="shared",
        tags=["imports", "style"],
    ),
    RuleInfo(
        id="no-inline-types",
        name="No Inline Types",
        description="Inline TypeScript types instead of interfaces",
        category="maintainability",
        severity="medium",
        layer="frontend",
        tags=["typescript", "types"],
    ),
    RuleInfo(
        id="no-inline-services",
        name="No Inline Services",
        description="Service instantiation in components",
        category="maintainability",
        severity="medium",
        layer="frontend",
        tags=["di", "services"],
    ),
    RuleInfo(
        id="react-project-structure-consistency",
        name="React Structure Consistency",
        description="Context-aware detection of scattered hooks, services, utilities, types, and weak folder boundaries",
        category="architecture",
        severity="medium",
        layer="frontend",
        tags=["react", "folders", "architecture", "scalability"],
    ),
    RuleInfo(
        id="tests-missing",
        name="Tests Missing",
        description="Project without test files",
        category="maintainability",
        severity="medium",
        layer="shared",
        tags=["testing"],
    ),
    RuleInfo(
        id="low-coverage-files",
        name="Low Coverage Files",
        description="Files with low test coverage",
        category="maintainability",
        severity="medium",
        layer="shared",
        tags=["testing", "coverage"],
    ),
    
    # === Shared: DRY ===
    RuleInfo(
        id="dry-violation",
        name="DRY Violation",
        description="Duplicated code blocks",
        category="dry",
        severity="medium",
        layer="shared",
        tags=["duplication"],
    ),
    
    # === Shared: SRP ===
    # (Covered by other rules like fat-controller, god-class)
    
    # === Security: Inertia/Props ===
    RuleInfo(
        id="inertia-shared-props-sensitive-data",
        name="Sensitive Data in Props",
        description="Sensitive data in shared Inertia props",
        category="security",
        severity="high",
        layer="backend",
        tags=["security", "inertia"],
    ),
    RuleInfo(
        id="npm-dependency-below-secure-version",
        name="Insecure NPM Dependency",
        description="NPM packages with known vulnerabilities",
        category="security",
        severity="high",
        layer="frontend",
        tags=["security", "dependencies"],
    ),
]


def get_rules_by_layer() -> dict[str, list[RuleInfo]]:
    """Group rules by layer (backend/frontend/shared)."""
    result: dict[str, list[RuleInfo]] = {"backend": [], "frontend": [], "shared": []}
    for rule in RULE_METADATA:
        result[rule.layer].append(rule)
    return result


def get_rules_by_category() -> dict[str, list[RuleInfo]]:
    """Group rules by category."""
    result: dict[str, list[RuleInfo]] = {}
    for rule in RULE_METADATA:
        if rule.category not in result:
            result[rule.category] = []
        result[rule.category].append(rule)
    return result


def get_rules_grouped_for_ui() -> dict:
    """
    Get rules structured for the UI.
    
    Returns:
        {
            "layers": [
                {
                    "id": "backend",
                    "label": "Backend (Laravel/PHP)",
                    "categories": [
                        {
                            "id": "laravel_best_practice",
                            "label": "Laravel Best Practices",
                            "rules": [...]
                        }
                    ]
                }
            ]
        }
    """
    # Group by layer then by category
    layers_data = []
    
    for layer_id, layer_info in LAYER_GROUPS.items():
        # Get categories for this layer
        categories_in_layer = [
            (cat_id, cat_info)
            for cat_id, cat_info in CATEGORY_GROUPS.items()
            if cat_info["layer"] == layer_id or (layer_id == "shared" and cat_info["layer"] == "shared")
        ]
        # Sort by order
        categories_in_layer.sort(key=lambda x: x[1]["order"])
        
        categories_data = []
        for cat_id, cat_info in categories_in_layer:
            rules_in_cat = [r for r in RULE_METADATA if r.category == cat_id]
            if not rules_in_cat:
                continue
            
            categories_data.append({
                "id": cat_id,
                "label": cat_info["label"],
                "description": cat_info["description"],
                "rules": [
                    {
                        "id": r.id,
                        "name": r.name,
                        "description": r.description,
                        "severity": r.severity,
                        "tags": r.tags,
                    }
                    for r in sorted(rules_in_cat, key=lambda x: x.name)
                ]
            })
        
        if categories_data:
            layers_data.append({
                "id": layer_id,
                "label": layer_info["label"],
                "description": layer_info["description"],
                "icon": layer_info["icon"],
                "categories": categories_data,
            })
    
    return {"layers": layers_data}


def get_rule_ids() -> list[str]:
    """Get all rule IDs."""
    return [r.id for r in RULE_METADATA]
