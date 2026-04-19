"""
Rule Metadata for UI Grouping

Provides structured metadata about rules for the advanced profile configuration UI.
Rules are grouped by layer (Backend/Frontend) then by category.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


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
        id="controller-index-filter-duplication",
        name="Controller Index Filter Duplication",
        description="Repeated inline status/q index filter extraction across controllers",
        category="architecture",
        severity="medium",
        layer="backend",
        tags=["architecture", "controllers", "dry", "filters"],
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
        id="action-class-naming-consistency",
        name="Action Naming Consistency",
        description="Mixed action naming style under app/Actions",
        category="architecture",
        severity="low",
        layer="backend",
        tags=["architecture", "actions", "naming"],
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
    RuleInfo(
        id="model-cross-model-query",
        name="Cross-Model Query in Model",
        description="Model methods querying other models directly",
        category="architecture",
        severity="low",
        layer="backend",
        tags=["architecture", "models", "boundaries"],
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
    RuleInfo(
        id="skip-link-missing",
        name="Skip Link Missing",
        description="Shell/layout is missing a valid skip-to-content link",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "keyboard", "navigation"],
    ),
    RuleInfo(
        id="semantic-wrapper-breakage",
        name="Semantic Wrapper Breakage",
        description="JSX wrappers that break list/table/description semantics",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "semantics", "jsx"],
    ),
    RuleInfo(
        id="interactive-accessible-name-required",
        name="Interactive Accessible Name Required",
        description="Interactive controls missing a programmatic accessible name",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "aria", "forms"],
    ),
    RuleInfo(
        id="jsx-aria-attribute-format",
        name="JSX ARIA Attribute Format",
        description="Malformed ARIA attribute names in JSX",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "aria", "jsx"],
    ),
    RuleInfo(
        id="outside-click-without-keyboard-fallback",
        name="Outside Click Without Keyboard Fallback",
        description="Overlay dismissal handled by pointer only without keyboard fallback",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "keyboard", "overlay"],
    ),
    RuleInfo(
        id="apg-tabs-keyboard-contract",
        name="APG Tabs Keyboard Contract",
        description="Custom tabs missing APG role/state/keyboard contract signals",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "apg", "tabs"],
    ),
    RuleInfo(
        id="apg-accordion-disclosure-contract",
        name="APG Accordion/Disclosure Contract",
        description="Disclosure widgets missing APG button/expanded/controls semantics",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "apg", "accordion"],
    ),
    RuleInfo(
        id="apg-menu-button-contract",
        name="APG Menu Button Contract",
        description="Menu button widgets missing APG expanded/controls/keyboard semantics",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "apg", "menu"],
    ),
    RuleInfo(
        id="apg-combobox-contract",
        name="APG Combobox Contract",
        description="Combobox widgets missing APG expanded/controls/active-option semantics",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "apg", "combobox"],
    ),
    RuleInfo(
        id="dialog-focus-restore-missing",
        name="Dialog Focus Restore Missing",
        description="Dialog close flow missing focus restore signal",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "dialog", "focus"],
    ),
    RuleInfo(
        id="tailwind-motion-reduce-missing",
        name="Tailwind Motion Reduce Missing",
        description="Animation utilities used without motion-safe/motion-reduce strategy",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "tailwind", "motion"],
    ),
    RuleInfo(
        id="tailwind-appearance-none-risk",
        name="Tailwind Appearance None Risk",
        description="appearance-none used on controls without compensating affordances",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "tailwind", "forms"],
    ),
    RuleInfo(
        id="css-focus-outline-without-replacement",
        name="CSS Focus Outline Without Replacement",
        description="Focus outline removed without visible replacement style",
        category="accessibility",
        severity="high",
        layer="frontend",
        tags=["a11y", "css", "focus"],
    ),
    RuleInfo(
        id="css-hover-only-interaction",
        name="CSS Hover-Only Interaction",
        description="Hover interaction styles without keyboard focus equivalent",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "css", "keyboard"],
    ),
    RuleInfo(
        id="css-color-only-state-indicator",
        name="CSS Color-Only State Indicator",
        description="Likely state indicators relying on color only",
        category="accessibility",
        severity="medium",
        layer="frontend",
        tags=["a11y", "css", "contrast"],
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
        id="react-parent-child-spacing-overlap",
        name="Parent/Child Spacing Overlap",
        description="Direct JSX parent/child nodes duplicate the same spacing utility scope",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["react", "layout", "tailwind", "spacing"],
    ),
    RuleInfo(
        id="css-font-size-px",
        name="CSS Font Size Uses px",
        description="Font-size declared in px instead of rem",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["css", "typography", "units", "accessibility"],
    ),
    RuleInfo(
        id="css-spacing-px",
        name="CSS Spacing Uses px",
        description="Margin/padding/gap values use px instead of rem scale",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["css", "spacing", "units", "design-system"],
    ),
    RuleInfo(
        id="css-fixed-layout-px",
        name="CSS Fixed Layout px",
        description="Rigid large px width/height values in layout declarations",
        category="react_best_practice",
        severity="low",
        layer="frontend",
        tags=["css", "layout", "responsive"],
    ),
    RuleInfo(
        id="tailwind-arbitrary-value-overuse",
        name="Tailwind Arbitrary Value Overuse",
        description="Excessive use of arbitrary Tailwind values in one class string",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["tailwind", "design-system", "maintainability"],
    ),
    RuleInfo(
        id="tailwind-arbitrary-text-size",
        name="Tailwind Arbitrary Text Size",
        description="Arbitrary text-[...] sizing instead of text scale tokens",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["tailwind", "typography", "design-system"],
    ),
    RuleInfo(
        id="tailwind-arbitrary-spacing",
        name="Tailwind Arbitrary Spacing",
        description="Arbitrary spacing utilities for p/m/gap/space",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["tailwind", "spacing", "design-system"],
    ),
    RuleInfo(
        id="tailwind-arbitrary-layout-size",
        name="Tailwind Arbitrary Layout Size",
        description="Rigid arbitrary width/height values in Tailwind classes",
        category="react_best_practice",
        severity="low",
        layer="frontend",
        tags=["tailwind", "layout", "responsive"],
    ),
    RuleInfo(
        id="tailwind-arbitrary-radius-shadow",
        name="Tailwind Arbitrary Radius/Shadow",
        description="Arbitrary rounded/shadow values instead of shared surface tokens",
        category="react_best_practice",
        severity="low",
        layer="frontend",
        tags=["tailwind", "surface", "design-system"],
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
        id="avoid-props-to-state-copy",
        name="Avoid Props-to-State Copy",
        description="State initialized directly from props without clear divergence intent",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["react", "state", "props"],
    ),
    RuleInfo(
        id="props-state-sync-effect-smell",
        name="Props-State Sync Effect Smell",
        description="useEffect mirrors dependency values into local state",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["react", "useeffect", "state"],
    ),
    RuleInfo(
        id="controlled-uncontrolled-input-mismatch",
        name="Controlled/Uncontrolled Input Mismatch",
        description="Form control mixes or violates controlled input contracts",
        category="react_best_practice",
        severity="high",
        layer="frontend",
        tags=["react", "forms", "inputs"],
    ),
    RuleInfo(
        id="usememo-overuse",
        name="useMemo Overuse",
        description="useMemo used where memoization benefit is weak",
        category="react_best_practice",
        severity="low",
        layer="frontend",
        tags=["react", "performance", "memoization"],
    ),
    RuleInfo(
        id="usecallback-overuse",
        name="useCallback Overuse",
        description="useCallback used where handler stability benefit is weak",
        category="react_best_practice",
        severity="low",
        layer="frontend",
        tags=["react", "performance", "memoization"],
    ),
    RuleInfo(
        id="context-oversized-provider",
        name="Context Oversized Provider",
        description="Provider value payload is broad and likely to fan out rerenders",
        category="performance",
        severity="medium",
        layer="frontend",
        tags=["react", "context", "performance"],
    ),
    RuleInfo(
        id="lazy-without-suspense",
        name="Lazy Without Suspense",
        description="React.lazy component rendered without Suspense boundary",
        category="react_best_practice",
        severity="high",
        layer="frontend",
        tags=["react", "suspense", "lazy"],
    ),
    RuleInfo(
        id="suspense-fallback-missing",
        name="Suspense Fallback Missing",
        description="Suspense boundary defined without explicit fallback",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["react", "suspense"],
    ),
    RuleInfo(
        id="stale-closure-in-timer",
        name="Stale Closure in Timer",
        description="Timer callback captures stale state in effect lifecycle",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["react", "hooks", "timers"],
    ),
    RuleInfo(
        id="stale-closure-in-listener",
        name="Stale Closure in Listener",
        description="Event listener callback captures stale state in effect lifecycle",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["react", "hooks", "events"],
    ),
    RuleInfo(
        id="duplicate-key-source",
        name="Duplicate Key Source",
        description="List key derived from likely non-unique field",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["react", "keys", "rendering"],
    ),
    RuleInfo(
        id="missing-loading-state",
        name="Missing Loading State",
        description="Async page flow lacks explicit loading/pending branch",
        category="react_best_practice",
        severity="low",
        layer="frontend",
        tags=["react", "ux", "async"],
    ),
    RuleInfo(
        id="missing-empty-state",
        name="Missing Empty State",
        description="List page lacks explicit empty-state branch",
        category="react_best_practice",
        severity="low",
        layer="frontend",
        tags=["react", "ux", "lists"],
    ),
    RuleInfo(
        id="ref-access-during-render",
        name="Ref Access During Render",
        description="Mutable ref current read directly in render output",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["react", "refs", "render"],
    ),
    RuleInfo(
        id="ref-used-as-reactive-state",
        name="Ref Used as Reactive State",
        description="Ref used as primary reactive state instead of useState",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["react", "refs", "state"],
    ),
    RuleInfo(
        id="meta-description-missing-or-generic",
        name="Meta Description Missing/Generic",
        description="Indexable page lacks a specific meta description",
        category="react_best_practice",
        severity="low",
        layer="frontend",
        tags=["seo", "metadata"],
    ),
    RuleInfo(
        id="canonical-missing-or-invalid",
        name="Canonical Missing/Invalid",
        description="Indexable page missing or misconfigured canonical URL",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["seo", "canonical", "indexing"],
    ),
    RuleInfo(
        id="robots-directive-risk",
        name="Robots Directive Risk",
        description="Risky robots directives on public/indexable page surfaces",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["seo", "robots", "indexing"],
    ),
    RuleInfo(
        id="crawlable-internal-navigation-required",
        name="Crawlable Internal Navigation Required",
        description="Internal navigation lacks crawlable anchor/href semantics",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["seo", "links", "crawlability"],
    ),
    RuleInfo(
        id="jsonld-structured-data-invalid-or-mismatched",
        name="JSON-LD Invalid/Mismatched",
        description="Structured data block is invalid or missing core schema signals",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["seo", "jsonld", "schema"],
    ),
    RuleInfo(
        id="h1-singleton-violation",
        name="H1 Singleton Violation",
        description="Page has missing or multiple H1 headings",
        category="react_best_practice",
        severity="medium",
        layer="frontend",
        tags=["seo", "headings", "content"],
    ),
    RuleInfo(
        id="page-indexability-conflict",
        name="Page Indexability Conflict",
        description="Conflicting robots/canonical intent for same page",
        category="react_best_practice",
        severity="high",
        layer="frontend",
        tags=["seo", "indexing", "canonical", "robots"],
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


def _title_from_rule_id(rule_id: str) -> str:
    return " ".join(part.capitalize() for part in rule_id.split("-") if part)


def _infer_layer_from_rule(*, module_name: str, category: str) -> Literal["backend", "frontend", "shared"]:
    if module_name.startswith("rules.react."):
        return "frontend"
    if module_name.startswith("rules.laravel."):
        return "backend"
    if category in {"react_best_practice", "accessibility"}:
        return "frontend"
    if category in {"laravel_best_practice", "validation"}:
        return "backend"
    return "shared"


def _build_fallback_rule_info(rule_id: str, rule_class: Any) -> RuleInfo:
    raw_category = getattr(rule_class, "category", "maintainability")
    raw_severity = getattr(rule_class, "default_severity", "medium")
    category = str(getattr(raw_category, "value", raw_category) or "maintainability").strip().lower()
    severity = str(getattr(raw_severity, "value", raw_severity) or "medium").strip().lower()
    module_name = str(getattr(rule_class, "__module__", "") or "")
    layer = _infer_layer_from_rule(module_name=module_name, category=category)
    name = str(getattr(rule_class, "name", "") or "").strip() or _title_from_rule_id(rule_id)
    description = str(getattr(rule_class, "description", "") or "").strip() or f"{name} rule"
    tags = [category]
    if module_name.startswith("rules.react."):
        tags.append("react")
    elif module_name.startswith("rules.laravel."):
        tags.append("laravel")
    return RuleInfo(
        id=rule_id,
        name=name,
        description=description,
        category=category,
        severity=severity,
        layer=layer,
        tags=tags,
    )


def _effective_rule_metadata() -> list[RuleInfo]:
    merged: dict[str, RuleInfo] = {rule.id: rule for rule in RULE_METADATA}

    try:
        # Lazy import to avoid loading the full rule graph unless metadata is requested.
        from core.rule_engine import ALL_RULES
    except Exception:
        return list(merged.values())

    for rule_id, rule_class in ALL_RULES.items():
        if rule_id in merged:
            continue
        merged[rule_id] = _build_fallback_rule_info(rule_id, rule_class)

    return list(merged.values())


def _effective_category_groups(rules: list[RuleInfo]) -> dict[str, dict[str, Any]]:
    categories: dict[str, dict[str, Any]] = {cat_id: dict(cat_info) for cat_id, cat_info in CATEGORY_GROUPS.items()}
    next_order = max((int(info.get("order", 0) or 0) for info in categories.values()), default=0) + 1
    for rule in rules:
        if rule.category in categories:
            continue
        categories[rule.category] = {
            "label": _title_from_rule_id(rule.category.replace("_", "-")),
            "description": "Auto-detected category",
            "layer": rule.layer,
            "order": next_order,
        }
        next_order += 1
    return categories


def get_rules_by_layer() -> dict[str, list[RuleInfo]]:
    """Group rules by layer (backend/frontend/shared)."""
    rules = _effective_rule_metadata()
    result: dict[str, list[RuleInfo]] = {"backend": [], "frontend": [], "shared": []}
    for rule in rules:
        result[rule.layer].append(rule)
    return result


def get_rules_by_category() -> dict[str, list[RuleInfo]]:
    """Group rules by category."""
    rules = _effective_rule_metadata()
    result: dict[str, list[RuleInfo]] = {}
    for rule in rules:
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
    rules = _effective_rule_metadata()
    categories = _effective_category_groups(rules)
    layers_data = []
    
    for layer_id, layer_info in LAYER_GROUPS.items():
        # Get categories for this layer
        categories_in_layer = [
            (cat_id, cat_info)
            for cat_id, cat_info in categories.items()
            if cat_info["layer"] == layer_id or (layer_id == "shared" and cat_info["layer"] == "shared")
        ]
        # Sort by order
        categories_in_layer.sort(key=lambda x: x[1]["order"])
        
        categories_data = []
        for cat_id, cat_info in categories_in_layer:
            rules_in_cat = [r for r in rules if r.category == cat_id]
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
    return [r.id for r in _effective_rule_metadata()]
