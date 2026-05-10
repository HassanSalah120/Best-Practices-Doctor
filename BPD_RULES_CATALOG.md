# BPD Rules Catalog

Generated from `backend/core/rule_engine.py` (`ALL_RULES`) on 2026-05-07.

This is a single-file catalog of every registered Best Practices Doctor rule, grouped by the rule metadata category/group currently used by the scanner.

## Summary

- Total registered rules: 313
- Startup profile enabled: 127
- Balanced profile enabled: 244
- Strict profile enabled: 313

### Severity Counts

- critical: 9
- high: 132
- low: 43
- medium: 129

### Classification Counts

- advisory: 168
- defect: 43
- risk: 102

### Detection Counts

- ast: 94
- cross-file: 35
- process: 3
- regex: 181

## Categories

### API Design (8)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `api-endpoint-missing-idempotency-key` | API Endpoint Missing Idempotency Key | high | risk | regex | low | laravel | controller, route | No (-) | Yes (high) | Yes (high) | Detects mutating API handlers that create durable state without an idempotency key guard |
| `api-resource-usage` | Prefer API Resources | medium | advisory | regex | low | laravel | global | Yes (medium) | Yes (medium) | Yes (medium) | Suggests using Laravel API Resources instead of returning raw arrays from API controllers |
| `api-response-inconsistent-shape` | API Response Inconsistent Shape | medium | advisory | ast | medium | laravel | controller | No (-) | No (-) | Yes (medium) | Detects controllers that mix wrapped JSON, raw JSON arrays, and resource response shapes |
| `controller-returning-view-in-api` | Controller Returning View in API | medium | advisory | regex | low | laravel | controller | No (-) | No (-) | Yes (medium) | Detects API routes returning Blade views instead of JSON responses |
| `inline-api-logic` | Inline API Logic Detection | medium | advisory | regex | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects API calls and logic in component bodies |
| `missing-api-rate-limit-headers` | Missing API Rate Limit Headers | low | advisory | regex | low | laravel | route, middleware | No (-) | Yes (low) | Yes (low) | Detects throttled API routes where rate-limit response headers may be stripped or absent |
| `missing-api-resource` | Missing API Resource | low | advisory | regex | low | laravel | global | No (-) | No (-) | Yes (medium) | Detects API endpoints returning raw model data instead of using API Resources |
| `public-api-versioning-missing` | Public API Versioning Missing | medium | advisory | ast | medium | laravel | route | No (-) | Yes (medium) | Yes (medium) | Detects public API routes that do not expose a versioned URI surface |

### Access Control (17)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `authorization-bypass-risk` | Authorization Bypass Risk | high | risk | cross-file | high | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects direct model access in mutation actions without authorization checks |
| `broadcast-channel-authorization-missing` | Broadcast Channel Authorization Missing | high | risk | ast | medium | laravel | global | No (-) | Yes (high) | Yes (high) | Detects broadcast channels that do not show explicit authorization logic |
| `client-side-auth-only` | Client-Side Authorization Only | high | risk | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects UI authorization checks that appear to lack nearby server-side enforcement cues |
| `console-command-missing-tenant-scope` | Console Command Missing Tenant Scope | high | risk | regex | low | laravel | php-class | No (-) | Yes (high) | Yes (high) | Detects Artisan commands that query tenant data without clinic or tenant scoping |
| `csrf-exception-wildcard-risk` | Broad CSRF Exception Wildcard | high | risk | regex | low | laravel | middleware | No (-) | Yes (high) | Yes (high) | Detects wildcard CSRF exception entries that can disable CSRF protection too broadly |
| `forced-login-without-authorization` | Forced Login Without Authorization | critical | risk | regex | low | laravel | controller, service | No (-) | Yes (critical) | Yes (critical) | Detects Auth::login calls that are not preceded by an authorization check |
| `high-privilege-action-missing-authorization` | High Privilege Action Missing Authorization | critical | risk | regex | low | laravel | service, controller | No (-) | Yes (critical) | Yes (critical) | Detects emergency access, impersonation, or role elevation without explicit authorization |
| `idor-risk-missing-ownership-check` | IDOR Risk Missing Ownership Check | high | risk | cross-file | high | laravel | global | No (-) | Yes (high) | Yes (high) | Detects authenticated resource fetch/update handlers missing ownership or policy checks |
| `job-missing-retry-policy` | Job Missing Retry Policy | medium | risk | regex | low | laravel | job | Yes (medium) | Yes (medium) | Yes (medium) | Detects side-effecting queued jobs without explicit retry or backoff controls |
| `missing-auth-on-mutating-api-routes` | Missing Auth On Mutating API Routes | high | risk | regex | low | laravel | route | Yes (high) | Yes (high) | Yes (high) | Detects mutating API routes that are not protected by auth middleware |
| `missing-content-security-policy` | Missing Content Security Policy | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects missing CSP middleware/header registration in Laravel bootstrap/kernel paths |
| `path-traversal-file-access` | Path Traversal File Access | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects request-derived file paths used in file access sinks without normalization |
| `policy-coverage-on-mutations` | Policy Coverage On Mutations | high | risk | cross-file | high | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects mutation controller actions without policy/gate/auth protection |
| `postmessage-receiver-origin-not-verified` | postMessage Receiver Missing Origin Verification | high | risk | ast | medium | react | react-component | No (-) | Yes (high) | Yes (high) | Detects message event listeners that handle cross-window messages without origin checks |
| `tenant-access-middleware-missing` | Tenant Access Middleware Missing | high | risk | cross-file | high | laravel | middleware | Yes (high) | Yes (high) | Yes (high) | Detects tenant-sensitive routes missing clinic/tenant access middleware |
| `tenant-scope-enforcement` | Tenant Scope Enforcement | high | risk | cross-file | high | laravel | model | Yes (high) | Yes (high) | Yes (high) | Detects tenant-sensitive queries that appear to be missing tenant scoping |
| `unsafe-csp-policy` | Unsafe CSP Policy | high | risk | regex | low | laravel | config | Yes (high) | Yes (high) | Yes (high) | Detects CSP definitions that allow unsafe inline or eval sources |

### Architecture Integrity (30)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `action-class-naming-consistency` | Action Class Naming Consistency | low | advisory | ast | medium | laravel | service | Yes (low) | Yes (low) | Yes (low) | Detects mixed action class naming style under app/Actions |
| `action-class-suggestion` | Action Class Suggestion | low | advisory | cross-file | high | laravel | service | No (-) | Yes (low) | Yes (low) | Suggests an Action class when a service has a single public method |
| `business-logic-in-migration` | Business Logic In Migration | high | advisory | regex | low | laravel | migration | No (-) | Yes (high) | Yes (high) | Detects model usage or business loops inside migration up methods |
| `circular-dependency` | Circular Dependency | high | advisory | cross-file | high | php | php-class | Yes (high) | Yes (high) | Yes (high) | Detects circular dependencies between classes (cycles in the dependency graph) |
| `contract-suggestion` | Contract-Based Development | low | advisory | ast | medium | laravel | service | No (-) | Yes (low) | Yes (medium) | Suggests using Interfaces (Contracts) for dependency injection |
| `controller-business-logic` | Business Logic In Controller | high | advisory | ast | medium | laravel | controller | Yes (high) | Yes (high) | Yes (high) | Detects complex/business logic inside controllers |
| `cross-feature-import-boundary` | Cross-Feature Import Boundary Violation | medium | advisory | regex | low | react | react-component | Yes (low) | Yes (medium) | Yes (medium) | Detects deep imports across feature boundaries |
| `custom-exception-suggestion` | Custom Exception Usage | high | advisory | ast | medium | laravel | global | Yes (low) | Yes (medium) | Yes (high) | Suggests using specific exceptions instead of generic ones |
| `duplicate-route-definition` | Duplicate Route Definition | high | advisory | cross-file | high | laravel | route | Yes (high) | Yes (high) | Yes (high) | Detects duplicate route method/URI definitions |
| `env-outside-config` | Avoid env() Outside Config | medium | advisory | ast | medium | laravel | config | Yes (medium) | Yes (medium) | Yes (medium) | Detects direct env() usage outside config files |
| `error-pages-missing` | Missing Laravel Error Pages | medium | advisory | cross-file | high | laravel | global | Yes (low) | Yes (medium) | Yes (medium) | Detects missing 4xx/5xx error pages in Blade or Inertia error surfaces |
| `fat-controller` | Fat Controller Detection | high | advisory | ast | medium | laravel | controller | Yes (high) | Yes (high) | Yes (high) | Detects controllers with too many responsibilities |
| `heavy-logic-in-routes` | Heavy Logic In Routes | medium | advisory | regex | low | laravel | route | Yes (medium) | Yes (medium) | Yes (medium) | Detects DB queries or service instantiation inside routes files |
| `high-coupling-class` | High Coupling Class | medium | advisory | ast | medium | php | php-class | Yes (medium) | Yes (medium) | Yes (medium) | Detects classes that depend on too many other application classes |
| `http-call-missing-fallback` | HTTP Call Missing Fallback | high | advisory | ast | medium | laravel | controller, service, job | No (-) | Yes (high) | Yes (high) | Detects Laravel HTTP client calls that are not wrapped or checked before use |
| `ioc-instead-of-new` | Prefer IoC Over new | medium | advisory | ast | medium | laravel | global | No (-) | Yes (low) | Yes (medium) | Suggests injecting dependencies instead of instantiating them in controllers |
| `long-method` | Long Method Detection | low | advisory | ast | medium | php | php-class, php-function | Yes (low) | Yes (medium) | Yes (medium) | Flags methods exceeding recommended length |
| `missing-circuit-breaker` | Missing Circuit Breaker | medium | advisory | regex | low | laravel | service, controller, job | No (-) | Yes (medium) | Yes (medium) | Detects Laravel HTTP client calls without timeout or fallback handling |
| `missing-domain-event` | Missing Domain Event | low | advisory | regex | low | laravel | service, controller | No (-) | Yes (low) | Yes (low) | Suggests dispatching domain events after critical model writes |
| `missing-feature-flag-pattern` | Missing Feature Flag Pattern | low | advisory | cross-file | medium | laravel | global | No (-) | No (-) | Yes (low) | Suggests a feature flag mechanism for larger Laravel apps with many routes |
| `missing-health-check-endpoint` | Missing Health Check Endpoint | medium | advisory | regex | medium | laravel | route | No (-) | Yes (medium) | Yes (medium) | Detects Laravel apps without a health, status, or ping route |
| `missing-model-observer-registration` | Missing Model Observer Registration | high | risk | cross-file | medium | laravel | observer, provider | No (-) | Yes (high) | Yes (high) | Detects Laravel Observer classes that are never registered in a ServiceProvider |
| `no-closure-routes` | Avoid Closure Routes | medium | advisory | regex | low | laravel | route | Yes (medium) | Yes (medium) | Yes (medium) | Detects closure-based route handlers (prefer controllers) |
| `no-json-encode-in-controllers` | Avoid json_encode/toJson in Controllers | medium | advisory | regex | low | laravel | controller | Yes (medium) | Yes (medium) | Yes (medium) | Detects json_encode() / ->toJson() usage inside controllers (prefer Response/Resources) |
| `observer-heavy-logic` | Observer Heavy Logic | medium | advisory | ast | medium | laravel | observer | No (-) | Yes (medium) | Yes (medium) | Detects observers with large or side-effect-heavy hook methods |
| `react-project-structure-consistency` | React Project Structure Consistency | medium | advisory | ast | medium | react | react-component | Yes (low) | Yes (medium) | Yes (medium) | Detects inconsistent React folder boundaries for hooks, services, utilities, helpers, types, and constants |
| `realtime-config-outside-laravel-config` | Realtime Config Outside Laravel Config | low | advisory | cross-file | medium | laravel | config | No (-) | Yes (low) | Yes (low) | Detects standalone realtime config files that are not bridged into Laravel config |
| `service-extraction` | Service Extraction Suggestion | medium | advisory | ast | medium | laravel | service | No (-) | Yes (low) | Yes (high) | Suggests extracting business logic to Service classes |
| `service-provider-heavy-boot` | Heavy ServiceProvider Boot | high | advisory | regex | low | laravel | provider | No (-) | Yes (high) | Yes (high) | Detects DB, HTTP, or filesystem work inside ServiceProvider::boot |
| `static-helper-abuse` | Static Helper Abuse | medium | advisory | ast | medium | php | php-class | Yes (medium) | Yes (medium) | Yes (medium) | Detects heavy use of Helper/Utils static calls (prefer DI) |

### Authentication & Session (3)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `cookie-samesite-missing` | Cookie SameSite Missing | high | risk | regex | low | laravel | config | No (-) | Yes (high) | Yes (high) | Detects weak or missing SameSite configuration in session cookies |
| `registration-missing-registered-event` | Registration Missing Registered Event | high | risk | regex | low | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects user registration flows that create users without dispatching Registered |
| `session-fixation-regenerate-missing` | Session Regeneration Missing After Login | high | risk | regex | low | laravel | config | No (-) | Yes (high) | Yes (high) | Detects authentication flows missing session regeneration |

### Caching (2)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `cache-missing-fallback` | Cache Missing Fallback | high | advisory | ast | medium | laravel | controller, service, job | No (-) | Yes (high) | Yes (high) | Detects Cache::get calls whose nullable result is dereferenced without a fallback |
| `missing-cache-for-reference-data` | Missing Cache for Reference Data | low | advisory | ast | medium | laravel | global | No (-) | No (-) | Yes (medium) | Detects reference data queries that could benefit from caching |

### Code Quality (44)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `anonymous-default-export-component` | Anonymous Default Export Component | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects anonymous default-exported React components |
| `blade-component-no-fallback-slot` | Blade Component No Fallback Slot | low | advisory | regex | low | laravel | blade | No (-) | No (-) | Yes (low) | Detects anonymous Blade components that render $slot without a fallback or empty-state guard |
| `canonical-missing-or-invalid` | Canonical Missing or Invalid | medium | advisory | regex | low | react | react-component, page | Yes (low) | Yes (medium) | Yes (medium) | Detects missing or malformed canonical metadata on public/indexable pages |
| `console-log-in-production-code` | Console Log In Production Code | medium | risk | regex | low | react | react-component, page | No (-) | Yes (medium) | Yes (medium) | Detects console calls left in non-test frontend source files |
| `controlled-uncontrolled-input-mismatch` | Controlled/Uncontrolled Input Mismatch | high | advisory | ast | medium | react | react-component, form | Yes (high) | Yes (high) | Yes (high) | Detects React form controls that switch or violate controlled-input contracts |
| `controller-inline-validation` | Inline Validation In Controller | medium | advisory | ast | medium | laravel | controller | Yes (low) | Yes (medium) | Yes (medium) | Detects inline validation inside controller actions (prefer FormRequest) |
| `crawlable-internal-navigation-required` | Crawlable Internal Navigation Required | medium | advisory | regex | low | react | react-component | Yes (low) | Yes (medium) | Yes (medium) | Detects internal navigation implemented without crawlable anchor/link semantics |
| `css-fixed-layout-px` | CSS Fixed Layout px Dimensions | low | advisory | regex | low | react | react-component, layout | No (-) | No (-) | Yes (low) | Detects rigid large px width/height values in layout declarations |
| `css-font-size-px` | CSS Font Size Uses px | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects font-size declared in px instead of rem |
| `css-spacing-px` | CSS Spacing Uses px | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects margin/padding/gap spacing declared in px instead of rem scale |
| `dto-suggestion` | DTO Suggestion | medium | advisory | ast | medium | laravel | service | No (-) | Yes (low) | Yes (medium) | Suggests DTOs when large associative arrays are used as data carriers |
| `enum-suggestion` | Enum Suggestion | low | advisory | ast | medium | laravel | global | Yes (low) | Yes (low) | Yes (low) | Suggests creating PHP enums for clustered or repeated string literals |
| `exhaustive-deps-ast` | Exhaustive Dependencies (AST) | high | advisory | ast | medium | react | react-component | No (-) | Yes (medium) | Yes (medium) | AST-based detection of missing dependencies in React hooks |
| `h1-singleton-violation` | H1 Singleton Violation | medium | advisory | regex | low | react | react-component, page | Yes (low) | Yes (medium) | Yes (medium) | Detects missing or multiple H1 headings on page surfaces |
| `hardcoded-user-facing-strings` | Hardcoded User Facing Strings | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects likely user-facing hardcoded strings not wrapped in i18n |
| `inertia-form-uses-fetch` | Inertia Form Uses Fetch | medium | advisory | regex | low | react | react-component, form | Yes (medium) | Yes (medium) | Yes (medium) | Detects Inertia page forms using fetch/axios instead of useForm |
| `inertia-internal-link-anchor` | Inertia Internal Link Anchor | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects internal anchors that should use Inertia Link |
| `inertia-page-missing-head` | Inertia Page Missing Head | medium | advisory | regex | low | react | react-component, page | Yes (low) | Yes (medium) | Yes (medium) | Detects Inertia page components that do not render a Head element |
| `jsonld-structured-data-invalid-or-mismatched` | JSON-LD Structured Data Invalid or Mismatched | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects invalid or weakly-formed JSON-LD structured data blocks |
| `large-react-component` | Large React Component Detection | medium | advisory | ast | medium | react | react-component | No (-) | No (-) | Yes (medium) | Detects oversized React components |
| `meta-description-missing-or-generic` | Meta Description Missing or Generic | low | advisory | regex | low | react | react-component | Yes (low) | Yes (low) | Yes (medium) | Detects missing or generic page-level meta descriptions on indexable/public surfaces |
| `missing-form-request` | Missing FormRequest | medium | defect | ast | medium | laravel | controller | Yes (medium) | Yes (medium) | Yes (medium) | Suggests FormRequest for inline validation |
| `missing-usecallback-for-event-handlers` | Missing UseCallback for Event Handlers | medium | advisory | regex | low | react | react-component, hook | No (-) | No (-) | Yes (medium) | Detects event handlers passed as props without useCallback memoization |
| `missing-usememo-for-expensive-calc` | Missing UseMemo for Expensive Calculations | medium | advisory | regex | low | react | react-component, hook | No (-) | No (-) | Yes (medium) | Detects expensive calculations in render without useMemo memoization |
| `multiple-exported-react-components` | Multiple Exported React Components | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects files exporting multiple top-level React components |
| `no-inline-services` | No Inline Service/Helper Definitions | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects helper functions or service classes defined inside UI component files |
| `no-inline-types` | No Inline Type/Interface Definitions | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects TypeScript types/interfaces defined inside UI component files |
| `no-log-debug-in-app` | Avoid Log::debug in app code | low | advisory | regex | low | laravel | global | Yes (low) | Yes (low) | Yes (low) | Detects Log::debug(...) calls in application code |
| `react-parent-child-spacing-overlap` | Parent/Child Spacing Overlap | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects overlapping spacing utilities between direct JSX parent-child nodes |
| `react-timer-cleanup-required` | Timer Cleanup Required | medium | risk | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Detects timer APIs in useEffect without proper cleanup |
| `robots-directive-risk` | Robots Directive Risk | medium | advisory | regex | low | react | react-component, page | Yes (medium) | Yes (medium) | Yes (high) | Detects risky robots directives on likely public/indexable pages |
| `route-shell-missing-error-boundary` | Route Shell Missing Error Boundary | low | risk | regex | low | react | react-component, page, layout | Yes (low) | Yes (low) | Yes (low) | Detects route/page shells with async data flow but no error boundary |
| `stale-closure-in-timer` | Stale Closure In Timer Callback | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects timer callbacks capturing stale state in empty-deps effects |
| `tailwind-arbitrary-layout-size` | Tailwind Arbitrary Layout Size | low | advisory | regex | low | react | react-component, layout | No (-) | No (-) | Yes (low) | Detects rigid arbitrary width/height Tailwind values |
| `tailwind-arbitrary-radius-shadow` | Tailwind Arbitrary Radius/Shadow | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects arbitrary rounded/shadow values where scale tokens are preferred |
| `tailwind-arbitrary-spacing` | Tailwind Arbitrary Spacing | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects p/m/gap/space arbitrary spacing values |
| `tailwind-arbitrary-text-size` | Tailwind Arbitrary Text Size | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects text-[..px] arbitrary sizing instead of Tailwind text scale |
| `tailwind-arbitrary-value-overuse` | Tailwind Arbitrary Value Overuse | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects class strings with excessive arbitrary Tailwind values |
| `typescript-type-check` | TypeScript Type Check | high | advisory | process | high | react | react-component | No (-) | No (-) | Yes (high) | Detects TypeScript type errors and syntax issues using tsc |
| `unsafe-async-handler-without-guard` | Unsafe Async Handler Without Guard | medium | risk | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects async event handlers that can be re-triggered without pending/processing guard |
| `usecallback-ast` | UseCallback Required (AST) | medium | advisory | ast | medium | react | react-component, hook | No (-) | Yes (medium) | Yes (medium) | AST-based detection of inline handlers needing memoization |
| `usecallback-overuse` | useCallback Overuse | low | advisory | ast | medium | react | react-component, hook | No (-) | No (-) | Yes (low) | Detects useCallback wrappers with little stability/perf benefit |
| `usememo-ast` | UseMemo Required (AST) | medium | advisory | ast | medium | react | react-component, hook | No (-) | Yes (medium) | Yes (medium) | AST-based detection of expensive calculations needing memoization |
| `usememo-overuse` | useMemo Overuse | low | advisory | ast | medium | react | react-component, hook | No (-) | No (-) | Yes (low) | Detects useMemo around trivial computations without measurable benefit |

### Data Access (10)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `controller-index-filter-duplication` | Controller Index Filter Duplication | medium | advisory | ast | medium | laravel | controller, migration | Yes (low) | Yes (medium) | Yes (medium) | Detects repeated inline index filter extraction in controllers |
| `controller-query-direct` | Controller Should Not Query DB Directly | high | advisory | ast | medium | laravel | controller | Yes (high) | Yes (high) | Yes (high) | Detects direct Eloquent/DB query usage inside controllers |
| `destructive-migration-without-safety-guard` | Destructive Migration Without Safety Guard | high | risk | ast | medium | laravel | migration | No (-) | No (-) | Yes (high) | Detects destructive migration operations without schema/table existence checks |
| `massive-model` | Massive Model Detection | medium | advisory | ast | medium | laravel | model | Yes (medium) | Yes (medium) | Yes (medium) | Detects models that contain too much logic (consider service/repository extraction) |
| `missing-foreign-key-in-migration` | Missing Foreign Key In Migration | medium | advisory | ast | medium | laravel | migration | No (-) | Yes (medium) | Yes (medium) | Detects migration reference columns that are added without a foreign key definition |
| `missing-null-guard-after-relation-load` | Missing Null Guard After Relation Load | medium | defect | regex | low | laravel | service, controller, job | No (-) | Yes (medium) | Yes (medium) | Detects relation loads followed by relation usage without a null guard |
| `model-cross-model-query` | Cross-Model Query Inside Model | low | advisory | ast | medium | laravel | model | Yes (low) | Yes (low) | Yes (low) | Detects direct queries to another model from within model methods |
| `page-indexability-conflict` | Page Indexability Conflict | high | risk | regex | low | react | react-component, page | Yes (high) | Yes (high) | Yes (high) | Detects conflicting indexability metadata signals on the same page |
| `repository-suggestion` | Repository Pattern Suggestion | medium | advisory | ast | medium | laravel | service | No (-) | Yes (low) | Yes (medium) | Suggests extracting database queries to Repository classes |
| `transaction-required-for-multi-write` | Transaction Required For Multi Write | high | advisory | ast | medium | laravel | service | Yes (high) | Yes (high) | Yes (high) | Detects methods with multiple writes that are not wrapped in a DB transaction |

### Dead Code (2)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `unused-private-method` | Unused Private Method | low | advisory | ast | medium | php | php-class, php-function | Yes (low) | Yes (low) | Yes (low) | Detects private methods that appear to be unused within their class |
| `unused-service-class` | Unused Service Class | low | advisory | ast | medium | laravel | service | Yes (low) | Yes (low) | Yes (low) | Detects service classes in app/Services that appear to be unused |

### DevOps (7)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `app-debug-not-false-in-production` | App Debug Not False In Production | high | risk | cross-file | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects debug defaults that enable Laravel debug mode in production-facing configuration |
| `app-env-not-set-to-production` | App Env Not Set To Production | medium | risk | cross-file | low | laravel | global | No (-) | Yes (medium) | Yes (medium) | Detects environment defaults that encourage production servers to run in local/development mode |
| `env-committed-to-git` | Env Committed To Git Risk | critical | risk | cross-file | low | laravel | global | Yes (critical) | Yes (critical) | Yes (critical) | Detects projects whose .gitignore does not explicitly ignore the real .env file |
| `env-example-missing-or-out-of-sync` | Env Example Missing Or Out Of Sync | high | risk | cross-file | medium | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects missing .env.example files or required keys absent from the example environment |
| `missing-queue-worker-supervision` | Missing Queue Worker Supervision | high | risk | cross-file | medium | laravel | global | No (-) | Yes (high) | Yes (high) | Detects Laravel queue usage without Horizon or supervisor worker restart configuration |
| `no-logging-strategy-configured` | No Logging Strategy Configured | low | advisory | cross-file | low | laravel | global | No (-) | Yes (low) | Yes (low) | Detects Laravel logging defaults that rely only on local file channels |
| `storage-paths-not-in-gitignore` | Storage Paths Not In Gitignore | high | risk | cross-file | low | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects generated Laravel storage/cache paths missing from .gitignore |

### File Security (7)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `archive-upload-zip-slip-risk` | Archive Upload Zip Slip Risk | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects ZipArchive extraction without traversal-safe entry validation |
| `insecure-file-download-response` | Insecure File Download Response | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects file download responses built from untrusted path input without guards |
| `unsafe-file-include-variable` | Unsafe File Include Variable | critical | risk | regex | low | php | php-class, php-function | No (-) | Yes (critical) | Yes (critical) | Detects include/require calls that use unsanitized variable paths |
| `unsafe-file-upload` | Unsafe File Upload | high | risk | ast | medium | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects file upload handling without validation |
| `upload-mime-extension-mismatch` | Upload MIME/Extension Mismatch Risk | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects upload flows that trust client extensions without MIME hardening |
| `upload-size-limit-missing` | Upload Size Limit Missing | medium | risk | regex | low | laravel | global | No (-) | Yes (medium) | Yes (high) | Detects upload validation without explicit max file size |
| `zip-bomb-risk` | Zip Bomb Risk | high | risk | ast | medium | laravel | global | No (-) | Yes (high) | Yes (high) | Detects archive extraction flows without decompression/entry safety checks |

### Injection Risks (12)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `blade-xss-risk` | Possible XSS risk in Blade raw output | medium | risk | ast | medium | laravel | blade | Yes (medium) | Yes (medium) | Yes (medium) | Detects `{!! ... !!}` usage that appears to output request-derived content |
| `command-injection-risk` | Command injection risk | high | risk | ast | medium | php | php-class, php-function | Yes (high) | Yes (high) | Yes (high) | Detects shell execution functions called with non-literal arguments |
| `dangerous-html-sink-without-sanitizer` | Dangerous HTML Sink Without Sanitizer | high | risk | ast | medium | react | react-component | No (-) | Yes (high) | Yes (high) | Detects dangerouslySetInnerHTML usage without sanitizer guard |
| `eloquent-raw-where-string` | Eloquent Raw Where String | high | risk | regex | low | laravel | controller, service, model | No (-) | Yes (high) | Yes (high) | Detects Eloquent where() calls that build SQL predicates inside the first string argument |
| `insecure-deserialization` | Insecure Deserialization | high | risk | regex | low | laravel | global | No (-) | No (-) | Yes (high) | Detects unsafe use of unserialize() on potentially untrusted input |
| `no-dangerously-set-inner-html` | No Dangerously Set Inner HTML | critical | risk | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects usage of dangerouslySetInnerHTML |
| `pcre-redos-risk` | PCRE ReDoS Risk | high | risk | regex | low | php | php-class | No (-) | Yes (high) | Yes (high) | Detects nested quantifier regex patterns in preg_match/preg_replace usage |
| `raw-sql` | Raw SQL Usage | high | risk | ast | medium | php | php-class, php-function | Yes (high) | Yes (high) | Yes (high) | Detects DB::select/statement/raw usage (prefer query builder with bindings) |
| `sql-injection-risk` | SQL injection risk (raw SQL with variables) | medium | risk | ast | medium | php | php-class, php-function | Yes (high) | Yes (medium) | Yes (medium) | Detects raw SQL built with variables/interpolation/concatenation |
| `unsafe-eval` | Unsafe code execution (eval/assert/preg_replace /e) | high | risk | ast | medium | php | php-class, php-function | Yes (high) | Yes (high) | Yes (high) | Detects eval/assert(string)/preg_replace(/e) which can lead to code execution |
| `unsafe-unserialize` | Unsafe unserialize() usage | high | risk | ast | medium | php | php-class | Yes (high) | Yes (high) | Yes (high) | Detects unserialize() without allowed_classes restriction or on request input |
| `xml-xxe-risk` | Potential XML External Entity Risk | high | risk | ast | medium | laravel | global | No (-) | Yes (high) | Yes (high) | Detects XML parsing calls without XXE hardening signals |

### PHP Quality (17)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `array-unpacking-in-loop` | Array Unpacking In Loop | high | advisory | regex | low | php | php-class, php-function | No (-) | Yes (high) | Yes (high) | Detects array_merge or array spread rebuilds inside loops |
| `bulk-insert-missing` | Bulk Insert Missing | high | advisory | regex | low | php | php-class, controller, service | No (-) | Yes (high) | Yes (high) | Detects insert/create/save calls inside loops that should likely be batched |
| `catch-too-broad` | Catch Too Broad | medium | risk | regex | low | php | php-function | No (-) | Yes (medium) | Yes (medium) | Detects broad catch blocks that return generic fallbacks without logging useful exception detail |
| `date-format-missing-cast` | Date Format Missing Cast | low | advisory | regex | low | laravel | model, blade | No (-) | Yes (low) | Yes (low) | Detects manual date parsing/formatting where model datetime casts are preferred |
| `dry-violation` | DRY Violation Detection | medium | advisory | ast | medium | php | php-class | Yes (low) | Yes (medium) | Yes (medium) | Detects duplicate code blocks |
| `exception-swallowing` | Exception Swallowing | high | advisory | regex | low | php | php-class, php-function | No (-) | Yes (high) | Yes (high) | Detects catch blocks that are empty or contain only comments |
| `god-class` | God Class Detection | high | advisory | ast | medium | php | php-class | Yes (medium) | Yes (high) | Yes (critical) | Flags classes that are too large and likely violate SRP/cohesion |
| `hardcoded-magic-strings` | Hardcoded Magic Strings | low | advisory | regex | low | laravel | php-class, model, service | No (-) | No (-) | Yes (low) | Detects repeated status/type/role strings that should be constants or enums |
| `high-complexity` | High Complexity Detection | medium | risk | ast | medium | php | php-class | Yes (medium) | Yes (high) | Yes (high) | Flags methods with high cyclomatic complexity |
| `laravel-naming-conventions` | Laravel Naming Conventions | low | advisory | regex | low | laravel | controller, model | No (-) | No (-) | Yes (low) | Detects selected Laravel class and relationship naming convention violations |
| `missing-return-type-nullable` | Missing Return Type Nullable | high | defect | regex | low | php | php-function | No (-) | No (-) | Yes (high) | Detects PHP functions that declare a non-nullable return type but return null on some path |
| `missing-strict-types` | Missing strict_types Declaration | medium | advisory | regex | low | php | php-class, php-function | No (-) | No (-) | Yes (medium) | Detects PHP class/function files missing declare(strict_types=1) near the top |
| `missing-type-declarations` | Missing Type Declarations | medium | advisory | regex | low | php | php-class, php-function | No (-) | No (-) | Yes (medium) | Detects functions or methods missing parameter or return type declarations |
| `mutable-global-state` | Mutable Global State | high | advisory | regex | low | php | php-class, php-function | No (-) | Yes (high) | Yes (high) | Detects use of PHP global variables and mutable static properties |
| `prefer-imports` | Prefer imports instead of fully-qualified class names | low | advisory | ast | medium | php | php-class | Yes (low) | Yes (low) | Yes (low) | Suggests importing project classes with `use` instead of referencing FQCNs directly. |
| `string-concat-in-loop` | String Concatenation In Loop | high | advisory | regex | low | php | php-function | No (-) | Yes (high) | Yes (high) | Detects .= string concatenation inside loops |
| `too-many-dependencies` | Too Many Constructor Dependencies | medium | advisory | ast | medium | php | php-class | Yes (medium) | Yes (medium) | Yes (medium) | Detects constructors with too many dependencies (likely SRP violation) |

### Performance (18)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `asset-versioning-check` | Asset Versioning Check | low | advisory | ast | medium | laravel | global | No (-) | No (-) | Yes (low) | Verifies that Inertia asset versioning is properly configured |
| `blade-queries` | Blade Queries Detection | high | advisory | ast | medium | laravel | blade | Yes (medium) | Yes (medium) | Yes (medium) | Detects database queries in Blade templates |
| `cache-stampede-risk` | Cache Stampede Risk | high | advisory | regex | low | laravel | controller, service | No (-) | Yes (high) | Yes (high) | Detects Cache::remember calls without nearby lock protection |
| `chunk-missing-for-large-datasets` | Chunk Missing For Large Datasets | high | advisory | regex | low | laravel | controller, service, job, php-function | No (-) | Yes (high) | Yes (high) | Detects Model::all or get results iterated without chunk/cursor |
| `column-selection-suggestion` | Column Selection Suggestion | low | advisory | ast | medium | laravel | global | No (-) | No (-) | Yes (low) | Suggests explicit column selection for better query performance |
| `config-in-loop` | config() Call Inside Loop | medium | advisory | ast | medium | php | php-class | Yes (medium) | Yes (medium) | Yes (medium) | Detects config() calls inside loops (cache value outside the loop) |
| `eager-loading` | Eager Loading Suggestion | medium | advisory | ast | medium | laravel | global | Yes (medium) | Yes (medium) | Yes (medium) | Suggests eager loading to prevent N+1 query problems |
| `inertia-shared-props-eager-query` | Inertia Shared Props Eager Query | medium | advisory | regex | low | laravel | provider | Yes (medium) | Yes (medium) | Yes (medium) | Detects eager database queries inside global Inertia shared props |
| `inertia-shared-props-payload-budget` | Inertia Shared Props Payload Budget | medium | advisory | regex | low | laravel | provider | No (-) | Yes (medium) | Yes (medium) | Detects heavy eager payloads inside global Inertia shared props |
| `listener-shouldqueue-missing-for-io-bound-handler` | Listener ShouldQueue Missing For IO-Bound Handler | medium | advisory | ast | medium | laravel | job | No (-) | Yes (medium) | Yes (medium) | Detects listeners that perform IO-heavy work synchronously |
| `missing-index-on-lookup-columns` | Missing Index On Lookup Columns | medium | advisory | ast | medium | laravel | migration | No (-) | Yes (medium) | Yes (medium) | Detects migration lookup columns that are added without an index or unique constraint |
| `missing-pagination` | Missing Pagination | medium | advisory | cross-file | high | laravel | global | No (-) | No (-) | Yes (medium) | Detects API endpoints returning all records without pagination or limit |
| `n-plus-one-risk` | N+1 Risk Detection | high | advisory | ast | medium | laravel | global | Yes (medium) | Yes (high) | Yes (high) | Detects likely lazy-loaded relation access in loops (N+1 risk) |
| `no-pagination-on-relationship` | No Pagination On Relationship | medium | advisory | ast | medium | laravel | model, service, controller | No (-) | No (-) | Yes (medium) | Detects potentially unbounded Eloquent relationship loads without paginate, limit, or take |
| `notification-shouldqueue-missing` | Notification ShouldQueue Missing | medium | advisory | ast | medium | laravel | job | No (-) | Yes (medium) | Yes (medium) | Detects notifications that deliver mail/database/broadcast payloads without implementing ShouldQueue |
| `null-filtering-suggestion` | Null Filtering Suggestion | low | advisory | regex | low | laravel | global | No (-) | No (-) | Yes (low) | Suggests filtering null values from response arrays |
| `realtime-inmemory-state-scalability` | Realtime In-Memory State Scalability | low | advisory | cross-file | medium | laravel | global | No (-) | Yes (low) | Yes (medium) | Detects standalone realtime runtimes that keep active room/player state only in process memory |
| `synchronous-mail-in-request` | Synchronous Mail In Request | high | advisory | regex | low | laravel | controller, service | No (-) | Yes (high) | Yes (high) | Detects synchronous Mail::send or Mail::to()->send calls in request path code |

### Queue & Jobs (3)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `queue-job-missing-failure-handling` | Queue Job Missing Failure Handling | medium | risk | regex | low | laravel | job | No (-) | Yes (medium) | Yes (medium) | Detects queued jobs with side effects but no visible retry/backoff/failed handling |
| `react-event-listener-cleanup-required` | Event Listener Cleanup Required | medium | risk | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Detects addEventListener in useEffect without removeEventListener cleanup |
| `stale-closure-in-listener` | Stale Closure In Event Listener | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects addEventListener callbacks capturing stale state in empty-deps effects |

### React Accessibility (41)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `accessible-authentication` | Accessible Authentication | medium | defect | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects authentication flows that may be difficult for users with cognitive impairments |
| `animation-no-pause-control` | Animation No Pause Control | medium | defect | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Detects animation utilities without reduced-motion variants or pause controls |
| `apg-accordion-disclosure-contract` | APG Accordion/Disclosure Contract | medium | defect | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects disclosure widgets missing APG button/expanded/controls signals |
| `apg-combobox-contract` | APG Combobox Contract | high | defect | ast | medium | react | react-component | Yes (medium) | Yes (high) | Yes (high) | Detects combobox widgets missing APG expanded/controls/active-option/keyboard signals |
| `apg-menu-button-contract` | APG Menu Button Contract | high | defect | ast | medium | react | react-component | Yes (medium) | Yes (high) | Yes (high) | Detects menu button widgets missing APG trigger/menu/keyboard signals |
| `apg-tabs-keyboard-contract` | APG Tabs Keyboard Contract | high | defect | ast | medium | react | react-component | Yes (medium) | Yes (high) | Yes (high) | Detects custom tab widgets missing APG role/state/keyboard signals |
| `autocomplete-missing` | Autocomplete Attribute Missing | low | advisory | regex | low | react | react-component, form | No (-) | No (-) | Yes (low) | Detects form fields that could benefit from autocomplete attribute |
| `autoplay-media` | Autoplay Media | high | defect | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects auto-playing audio/video without user controls |
| `button-text-vague` | Button Text Vague | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects buttons with vague text that lacks context |
| `color-contrast-ratio` | Color Contrast Ratio | high | defect | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects potential color contrast issues in text elements |
| `css-color-only-state-indicator` | CSS Color-Only State Indicator | medium | defect | regex | low | react | react-component | Yes (low) | Yes (medium) | Yes (medium) | Detects likely state/error indicators conveyed only by color |
| `css-focus-outline-without-replacement` | CSS Focus Outline Without Replacement | high | defect | regex | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects focus styles that remove outline without visible replacement |
| `css-hover-only-interaction` | CSS Hover-Only Interaction | medium | defect | regex | low | react | react-component | Yes (low) | Yes (medium) | Yes (medium) | Detects hover interaction selectors without corresponding focus styles |
| `dialog-focus-restore-missing` | Dialog Focus Restore Missing | high | defect | ast | medium | react | react-component | Yes (medium) | Yes (high) | Yes (high) | Detects dialog/overlay flows missing focus restoration signals on close |
| `error-message-missing` | Error Message Missing | medium | defect | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects form fields with validation but no error message association |
| `focus-indicator-missing` | Focus Indicator Missing | high | defect | regex | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects explicit focus outline removal without visible replacement |
| `focus-lost-on-route-change` | Focus Lost On Route Change | medium | defect | regex | low | react | page, layout | No (-) | Yes (medium) | Yes (medium) | Detects SPA route navigation without visible focus restoration logic |
| `focus-not-obscured` | Focus Not Obscured | medium | defect | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects fixed/sticky elements that may obscure focused content |
| `form-label-association` | Form Label Association | high | defect | regex | low | react | react-component, form | Yes (high) | Yes (high) | Yes (high) | Detects labels that are not associated with a form control |
| `heading-order` | Heading Order | medium | defect | regex | low | react | react-component, page | No (-) | No (-) | Yes (medium) | Detects skipped heading levels that break document outline |
| `img-alt-missing` | Image Alt Text Missing | high | defect | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects <img> tags missing descriptive alt text |
| `interactive-accessible-name-required` | Interactive Accessible Name Required | high | defect | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects interactive controls that lack a programmatic accessible name |
| `interactive-element-a11y` | Interactive Element Accessibility | high | defect | regex | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects non-semantic clickable elements missing role/keyboard contracts |
| `jsx-aria-attribute-format` | JSX ARIA Attribute Format | medium | defect | ast | medium | react | react-component, form | Yes (medium) | Yes (medium) | Yes (medium) | Detects malformed ARIA attribute names in JSX |
| `language-attribute-missing` | Language Attribute Missing | high | defect | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects HTML documents without lang attribute |
| `link-text-vague` | Link Text Vague | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects links with vague text that lacks context |
| `long-page-no-toc` | Long Page Without TOC | low | advisory | regex | low | react | react-component, page | No (-) | No (-) | Yes (low) | Detects long pages without table of contents or navigation landmarks |
| `missing-fieldset-legend` | Missing Fieldset Legend | high | defect | regex | low | react | form, react-component | No (-) | Yes (high) | Yes (high) | Detects radio/checkbox groups without fieldset and legend |
| `modal-trap-focus` | Modal Focus Trap Missing | high | defect | regex | low | react | react-component | Yes (medium) | Yes (high) | Yes (high) | Detects dialog/modal widgets missing keyboard focus management contracts |
| `outside-click-without-keyboard-fallback` | Outside Click Without Keyboard Fallback | high | defect | ast | medium | react | react-component | Yes (medium) | Yes (high) | Yes (high) | Detects outside-click close logic without keyboard fallback |
| `page-title-missing` | Page Title Missing | high | defect | regex | low | react | react-component, page | No (-) | No (-) | Yes (high) | Detects pages without descriptive title element |
| `placeholder-as-label` | Placeholder Used as Label | medium | defect | regex | low | react | react-component, form | No (-) | No (-) | Yes (medium) | Detects form fields with placeholder but no associated label |
| `redundant-entry` | Redundant Entry | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects forms that may ask users to re-enter previously provided information |
| `semantic-wrapper-breakage` | Semantic Wrapper Breakage | medium | defect | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects JSX wrappers that break list/table/description-list semantics |
| `skip-link-missing` | Skip Link Missing | high | defect | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (high) | Detects shell/layout files without a valid skip-to-content link |
| `status-message-announcement` | Status Message Announcement | medium | defect | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects status messages that may not be announced to screen readers |
| `table-missing-headers` | Table Missing Headers | high | defect | regex | low | react | react-component, page | No (-) | Yes (high) | Yes (high) | Detects tables whose first row uses td cells instead of th headers |
| `tailwind-appearance-none-risk` | Tailwind Appearance None Risk | medium | defect | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Flags appearance-none on form controls without compensating focus/usability cues |
| `tailwind-motion-reduce-missing` | Tailwind Motion Reduce Missing | medium | defect | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects animation-heavy class strings without motion-safe/motion-reduce variants |
| `touch-target-size` | Touch Target Size | medium | defect | regex | low | react | react-component | Yes (low) | Yes (medium) | Yes (medium) | Detects interactive controls with explicit size below 44x44px |
| `video-missing-captions` | Video Missing Captions | medium | defect | regex | low | react | react-component, page | No (-) | Yes (medium) | Yes (medium) | Detects video elements without caption tracks |

### React Performance (10)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `context-oversized-provider` | Context Provider Oversized Value | medium | advisory | ast | medium | react | react-component | Yes (low) | Yes (medium) | Yes (medium) | Detects broad provider values that likely trigger unnecessary fan-out rerenders |
| `context-provider-inline-value` | Context Provider Inline Value | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects inline provider values that trigger unnecessary rerenders |
| `inertia-reload-without-only` | Inertia Reload Without only/except | medium | advisory | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Detects unscoped Inertia reload calls that can fetch unnecessary payload |
| `inline-prop-object-array` | Inline Object/Array Prop Creation | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Inline objects or arrays passed as props create new references on every render. |
| `input-debounce-missing` | Input Debounce Missing | high | advisory | regex | low | react | react-component, form | No (-) | Yes (high) | Yes (high) | Detects input search/change handlers that call fetch/search without debounce |
| `missing-list-virtualization` | Missing List Virtualization | high | advisory | regex | low | react | react-component, page | No (-) | Yes (high) | Yes (high) | Detects large-looking list renders without virtualization imports |
| `missing-route-code-splitting` | Missing Route Code Splitting | high | advisory | regex | low | react | page, route | No (-) | Yes (high) | Yes (high) | Detects router files with many static page imports instead of React.lazy |
| `no-nested-components` | No Nested Components | high | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects components defined inside other components (causes remounts) |
| `query-key-instability` | Unstable Query Key | medium | risk | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects inline objects/functions in query keys that break cache stability |
| `unthrottled-scroll-resize-handler` | Unthrottled Scroll/Resize Handler | high | advisory | regex | low | react | react-component, hook | No (-) | Yes (high) | Yes (high) | Detects scroll or resize listeners without throttle/debounce protection |

### React Stability (33)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `avoid-props-to-state-copy` | Avoid Props-to-State Copy | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects direct props mirroring into useState initializers |
| `derived-state-in-effect` | Derived State Synced Through useEffect | medium | advisory | regex | low | react | react-component | Yes (low) | Yes (medium) | Yes (medium) | Detects state that is derived in useEffect instead of render/useMemo |
| `duplicate-key-source` | Potential Duplicate Key Source | medium | advisory | cross-file | high | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects list keys derived from weak/non-unique fields |
| `effect-event-relay-smell` | Effect Event Relay Smell | medium | advisory | regex | low | react | react-component | Yes (low) | Yes (medium) | Yes (medium) | Detects action relays implemented through flag state + useEffect |
| `form-double-submit` | Form Double Submit | high | advisory | regex | low | react | form, react-component | No (-) | Yes (high) | Yes (high) | Detects submit buttons without disabled state during submission |
| `hooks-in-conditional-or-loop` | Hooks In Conditional Or Loop | high | advisory | regex | low | react | react-component, hook | Yes (high) | Yes (high) | Yes (high) | Detects React hooks inside conditionals, loops, or callback loops |
| `inertia-page-missing-error-boundary` | Inertia Page Missing Error Boundary | medium | advisory | regex | low | react | page, react-component | No (-) | Yes (medium) | Yes (medium) | Detects Inertia page components that use page data without an ErrorBoundary wrapper |
| `large-custom-hook` | Large Custom Hook | medium | advisory | regex | low | react | react-component, hook | Yes (low) | Yes (medium) | Yes (medium) | Detects oversized custom hooks that likely need decomposition |
| `lazy-without-suspense` | Lazy Component Without Suspense Boundary | high | advisory | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects lazy component usage without a Suspense boundary |
| `loose-default-object-prop` | Loose Default Object Prop | medium | advisory | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Defaulting props to an empty object can hide missing data and lead to runtime bugs. |
| `missing-empty-state` | Missing Empty State | low | advisory | ast | medium | react | react-component | Yes (low) | Yes (low) | Yes (low) | Detects list-heavy page surfaces without explicit empty-state handling |
| `missing-error-boundary-general` | Missing Error Boundary General | high | advisory | regex | low | react | react-component, page | No (-) | Yes (high) | Yes (high) | Detects large data-heavy feature component trees without ErrorBoundary wrapping |
| `missing-key-on-list-render` | Missing Key On List Render | high | advisory | regex | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects list renders that return JSX without a key prop |
| `missing-loading-state` | Missing Loading State | low | advisory | ast | medium | react | react-component | Yes (low) | Yes (low) | Yes (low) | Detects async page surfaces without explicit loading UI |
| `missing-props-type` | Missing Props Type | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects React components without TypeScript props type definitions |
| `no-direct-useeffect` | Direct useEffect Is Disallowed | medium | advisory | ast | medium | react | react-component, hook | No (-) | No (-) | Yes (high) | Flags direct useEffect usage in strict React policy projects |
| `no-inline-hooks` | No Inline Hook Definitions | medium | advisory | regex | low | react | react-component, hook | No (-) | No (-) | Yes (medium) | Enforces extraction of custom hooks to separate files |
| `props-state-sync-effect-smell` | Props-State Sync Effect Smell | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects useEffect blocks that mirror props into state |
| `react-no-array-index-key` | Avoid Array Index as React Key | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects unstable React key props that use array index variables |
| `react-no-props-mutation` | Props Object Mutation | high | defect | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects direct mutation of React props |
| `react-no-random-key` | Random Value Used As React Key | medium | risk | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Detects list keys generated from random/time-based values during render |
| `react-no-state-mutation` | State Variable Mutation | high | defect | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects direct mutation of React state variables |
| `react-side-effects-in-render` | Side Effects During Render | high | defect | ast | medium | react | react-component | No (-) | Yes (high) | Yes (high) | Detects side-effect calls executed directly during React render |
| `react-useeffect-deps` | Missing useEffect Dependency Array | medium | advisory | regex | low | react | react-component, hook | Yes (medium) | Yes (medium) | Yes (medium) | Detects useEffect calls without a dependency array |
| `react-useeffect-fetch-without-abort` | UseEffect Fetch Without Abort | medium | advisory | regex | low | react | react-component, hook | Yes (medium) | Yes (medium) | Yes (medium) | Detects fetch in useEffect without abort or cleanup handling |
| `ref-access-during-render` | Ref Access During Render | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects `.current` reads directly inside JSX render expressions |
| `ref-used-as-reactive-state` | Ref Used as Reactive State | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects refs used as primary reactive state instead of useState |
| `state-update-in-render` | State Update During Render | high | defect | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects direct setState-like calls in React render flow |
| `suspense-fallback-missing` | Suspense Fallback Missing | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects Suspense boundaries that do not define fallback UI |
| `unhandled-promise-in-handler` | Unhandled Promise In Handler | high | advisory | regex | low | react | react-component, form | No (-) | Yes (high) | Yes (high) | Detects async event handlers with await but no local error handling |
| `unstable-react-key` | Unstable React Key | high | advisory | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | React keys must be stable and unique. Unstable keys can cause incorrect UI updates and bugs. |
| `useeffect-cleanup-missing` | UseEffect Cleanup Missing | medium | advisory | regex | low | react | react-component, hook | No (-) | No (-) | Yes (medium) | Detects useEffect with side effects that need cleanup but don't have it |
| `useless-suspense-boundary` | Useless Suspense Boundary | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects Suspense boundaries that wrap only synchronous components |

### Security Hardening (26)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `api-key-in-client-bundle` | API Key In Client Bundle | critical | risk | regex | low | react | react-component | No (-) | Yes (critical) | Yes (critical) | Detects likely secret/API key literals embedded in client-side source files |
| `client-open-redirect-unvalidated-navigation` | Client Open Redirect Unvalidated Navigation | high | risk | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects client-side navigation to unvalidated user-controlled targets |
| `composer-dependency-below-secure-version` | Composer Dependency Below Secure Version | high | risk | regex | low | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects Composer dependencies pinned below curated secure minimum versions |
| `debug-exposure-risk` | Debug Exposure Risk | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects debug settings that can expose stack traces, secrets, or internal internals |
| `host-header-poisoning-risk` | Host Header Poisoning Risk | high | risk | ast | medium | laravel | global | No (-) | Yes (high) | Yes (high) | Detects host header-derived URL/redirect construction without trusted host guard |
| `insecure-postmessage-origin-wildcard` | Insecure postMessage Origin Wildcard | high | risk | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects postMessage calls with wildcard target origin |
| `insecure-random-for-security` | Insecure Random for Security | medium | risk | regex | low | laravel | global | No (-) | No (-) | Yes (high) | Detects use of rand() or mt_rand() in security-sensitive contexts |
| `job-http-call-missing-timeout` | Job HTTP Call Missing Timeout | medium | risk | regex | low | laravel | job | Yes (medium) | Yes (medium) | Yes (medium) | Detects queued jobs with outbound HTTP calls and no timeout controls |
| `job-missing-idempotency-guard` | Job Missing Idempotency Guard | medium | risk | regex | low | laravel | job | Yes (medium) | Yes (medium) | Yes (medium) | Detects queued jobs with side effects and no obvious idempotency guard |
| `livewire-public-prop-mass-assignment` | Livewire Public Property Mass Assignment Risk | high | risk | regex | low | laravel | model | No (-) | Yes (high) | Yes (high) | Detects mutable public Livewire properties without #[Locked] attribute |
| `mass-assignment-risk` | Mass Assignment Risk | high | risk | ast | medium | laravel | model | Yes (high) | Yes (high) | Yes (high) | Detects Model::create/update/fill with $request->all() (mass assignment risk) |
| `missing-hsts-header` | Missing HSTS Header | high | risk | regex | low | laravel | config | No (-) | Yes (high) | Yes (high) | Detects missing Strict-Transport-Security hardening in middleware/header configuration |
| `missing-https-enforcement` | Missing HTTPS Enforcement | medium | risk | regex | low | laravel | global | No (-) | No (-) | Yes (high) | Detects missing force HTTPS configuration for production |
| `missing-rate-limiting` | Missing Rate Limiting | high | risk | cross-file | high | laravel | global | No (-) | Yes (high) | Yes (high) | Detects sensitive endpoints missing explicit throttle/rate-limit controls |
| `npm-dependency-below-secure-version` | NPM Dependency Below Secure Version | high | risk | regex | low | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects npm dependencies pinned below curated secure minimum versions |
| `public-anonymous-mutation-abuse-readiness` | Public Anonymous Mutation Abuse Readiness | medium | advisory | cross-file | low | laravel | route, middleware | No (-) | Yes (medium) | Yes (medium) | Reviews anonymous public game/room mutation endpoints for abuse controls |
| `safe-target-blank` | Unsafe target='_blank' | high | risk | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects usage of target='_blank' without rel='noopener noreferrer' |
| `security-headers-baseline-missing` | Security Headers Baseline Missing | medium | risk | cross-file | high | laravel | config | No (-) | Yes (medium) | Yes (medium) | Detects missing baseline security headers handling for web apps |
| `signed-routes-missing-signature-middleware` | Signed Routes Missing Signature Middleware | high | risk | cross-file | high | laravel | middleware, route | Yes (high) | Yes (high) | Yes (high) | Detects routes that likely need signed middleware but do not have it |
| `ssrf-risk-http-client` | Potential SSRF in HTTP Client Call | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects request-derived URLs used in outbound HTTP calls without allowlist validation |
| `unsafe-redirect` | Unsafe Redirect | high | risk | regex | low | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects redirects that appear to trust unvalidated external or user-provided targets |
| `url-validation-protocol-bypass` | URL Validation Protocol Bypass | high | risk | regex | low | laravel | controller, middleware | No (-) | Yes (high) | Yes (high) | Detects redirect/link request fields that rely on Laravel's broad url validation rule |
| `user-model-missing-must-verify-email` | User Model Missing MustVerifyEmail | high | risk | regex | low | laravel | model | Yes (high) | Yes (high) | Yes (high) | Detects User models that do not implement Laravel email verification |
| `webhook-replay-protection-missing` | Webhook Replay Protection Missing | high | risk | cross-file | high | laravel | global | No (-) | Yes (high) | Yes (high) | Detects webhook handlers without visible timestamp/nonce replay protection |
| `webhook-signature-missing` | Webhook Signature Verification Missing | high | risk | cross-file | high | laravel | global | No (-) | Yes (high) | Yes (high) | Detects webhook handlers lacking visible signature verification |
| `webhook-signature-parameter-unused` | Webhook Signature Parameter Unused | critical | risk | regex | low | laravel | service, controller | No (-) | Yes (critical) | Yes (critical) | Detects webhook/payment handlers that accept a signature parameter but never use it |

### Sensitive Data (18)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `authorization-missing-on-sensitive-reads` | Authorization Missing On Sensitive Reads | high | risk | cross-file | high | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects sensitive read flows without visible policy or ability checks |
| `cors-misconfiguration` | CORS Misconfiguration | high | risk | regex | low | laravel | middleware, config | No (-) | No (-) | Yes (high) | Detects overly permissive CORS settings that could expose sensitive data |
| `hardcoded-secrets` | Hardcoded Secrets Detection | high | risk | regex | low | laravel | global | No (-) | No (-) | Yes (critical) | Detects hardcoded passwords, API keys, tokens, and other sensitive values |
| `inertia-shared-props-sensitive-data` | Inertia Shared Props Sensitive Data | high | risk | regex | low | laravel | provider | Yes (high) | Yes (high) | Yes (high) | Detects raw user objects shared globally with Inertia props |
| `insecure-session-cookie-config` | Insecure Session Cookie Config | high | risk | regex | low | laravel | config | Yes (high) | Yes (high) | Yes (high) | Detects Laravel session cookie settings with weak security defaults |
| `missing-csrf-token-verification` | Missing CSRF Token Verification | high | risk | cross-file | high | laravel | middleware | No (-) | No (-) | Yes (high) | Detects routes missing CSRF protection that should have it |
| `model-hidden-sensitive-attributes-missing` | Model Hidden Sensitive Attributes Missing | high | risk | ast | medium | laravel | model | No (-) | Yes (high) | Yes (high) | Detects models that expose sensitive attributes without listing them in $hidden |
| `password-hash-weak-algorithm` | Password Hash Uses Weak Algorithm | critical | risk | regex | low | laravel | global | No (-) | Yes (critical) | Yes (critical) | Detects md5/sha1 usage for password hashing flows |
| `password-reset-token-hardening-missing` | Password Reset Token Hardening Missing | high | risk | cross-file | high | laravel | global | No (-) | Yes (high) | Yes (high) | Detects reset-password handlers missing visible broker/token hardening flow |
| `plain-text-sensitive-config` | Plain-Text Sensitive Config | critical | risk | regex | low | laravel | config | No (-) | Yes (critical) | Yes (critical) | Detects sensitive config keys assigned to literal strings instead of env() lookups |
| `sanctum-token-scope-missing` | Sanctum Token Scope Missing | medium | risk | regex | low | laravel | model | No (-) | Yes (medium) | Yes (high) | Detects Sanctum personal access token creation without explicit abilities |
| `sensitive-data-logging` | Sensitive Data Logging Detection | high | risk | regex | low | laravel | global | No (-) | No (-) | Yes (high) | Detects logging of passwords, tokens, and other sensitive data |
| `sensitive-model-appends-risk` | Sensitive Model Appends Risk | high | risk | ast | medium | laravel | model | No (-) | Yes (high) | Yes (high) | Detects sensitive attributes listed in a model's $appends array |
| `sensitive-response-cache-control-missing` | Sensitive Response Missing Cache-Control | medium | risk | cross-file | high | laravel | global | No (-) | Yes (medium) | Yes (medium) | Detects sensitive/authenticated responses without explicit no-store cache headers |
| `sensitive-routes-missing-verified-middleware` | Sensitive Routes Missing Verified Middleware | high | risk | cross-file | high | laravel | middleware, route | Yes (high) | Yes (high) | Yes (high) | Detects sensitive web routes missing verified middleware |
| `timing-attack-token-comparison` | Timing Attack Token Comparison | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects direct token/hash equality comparisons that should use constant-time `hash_equals` |
| `token-storage-insecure-localstorage` | Token Storage Insecure LocalStorage | high | risk | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects sensitive token persistence in localStorage/sessionStorage |
| `weak-password-policy-validation` | Weak Password Policy Validation | medium | risk | regex | low | laravel | controller | No (-) | Yes (medium) | Yes (high) | Detects weak password validation in authentication/registration flows |

### Testing (5)

| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `low-coverage-files` | Low Coverage Files | medium | advisory | process | high | php | php-class, test | Yes (medium) | Yes (medium) | Yes (medium) | Detects source files with coverage below a minimum threshold (when coverage reports are present) |
| `missing-model-factory` | Missing Model Factory | medium | advisory | cross-file | high | laravel | model | No (-) | Yes (medium) | Yes (medium) | Detects Eloquent models without corresponding Factory classes |
| `test-no-database-trait` | Test Missing Database Isolation Trait | high | advisory | regex | low | laravel | test | No (-) | Yes (high) | Yes (high) | Detects database-touching tests without RefreshDatabase or transaction traits |
| `tests-missing` | Tests Missing | medium | advisory | process | high | php | php-class, test | Yes (medium) | Yes (medium) | Yes (medium) | Detects missing or insufficient automated tests (quality gate) |
| `websocket-handler-integration-tests-missing` | WebSocket Handler Integration Tests Missing | low | advisory | cross-file | medium | laravel | test, php-class | No (-) | Yes (low) | Yes (low) | Detects realtime handlers without handler-level or socket-message integration tests |
