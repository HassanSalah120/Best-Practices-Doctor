# BPD Rules Catalog
Generated from `core.rule_engine.py` (`ALL_RULES`) on 2026-07-03.
This is a single-file catalog of every registered Best Practices Doctor rule, grouped by the rule metadata category/group currently used by the scanner.
## Summary
- Total registered rules: 332
- Startup profile enabled: 127
- Balanced profile enabled: 244
- Strict profile enabled: 313

### Severity Counts
- critical: 9
- high: 143
- medium: 132
- low: 48

### Classification Counts
- defect: 5
- risk: 48
- advisory: 279

### Detection Counts
- ast: 144
- regex: 187
- process: 1

## Categories
### API Design (9)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `api-resource-usage` | Prefer API Resources | medium | advisory | regex | low | laravel | global | Yes (medium) | Yes (medium) | Yes (medium) | Suggests using Laravel API Resources instead of returning raw arrays from API controllers |
| `api-response-inconsistent-shape` | API Response Inconsistent Shape | medium | advisory | ast | medium | laravel | controller | No (-) | No (-) | Yes (medium) | Detects controllers that mix wrapped JSON, raw JSON arrays, and resource response shapes |
| `controller-returning-view-in-api` | Controller Returning View in API | medium | advisory | regex | low | laravel | controller | No (-) | No (-) | Yes (medium) | Detects API routes returning Blade views instead of JSON responses |
| `duplicate-route-definition` | Duplicate Route Definition | high | advisory | ast | high | laravel | route | Yes (high) | Yes (high) | Yes (high) | Detects duplicate route method/URI definitions |
| `heavy-logic-in-routes` | Heavy Logic In Routes | medium | advisory | regex | low | laravel | route | Yes (medium) | Yes (medium) | Yes (medium) | Detects DB queries or service instantiation inside routes files |
| `missing-api-resource` | Missing API Resource | low | advisory | regex | low | laravel | global | No (-) | No (-) | Yes (low) | Detects API endpoints returning raw model data instead of using API Resources |
| `missing-route-code-splitting` | Missing Route Code Splitting | high | advisory | regex | low | react | page, route | No (-) | Yes (high) | Yes (high) | Detects router files with many static page imports instead of React.lazy |
| `no-closure-routes` | Avoid Closure Routes | medium | advisory | regex | low | laravel | route | Yes (medium) | Yes (medium) | Yes (medium) | Detects closure-based route handlers (prefer controllers) |
| `public-api-versioning-missing` | Public API Versioning Missing | medium | advisory | ast | medium | laravel | route | No (-) | Yes (medium) | Yes (medium) | Detects public API routes that do not expose a versioned URI surface |

### Access Control (15)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `authorization-bypass-risk` | Authorization Bypass Risk | high | advisory | ast | high | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects direct model access in mutation actions without authorization checks |
| `client-side-auth-only` | Client-Side Authorization Only | high | advisory | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects UI authorization checks that appear to lack nearby server-side enforcement cues |
| `console-command-missing-tenant-scope` | Console Command Missing Tenant Scope | high | advisory | regex | low | laravel | php-class | No (-) | Yes (high) | Yes (high) | Detects Artisan commands that query tenant data without clinic or tenant scoping |
| `csrf-exception-wildcard-risk` | Broad CSRF Exception Wildcard | high | risk | regex | low | laravel | middleware | No (-) | Yes (high) | Yes (high) | Detects wildcard CSRF exception entries that can disable CSRF protection too broadly |
| `forced-login-without-authorization` | Forced Login Without Authorization | critical | advisory | regex | low | laravel | controller, service | No (-) | Yes (critical) | Yes (critical) | Detects Auth::login calls that are not preceded by an authorization check |
| `high-privilege-action-missing-authorization` | High Privilege Action Missing Authorization | critical | advisory | regex | low | laravel | service, controller | No (-) | Yes (critical) | Yes (critical) | Detects emergency access, impersonation, or role elevation without explicit authorization |
| `idor-risk-missing-ownership-check` | IDOR Risk Missing Ownership Check | high | risk | ast | high | laravel | global | No (-) | Yes (high) | Yes (high) | Detects authenticated resource fetch/update handlers missing ownership or policy checks |
| `missing-auth-on-mutating-api-routes` | Missing Auth On Mutating API Routes | high | advisory | regex | low | laravel | route | Yes (high) | Yes (high) | Yes (high) | Detects mutating API routes that are not protected by auth middleware |
| `missing-content-security-policy` | Missing Content Security Policy | high | advisory | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects CSP omissions in an application-owned security-header boundary |
| `path-traversal-file-access` | Path Traversal File Access | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects request-derived file paths used in file access sinks without normalization |
| `policy-coverage-on-mutations` | Policy Coverage On Mutations | high | advisory | ast | high | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects mutation controller actions without policy/gate/auth protection |
| `postmessage-receiver-origin-not-verified` | postMessage Receiver Missing Origin Verification | high | risk | ast | medium | react | react-component | No (-) | Yes (high) | Yes (high) | Detects message event listeners that handle cross-window messages without origin checks |
| `tenant-access-middleware-missing` | Tenant Access Middleware Missing | high | advisory | ast | high | laravel | middleware | Yes (high) | Yes (high) | Yes (high) | Detects tenant-sensitive routes missing clinic/tenant access middleware |
| `tenant-scope-enforcement` | Tenant Scope Enforcement | high | advisory | ast | high | laravel | model | Yes (high) | Yes (high) | Yes (high) | Detects tenant-sensitive queries that appear to be missing tenant scoping |
| `unsafe-csp-policy` | Unsafe CSP Policy | high | advisory | regex | low | laravel | config | Yes (high) | Yes (high) | Yes (high) | Detects CSP definitions that allow unsafe inline or eval sources |

### Authentication & Session (5)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `inertia-session-flash-on-api` | Inertia Session Flash on API | medium | advisory | regex | medium | laravel | controller | No (-) | No (-) | No (-) | Detects API route controllers mutating session state |
| `password-reset-token-hardening-missing` | Password Reset Token Hardening Missing | high | risk | ast | high | laravel | global | No (-) | Yes (high) | Yes (high) | Detects reset-password handlers missing visible broker/token hardening flow |
| `sanctum-token-scope-missing` | Sanctum Token Scope Missing | medium | risk | regex | low | laravel | model | No (-) | Yes (medium) | Yes (medium) | Detects Sanctum personal access token creation without explicit abilities |
| `session-fixation-regenerate-missing` | Session Regeneration Missing After Login | high | risk | regex | low | laravel | config | No (-) | Yes (high) | Yes (high) | Detects authentication flows missing session regeneration |
| `user-model-missing-must-verify-email` | User Model Missing MustVerifyEmail | high | advisory | regex | low | laravel | model | Yes (high) | Yes (high) | Yes (high) | Detects User models that do not implement Laravel email verification |

### Backend Architecture (34)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `action-class-naming-consistency` | Action Class Naming Consistency | low | advisory | ast | medium | laravel | service | Yes (low) | Yes (low) | Yes (low) | Detects mixed action class naming style under app/Actions |
| `action-class-suggestion` | Action Class Suggestion | low | advisory | ast | high | laravel | service | No (-) | Yes (low) | Yes (low) | Suggests an Action class when a service has a single public method |
| `contract-suggestion` | Contract-Based Development | low | advisory | ast | medium | laravel | service | No (-) | Yes (low) | Yes (low) | Suggests using Interfaces (Contracts) for dependency injection |
| `controller-business-logic` | Business Logic In Controller | high | advisory | ast | medium | laravel | controller | Yes (high) | Yes (high) | Yes (high) | Detects complex/business logic inside controllers |
| `controller-index-filter-duplication` | Controller Index Filter Duplication | medium | advisory | ast | medium | laravel | controller, migration | Yes (medium) | Yes (medium) | Yes (medium) | Detects repeated inline index filter extraction in controllers |
| `controller-inheritance-inconsistency` | Controller Inheritance Inconsistency | low | advisory | ast | low | laravel | controller | No (-) | No (-) | No (-) | Detects mixed controller inheritance patterns (some extend BaseController, others extend Controller) |
| `controller-inline-validation` | Inline Validation In Controller | medium | advisory | ast | medium | laravel | controller | Yes (medium) | Yes (medium) | Yes (medium) | Detects inline validation inside controller actions (prefer FormRequest) |
| `controller-query-direct` | Controller Should Not Query DB Directly | high | advisory | ast | medium | laravel | controller | Yes (high) | Yes (high) | Yes (high) | Detects direct Eloquent/DB query usage inside controllers |
| `custom-exception-suggestion` | Custom Exception Usage | high | advisory | ast | medium | laravel | global | Yes (high) | Yes (high) | Yes (high) | Suggests using specific exceptions instead of generic ones |
| `dto-suggestion` | DTO Suggestion | medium | advisory | ast | medium | laravel | service | No (-) | Yes (medium) | Yes (medium) | Suggests DTOs when large associative arrays are used as data carriers |
| `enum-suggestion` | Enum Suggestion | low | advisory | ast | medium | laravel | global | Yes (low) | Yes (low) | Yes (low) | Suggests creating PHP enums for clustered or repeated string literals |
| `fat-controller` | Fat Controller Detection | high | advisory | ast | medium | laravel | controller | Yes (high) | Yes (high) | Yes (high) | Detects controllers with too many responsibilities |
| `inertia-api-route-returns-inertia` | Inertia API Route Returns Inertia | high | advisory | regex | low | laravel | controller | No (-) | No (-) | No (-) | Detects API route controllers returning Inertia::render() instead of JSON |
| `inertia-conditional-wants-json` | Inertia Conditional wantsJson | high | advisory | regex | low | laravel | controller | No (-) | No (-) | No (-) | Detects methods mixing JSON and Inertia responses via wantsJson() conditional |
| `inertia-form-uses-fetch` | Inertia Form Uses Fetch | medium | advisory | regex | low | react | react-component, form | Yes (medium) | Yes (medium) | Yes (medium) | Detects Inertia page forms using fetch/axios instead of useForm |
| `inertia-get-with-side-effects` | Inertia GET With Side Effects | high | advisory | regex | medium | laravel | controller | No (-) | No (-) | No (-) | Detects GET routes performing database write operations |
| `inertia-hybrid-controller` | Inertia Hybrid Controller | medium | advisory | regex | low | laravel | controller | No (-) | No (-) | No (-) | Detects controllers mixing Inertia::render() and Blade view() calls |
| `inertia-internal-link-anchor` | Inertia Internal Link Anchor | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects internal anchors that should use Inertia Link |
| `inertia-page-missing-error-boundary` | Inertia Page Missing Error Boundary | medium | advisory | regex | low | react | page, react-component | No (-) | Yes (medium) | Yes (medium) | Detects Inertia page components that use page data without an ErrorBoundary wrapper |
| `inertia-page-missing-head` | Inertia Page Missing Head | medium | advisory | regex | low | react | react-component, page | Yes (medium) | Yes (medium) | Yes (medium) | Detects Inertia page components that do not render a Head element |
| `inertia-post-returns-render` | Inertia POST Returns Render | high | advisory | regex | medium | laravel | controller | No (-) | No (-) | No (-) | Detects mutation routes returning Inertia::render() instead of redirecting |
| `inertia-reload-without-only` | Inertia Reload Without only/except | medium | advisory | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Detects unscoped Inertia reload calls that can fetch unnecessary payload |
| `inertia-route-returns-json-response` | Inertia Route Returns JSON Response | high | advisory | regex | low | laravel | controller | No (-) | No (-) | No (-) | Detects web route controllers returning JSON instead of Inertia responses |
| `inertia-shared-props-eager-query` | Inertia Shared Props Eager Query | medium | advisory | regex | low | laravel | provider | Yes (medium) | Yes (medium) | Yes (medium) | Detects eager database queries inside global Inertia shared props |
| `inertia-shared-props-payload-budget` | Inertia Shared Props Payload Budget | medium | advisory | regex | low | laravel | provider | No (-) | Yes (medium) | Yes (medium) | Detects heavy eager payloads inside global Inertia shared props |
| `inertia-shared-props-sensitive-data` | Inertia Shared Props Sensitive Data | high | advisory | regex | low | laravel | provider | Yes (high) | Yes (high) | Yes (high) | Detects raw user objects shared globally with Inertia props |
| `ioc-instead-of-new` | Prefer IoC Over new | medium | advisory | ast | medium | laravel | global | No (-) | Yes (medium) | Yes (medium) | Suggests injecting dependencies instead of instantiating them in controllers |
| `laravel-naming-conventions` | Laravel Naming Conventions | low | advisory | regex | low | laravel | controller, model | No (-) | No (-) | Yes (low) | Detects selected Laravel class and relationship naming convention violations |
| `massive-model` | Massive Model Detection | medium | advisory | ast | medium | laravel | model | Yes (medium) | Yes (medium) | Yes (medium) | Detects models that contain too much logic (consider service/repository extraction) |
| `missing-domain-event` | Missing Domain Event | low | advisory | regex | low | laravel | service, controller | No (-) | Yes (low) | Yes (low) | Suggests dispatching domain events after critical model writes |
| `no-json-encode-in-controllers` | Avoid json_encode/toJson in Controllers | medium | advisory | regex | low | laravel | controller | Yes (medium) | Yes (medium) | Yes (medium) | Detects json_encode() / ->toJson() usage inside controllers (prefer Response/Resources) |
| `registration-missing-registered-event` | Registration Missing Registered Event | high | advisory | regex | low | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects user registration flows that create users without dispatching Registered |
| `repository-suggestion` | Repository Pattern Suggestion | medium | advisory | ast | medium | laravel | service | No (-) | Yes (medium) | Yes (medium) | Suggests extracting database queries to Repository classes |
| `service-extraction` | Service Extraction Suggestion | medium | advisory | ast | medium | laravel | service | No (-) | Yes (medium) | Yes (medium) | Suggests extracting business logic to Service classes |

### Backend Security (28)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `api-endpoint-missing-idempotency-key` | API Endpoint Missing Idempotency Key | high | advisory | regex | low | laravel | controller, route | No (-) | Yes (high) | Yes (high) | Detects mutating API handlers that create durable state without an idempotency key guard |
| `archive-upload-zip-slip-risk` | Archive Upload Zip Slip Risk | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects ZipArchive extraction without traversal-safe entry validation |
| `authorization-missing-on-sensitive-reads` | Authorization Missing On Sensitive Reads | high | advisory | ast | high | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects sensitive read flows without visible policy or ability checks |
| `blade-component-no-fallback-slot` | Blade Component No Fallback Slot | low | advisory | regex | low | laravel | blade | No (-) | No (-) | Yes (low) | Detects anonymous Blade components that render $slot without a fallback or empty-state guard |
| `blade-queries` | Blade Queries Detection | high | advisory | ast | medium | laravel | blade | Yes (high) | Yes (high) | Yes (high) | Detects database queries in Blade templates |
| `blade-xss-risk` | Possible XSS risk in Blade raw output | medium | advisory | ast | medium | laravel | blade | Yes (medium) | Yes (medium) | Yes (medium) | Detects `{!! ... !!}` usage that appears to output request-derived content |
| `broadcast-channel-authorization-missing` | Broadcast Channel Authorization Missing | high | risk | ast | medium | laravel | global | No (-) | Yes (high) | Yes (high) | Detects broadcast channels that do not show explicit authorization logic |
| `host-header-poisoning-risk` | Host Header Poisoning Risk | high | risk | ast | medium | laravel | global | No (-) | Yes (high) | Yes (high) | Detects host header-derived URL/redirect construction without trusted host guard |
| `insecure-deserialization` | Insecure Deserialization | high | advisory | regex | low | laravel | global | No (-) | No (-) | Yes (high) | Detects unsafe use of unserialize() on potentially untrusted input |
| `insecure-random-for-security` | Insecure Random for Security | medium | advisory | regex | low | laravel | global | No (-) | No (-) | Yes (medium) | Detects use of rand() or mt_rand() in security-sensitive contexts |
| `insecure-session-cookie-config` | Insecure Session Cookie Config | high | advisory | regex | low | laravel | config | Yes (high) | Yes (high) | Yes (high) | Detects Laravel session cookie settings with weak security defaults |
| `mass-assignment-risk` | Mass Assignment Risk | high | advisory | ast | medium | laravel | model | Yes (high) | Yes (high) | Yes (high) | Detects Model::create/update/fill with $request->all() (mass assignment risk) |
| `missing-rate-limiting` | Missing Rate Limiting | high | risk | ast | high | laravel | global | No (-) | Yes (high) | Yes (high) | Detects sensitive endpoints missing explicit throttle/rate-limit controls |
| `model-hidden-sensitive-attributes-missing` | Model Hidden Sensitive Attributes Missing | high | risk | ast | medium | laravel | model | No (-) | Yes (high) | Yes (high) | Detects models that expose sensitive attributes without listing them in $hidden |
| `obsolete-x-xss-protection-header` | Obsolete X-XSS-Protection Header | low | advisory | regex | low | laravel | config, middleware | No (-) | No (-) | No (-) | Detects obsolete X-XSS-Protection header in middleware/kernel configuration |
| `password-hash-weak-algorithm` | Password Hash Uses Weak Algorithm | critical | advisory | regex | low | laravel | global | No (-) | Yes (critical) | Yes (critical) | Detects md5/sha1 usage for password hashing flows |
| `plain-text-sensitive-config` | Plain-Text Sensitive Config | critical | advisory | regex | low | laravel | config | No (-) | Yes (critical) | Yes (critical) | Detects sensitive config keys assigned to literal strings instead of env() lookups |
| `public-anonymous-mutation-abuse-readiness` | Public Anonymous Mutation Abuse Readiness | medium | advisory | ast | low | laravel | route, middleware | No (-) | Yes (medium) | Yes (medium) | Reviews anonymous public game/room mutation endpoints for abuse controls |
| `sensitive-model-appends-risk` | Sensitive Model Appends Risk | high | risk | ast | medium | laravel | model | No (-) | Yes (high) | Yes (high) | Detects sensitive attributes listed in a model's $appends array |
| `sensitive-response-cache-control-missing` | Sensitive Response Missing Cache-Control | medium | risk | ast | high | laravel | global | No (-) | Yes (medium) | Yes (medium) | Detects sensitive/authenticated responses without explicit no-store cache headers |
| `sensitive-routes-missing-verified-middleware` | Sensitive Routes Missing Verified Middleware | high | advisory | ast | high | laravel | middleware, route | Yes (high) | Yes (high) | Yes (high) | Detects sensitive web routes missing verified middleware |
| `signed-routes-missing-signature-middleware` | Signed Routes Missing Signature Middleware | high | advisory | ast | high | laravel | middleware, route | Yes (high) | Yes (high) | Yes (high) | Detects routes that likely need signed middleware but do not have it |
| `timing-attack-token-comparison` | Timing Attack Token Comparison | high | advisory | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects direct token/hash equality comparisons that should use constant-time `hash_equals` |
| `unsafe-redirect` | Unsafe Redirect | high | risk | regex | low | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects redirects that appear to trust unvalidated external or user-provided targets |
| `url-validation-protocol-bypass` | URL Validation Protocol Bypass | high | advisory | regex | low | laravel | controller, middleware | No (-) | Yes (high) | Yes (high) | Detects redirect/link request fields that rely on Laravel's broad url validation rule |
| `weak-password-policy-validation` | Weak Password Policy Validation | medium | risk | regex | low | laravel | controller | No (-) | Yes (medium) | Yes (medium) | Detects weak password validation in authentication/registration flows |
| `xml-xxe-risk` | Potential XML External Entity Risk | high | risk | ast | medium | laravel | global | No (-) | Yes (high) | Yes (high) | Detects XML parsing calls without XXE hardening signals |
| `zip-bomb-risk` | Zip Bomb Risk | high | risk | ast | medium | laravel | global | No (-) | Yes (high) | Yes (high) | Detects archive extraction flows without decompression/entry safety checks |

### Cache & Performance (7)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `cache-missing-fallback` | Cache Missing Fallback | high | advisory | ast | medium | laravel | controller, service, job | No (-) | Yes (high) | Yes (high) | Detects Cache::get calls whose nullable result is dereferenced without a fallback |
| `cache-stampede-risk` | Cache Stampede Risk | high | advisory | regex | low | laravel | controller, service | No (-) | Yes (high) | Yes (high) | Detects Cache::remember calls without nearby lock protection |
| `chunk-missing-for-large-datasets` | Chunk Missing For Large Datasets | high | advisory | regex | low | laravel | controller, service, job, php-function | No (-) | Yes (high) | Yes (high) | Detects Model::all or get results iterated without chunk/cursor |
| `eager-loading` | Eager Loading Suggestion | medium | advisory | ast | medium | laravel | global | Yes (medium) | Yes (medium) | Yes (medium) | Suggests eager loading to prevent N+1 query problems |
| `missing-cache-for-reference-data` | Missing Cache for Reference Data | low | advisory | ast | medium | laravel | global | No (-) | No (-) | Yes (low) | Detects reference data queries that could benefit from caching |
| `missing-pagination` | Missing Pagination | medium | advisory | ast | high | laravel | global | No (-) | No (-) | Yes (medium) | Detects API endpoints returning all records without pagination or limit |
| `n-plus-one-risk` | N+1 Risk Detection | high | advisory | ast | medium | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects likely lazy-loaded relation access in loops (N+1 risk) |

### CI/CD & Devops (10)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `app-debug-not-false-in-production` | App Debug Not False In Production | high | risk | ast | low | devops | global | No (-) | Yes (high) | Yes (high) | Detects debug defaults that enable Laravel debug mode in production-facing configuration |
| `app-env-not-set-to-production` | App Env Not Set To Production | medium | risk | ast | low | devops | global | No (-) | Yes (medium) | Yes (medium) | Detects environment defaults that encourage production servers to run in local/development mode |
| `ci-cd-hardening-missing` | CI/CD Hardening Missing | medium | advisory | regex | low | devops | config | No (-) | No (-) | No (-) | Detects CI workflows missing fundamental quality and security gates |
| `config-in-loop` | config() Call Inside Loop | medium | advisory | ast | medium | php | php-class | Yes (medium) | Yes (medium) | Yes (medium) | Detects config() calls inside loops (cache value outside the loop) |
| `env-committed-to-git` | Env Committed To Git Risk | critical | risk | ast | low | devops | global | Yes (critical) | Yes (critical) | Yes (critical) | Detects projects whose .gitignore does not explicitly ignore the real .env file |
| `env-example-missing-or-out-of-sync` | Env Example Missing Or Out Of Sync | high | risk | ast | medium | devops | global | Yes (high) | Yes (high) | Yes (high) | Detects missing .env.example files or required keys absent from the example environment |
| `env-outside-config` | Avoid env() Outside Config | medium | advisory | ast | medium | laravel | config | Yes (medium) | Yes (medium) | Yes (medium) | Detects direct env() usage outside config files |
| `missing-queue-worker-supervision` | Missing Queue Worker Supervision | high | risk | ast | medium | devops | global | No (-) | Yes (high) | Yes (high) | Detects Laravel queue usage without Horizon or supervisor worker restart configuration |
| `no-logging-strategy-configured` | No Logging Strategy Configured | low | advisory | ast | low | devops | global | No (-) | Yes (low) | Yes (low) | Detects Laravel logging defaults that rely only on local file channels |
| `storage-paths-not-in-gitignore` | Storage Paths Not In Gitignore | high | risk | ast | low | devops | global | Yes (high) | Yes (high) | Yes (high) | Detects generated Laravel storage/cache paths missing from .gitignore |

### Code Quality (22)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `array-unpacking-in-loop` | Array Unpacking In Loop | high | advisory | regex | low | php | php-class, php-function | No (-) | Yes (high) | Yes (high) | Detects array_merge or array spread rebuilds inside loops |
| `bulk-insert-missing` | Bulk Insert Missing | high | advisory | regex | low | php | php-class, controller, service | No (-) | Yes (high) | Yes (high) | Detects insert/create/save calls inside loops that should likely be batched |
| `catch-too-broad` | Catch Too Broad | medium | risk | regex | low | php | php-function | No (-) | Yes (medium) | Yes (medium) | Detects broad catch blocks that return generic fallbacks without logging useful exception detail |
| `circular-dependency` | Circular Dependency | high | advisory | ast | high | php | php-class | Yes (high) | Yes (high) | Yes (high) | Detects circular dependencies between classes (cycles in the dependency graph) |
| `dry-violation` | DRY Violation Detection | medium | advisory | ast | medium | php | php-class | Yes (medium) | Yes (medium) | Yes (medium) | Detects duplicate code blocks |
| `exception-swallowing` | Exception Swallowing | high | advisory | regex | low | php | php-class, php-function | No (-) | Yes (high) | Yes (high) | Detects catch blocks that are empty or contain only comments |
| `god-class` | God Class Detection | high | advisory | ast | medium | php | php-class | Yes (high) | Yes (high) | Yes (high) | Flags classes that are too large and likely violate SRP/cohesion |
| `high-complexity` | High Complexity Detection | medium | advisory | ast | medium | php | php-class | Yes (medium) | Yes (medium) | Yes (medium) | Flags methods with high cyclomatic complexity |
| `high-coupling-class` | High Coupling Class | medium | advisory | ast | medium | php | php-class | Yes (medium) | Yes (medium) | Yes (medium) | Detects classes that depend on too many other application classes |
| `long-method` | Long Method Detection | low | advisory | ast | medium | php | php-class, php-function | Yes (low) | Yes (low) | Yes (low) | Flags methods exceeding recommended length |
| `low-coverage-files` | Low Coverage Files | medium | advisory | ast | high | php | php-class, test | Yes (medium) | Yes (medium) | Yes (medium) | Detects source files with coverage below a minimum threshold (when coverage reports are present) |
| `missing-return-type-nullable` | Missing Return Type Nullable | high | defect | regex | low | php | php-function | No (-) | No (-) | Yes (high) | Detects PHP functions that declare a non-nullable return type but return null on some path |
| `missing-strict-types` | Missing strict_types Declaration | medium | advisory | regex | low | php | php-class, php-function | No (-) | No (-) | Yes (medium) | Detects PHP class/function files missing declare(strict_types=1) near the top |
| `missing-type-declarations` | Missing Type Declarations | medium | advisory | regex | low | php | php-class, php-function | No (-) | No (-) | Yes (medium) | Detects functions or methods missing parameter or return type declarations |
| `mutable-global-state` | Mutable Global State | high | advisory | regex | low | php | php-class, php-function | No (-) | Yes (high) | Yes (high) | Detects use of PHP global variables and mutable static properties |
| `prefer-imports` | Prefer imports instead of fully-qualified class names | low | advisory | ast | medium | php | php-class | Yes (low) | Yes (low) | Yes (low) | Suggests importing project classes with `use` instead of referencing FQCNs directly. |
| `static-helper-abuse` | Static Helper Abuse | medium | advisory | ast | medium | php | php-class | Yes (medium) | Yes (medium) | Yes (medium) | Detects heavy use of Helper/Utils static calls (prefer DI) |
| `string-concat-in-loop` | String Concatenation In Loop | high | advisory | regex | low | php | php-function | No (-) | Yes (high) | Yes (high) | Detects .= string concatenation inside loops |
| `test-coverage-ratio` | Test Coverage Ratio | medium | advisory | ast | low | php | php-class | No (-) | No (-) | No (-) | Detects projects where test file count is low relative to source class count |
| `tests-missing` | Tests Missing | medium | advisory | ast | high | php | php-class, test | Yes (medium) | Yes (medium) | Yes (medium) | Detects missing or insufficient automated tests (quality gate) |
| `too-many-dependencies` | Too Many Constructor Dependencies | medium | advisory | ast | medium | php | php-class | Yes (medium) | Yes (medium) | Yes (medium) | Detects constructors with too many dependencies (likely SRP violation) |
| `unused-private-method` | Unused Private Method | low | advisory | ast | medium | php | php-class, php-function | Yes (low) | Yes (low) | Yes (low) | Detects private methods that appear to be unused within their class |

### CORS & Middleware (6)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `cookie-samesite-missing` | Cookie SameSite Missing | high | advisory | regex | low | laravel | config | No (-) | Yes (high) | Yes (high) | Detects weak or missing SameSite configuration in session cookies |
| `cors-misconfiguration` | CORS Misconfiguration | high | advisory | regex | low | laravel | middleware, config | No (-) | No (-) | Yes (high) | Detects overly permissive CORS settings that could expose sensitive data |
| `missing-csrf-token-verification` | Missing CSRF Token Verification | high | advisory | ast | high | laravel | middleware | No (-) | No (-) | Yes (high) | Detects routes missing CSRF protection that should have it |
| `missing-hsts-header` | Missing HSTS Header | high | advisory | regex | low | laravel | config | No (-) | Yes (high) | Yes (high) | Detects HSTS omissions at an application-owned security-header boundary |
| `missing-https-enforcement` | Missing HTTPS Enforcement | medium | advisory | regex | low | laravel | global | No (-) | No (-) | Yes (medium) | Detects missing force HTTPS configuration for production |
| `security-headers-baseline-missing` | Security Headers Baseline Missing | medium | risk | ast | high | laravel | config | No (-) | Yes (medium) | Yes (medium) | Detects missing baseline security headers handling for web apps |

### Database & Migrations (8)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `business-logic-in-migration` | Business Logic In Migration | high | advisory | regex | low | laravel | migration | No (-) | Yes (high) | Yes (high) | Detects model usage or business loops inside migration up methods |
| `composite-index-on-tenant-models` | Composite Index On Tenant Models | low | advisory | ast | medium | laravel | migration, model | No (-) | No (-) | No (-) | Detects tenant-scoped models missing composite (tenant_id, created_at) indexes |
| `date-format-missing-cast` | Date Format Missing Cast | low | advisory | regex | low | laravel | model, blade | No (-) | Yes (low) | Yes (low) | Detects manual date parsing/formatting where model datetime casts are preferred |
| `destructive-migration-without-safety-guard` | Destructive Migration Without Safety Guard | high | risk | ast | medium | laravel | migration | No (-) | No (-) | Yes (high) | Detects destructive migration operations without schema/table existence checks |
| `missing-foreign-key-in-migration` | Missing Foreign Key In Migration | medium | advisory | ast | medium | laravel | migration | No (-) | Yes (medium) | Yes (medium) | Detects migration reference columns that are added without a foreign key definition |
| `missing-index-on-lookup-columns` | Missing Index On Lookup Columns | medium | advisory | ast | medium | laravel | migration | No (-) | Yes (medium) | Yes (medium) | Detects migration lookup columns that are added without an index or unique constraint |
| `missing-model-factory` | Missing Model Factory | medium | advisory | ast | high | laravel | model | No (-) | Yes (medium) | Yes (medium) | Detects Eloquent models without corresponding Factory classes |
| `missing-model-observer-registration` | Missing Model Observer Registration | high | risk | ast | medium | laravel | observer, provider | No (-) | Yes (high) | Yes (high) | Detects Laravel Observer classes that are never registered in a ServiceProvider |

### Dependency & Compatibility (4)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `asset-versioning-check` | Asset Versioning Check | low | advisory | ast | medium | laravel | global | No (-) | No (-) | Yes (low) | Verifies that Inertia asset versioning is properly configured |
| `composer-dependency-below-secure-version` | Composer Dependency Below Secure Version | high | advisory | regex | low | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects Composer dependencies pinned below curated secure minimum versions |
| `npm-dependency-below-secure-version` | NPM Dependency Below Secure Version | high | advisory | regex | low | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects npm dependencies pinned below curated secure minimum versions |
| `vite-chunk-config-missing` | Vite Chunk Config Missing | low | advisory | regex | low | react | config | No (-) | No (-) | No (-) | Detects missing or oversized Vite chunk configuration in vite.config.ts |

### Error Handling & Resilience (13)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `error-pages-missing` | Missing Laravel Error Pages | medium | advisory | ast | high | laravel | global | Yes (medium) | Yes (medium) | Yes (medium) | Detects missing 4xx/5xx error pages in Blade or Inertia error surfaces |
| `http-call-missing-fallback` | HTTP Call Missing Fallback | high | advisory | ast | medium | laravel | controller, service, job | No (-) | Yes (high) | Yes (high) | Detects Laravel HTTP client calls that are not wrapped or checked before use |
| `job-http-call-missing-timeout` | Job HTTP Call Missing Timeout | medium | advisory | regex | low | laravel | job | Yes (medium) | Yes (medium) | Yes (medium) | Detects queued jobs with outbound HTTP calls and no timeout controls |
| `job-missing-idempotency-guard` | Job Missing Idempotency Guard | medium | advisory | regex | low | laravel | job | Yes (medium) | Yes (medium) | Yes (medium) | Detects queued jobs with side effects and no obvious idempotency guard |
| `job-missing-retry-policy` | Job Missing Retry Policy | medium | advisory | regex | low | laravel | job | Yes (medium) | Yes (medium) | Yes (medium) | Detects side-effecting queued jobs without explicit retry or backoff controls |
| `listener-shouldqueue-missing-for-io-bound-handler` | Listener ShouldQueue Missing For IO-Bound Handler | medium | advisory | ast | medium | laravel | job | No (-) | Yes (medium) | Yes (medium) | Detects listeners that perform IO-heavy work synchronously |
| `missing-circuit-breaker` | Missing Circuit Breaker | medium | advisory | regex | low | laravel | service, controller, job | No (-) | Yes (medium) | Yes (medium) | Detects Laravel HTTP client calls without timeout or fallback handling |
| `notification-shouldqueue-missing` | Notification ShouldQueue Missing | medium | advisory | ast | medium | laravel | job | No (-) | Yes (medium) | Yes (medium) | Detects notifications that deliver mail/database/broadcast payloads without implementing ShouldQueue |
| `queue-job-missing-failure-handling` | Queue Job Missing Failure Handling | medium | advisory | regex | low | laravel | job | No (-) | Yes (medium) | Yes (medium) | Detects queued jobs with side effects but no visible retry/backoff/failed handling |
| `synchronous-mail-in-request` | Synchronous Mail In Request | high | advisory | regex | low | laravel | controller, service | No (-) | Yes (high) | Yes (high) | Detects synchronous Mail::send or Mail::to()->send calls in request path code |
| `webhook-replay-protection-missing` | Webhook Replay Protection Missing | high | risk | ast | high | laravel | global | No (-) | Yes (high) | Yes (high) | Detects webhook handlers without visible timestamp/nonce replay protection |
| `webhook-signature-missing` | Webhook Signature Verification Missing | high | risk | ast | high | laravel | global | No (-) | Yes (high) | Yes (high) | Detects webhook handlers lacking visible signature verification |
| `webhook-signature-parameter-unused` | Webhook Signature Parameter Unused | critical | advisory | regex | low | laravel | service, controller | No (-) | Yes (critical) | Yes (critical) | Detects webhook/payment handlers that accept a signature parameter but never use it |

### File & Media Security (5)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `insecure-file-download-response` | Insecure File Download Response | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects file download responses built from untrusted path input without guards |
| `unsafe-file-include-variable` | Unsafe File Include Variable | critical | advisory | regex | low | php | php-class, php-function | No (-) | Yes (critical) | Yes (critical) | Detects include/require calls that use unsanitized variable paths |
| `unsafe-file-upload` | Unsafe File Upload | high | advisory | ast | medium | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects file upload handling without validation |
| `upload-mime-extension-mismatch` | Upload MIME/Extension Mismatch Risk | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects upload flows that trust client extensions without MIME hardening |
| `upload-size-limit-missing` | Upload Size Limit Missing | medium | risk | regex | low | laravel | global | No (-) | Yes (medium) | Yes (medium) | Detects upload validation without explicit max file size |

### Frontend Architecture (10)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `anonymous-default-export-component` | Anonymous Default Export Component | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects anonymous default-exported React components |
| `context-oversized-provider` | Context Provider Oversized Value | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects broad provider values that likely trigger unnecessary fan-out rerenders |
| `context-provider-inline-value` | Context Provider Inline Value | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects inline provider values that trigger unnecessary rerenders |
| `cross-feature-import-boundary` | Cross-Feature Import Boundary Violation | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects deep imports across feature boundaries |
| `large-custom-hook` | Large Custom Hook | medium | advisory | regex | low | react | react-component, hook | Yes (medium) | Yes (medium) | Yes (medium) | Detects oversized custom hooks that likely need decomposition |
| `no-inline-hooks` | No Inline Hook Definitions | medium | advisory | regex | low | react | react-component, hook | No (-) | No (-) | Yes (medium) | Enforces extraction of custom hooks to separate files |
| `no-inline-services` | No Inline Service/Helper Definitions | medium | advisory | ast | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects helper functions or service classes defined inside UI component files |
| `no-inline-types` | No Inline Type/Interface Definitions | medium | advisory | ast | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects TypeScript types/interfaces defined inside UI component files |
| `no-nested-components` | No Nested Components | high | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects components defined inside other components (causes remounts) |
| `react-project-structure-consistency` | React Project Structure Consistency | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects inconsistent React folder boundaries for hooks, services, utilities, helpers, types, and con |

### Frontend Security (4)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `api-key-in-client-bundle` | API Key In Client Bundle | critical | advisory | regex | low | react | react-component | No (-) | Yes (critical) | Yes (critical) | Detects likely secret/API key literals embedded in client-side source files |
| `client-open-redirect-unvalidated-navigation` | Client Open Redirect Unvalidated Navigation | high | risk | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects client-side navigation to unvalidated user-controlled targets |
| `insecure-postmessage-origin-wildcard` | Insecure postMessage Origin Wildcard | high | risk | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects postMessage calls with wildcard target origin |
| `token-storage-insecure-localstorage` | Token Storage Insecure LocalStorage | high | risk | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects sensitive token persistence in localStorage/sessionStorage |

### Input Validation & Sanitization (10)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `command-injection-risk` | Command injection risk | high | advisory | ast | medium | php | php-class, php-function | Yes (high) | Yes (high) | Yes (high) | Detects shell execution functions called with non-literal arguments |
| `dangerous-html-sink-without-sanitizer` | Dangerous HTML Sink Without Sanitizer | high | risk | ast | medium | react | react-component | No (-) | Yes (high) | Yes (high) | Detects dangerouslySetInnerHTML usage without sanitizer guard |
| `hardcoded-secrets` | Hardcoded Secrets Detection | high | advisory | regex | low | laravel | global | No (-) | No (-) | Yes (high) | Detects hardcoded passwords, API keys, tokens, and other sensitive values |
| `no-dangerously-set-inner-html` | No Dangerously Set Inner HTML | critical | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (critical) | Detects usage of dangerouslySetInnerHTML |
| `pcre-redos-risk` | PCRE ReDoS Risk | high | advisory | regex | low | php | php-class | No (-) | Yes (high) | Yes (high) | Detects nested quantifier regex patterns in preg_match/preg_replace usage |
| `raw-sql` | Raw SQL Usage | high | advisory | ast | medium | php | php-class, php-function | Yes (high) | Yes (high) | Yes (high) | Detects DB::select/statement/raw usage (prefer query builder with bindings) |
| `sql-injection-risk` | SQL Injection Risk Detection | high | advisory | regex | low | laravel | global | Yes (high) | Yes (high) | Yes (high) | Detects raw SQL queries with potential variable interpolation |
| `ssrf-risk-http-client` | Potential SSRF in HTTP Client Call | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects request-derived URLs used in outbound HTTP calls without allowlist validation |
| `unsafe-eval` | Unsafe code execution (eval/assert/preg_replace /e) | high | advisory | ast | medium | php | php-class, php-function | Yes (high) | Yes (high) | Yes (high) | Detects eval/assert(string)/preg_replace(/e) which can lead to code execution |
| `unsafe-unserialize` | Unsafe unserialize() usage | high | advisory | ast | medium | php | php-class | Yes (high) | Yes (high) | Yes (high) | Detects unserialize() without allowed_classes restriction or on request input |

### Logging & Observability (5)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `debug-exposure-risk` | Debug Exposure Risk | high | risk | regex | low | laravel | global | No (-) | Yes (high) | Yes (high) | Detects debug settings that can expose stack traces, secrets, or internal internals |
| `missing-api-rate-limit-headers` | Missing API Rate Limit Headers | low | advisory | ast | low | laravel | route, middleware | No (-) | Yes (low) | Yes (low) | Detects throttled API routes where rate-limit response headers may be stripped or absent |
| `missing-health-check-endpoint` | Missing Health Check Endpoint | medium | advisory | ast | medium | laravel | route | No (-) | Yes (medium) | Yes (medium) | Detects Laravel apps without a health, status, or ping route |
| `no-log-debug-in-app` | Avoid Log::debug in app code | low | advisory | regex | low | laravel | global | Yes (low) | Yes (low) | Yes (low) | Detects Log::debug(...) calls in application code |
| `sensitive-data-logging` | Sensitive Data Logging Detection | high | advisory | regex | low | laravel | global | No (-) | No (-) | Yes (high) | Detects logging of passwords, tokens, and other sensitive data |

### Model & Eloquent (7)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `eloquent-raw-where-string` | Eloquent Raw Where String | high | risk | regex | low | laravel | controller, service, model | No (-) | Yes (high) | Yes (high) | Detects Eloquent where() calls that build SQL predicates inside the first string argument |
| `missing-inventory-lock-on-decrement` | Missing Inventory Lock On Decrement | high | advisory | ast | medium | laravel | controller, service, job | No (-) | No (-) | No (-) | Detects inventory decrements without pessimistic locking |
| `missing-null-guard-after-relation-load` | Missing Null Guard After Relation Load | medium | advisory | regex | low | laravel | service, controller, job | No (-) | Yes (medium) | Yes (medium) | Detects relation loads followed by relation usage without a null guard |
| `model-cross-model-query` | Cross-Model Query Inside Model | low | advisory | ast | medium | laravel | model | Yes (low) | Yes (low) | Yes (low) | Detects direct queries to another model from within model methods |
| `negative-stock-not-guarded` | Negative Stock Not Guarded | high | advisory | ast | medium | laravel | controller, service, job | No (-) | No (-) | No (-) | Detects inventory decrements without floor validation |
| `tenant-global-scope-missing` | Tenant Global Scope Missing | high | advisory | ast | medium | laravel | provider | No (-) | No (-) | No (-) | Detects multi-tenant projects missing a global tenant scope in ServiceProviders |
| `transaction-required-for-multi-write` | Transaction Required For Multi Write | high | advisory | ast | medium | laravel | service | Yes (high) | Yes (high) | Yes (high) | Detects methods with multiple writes that are not wrapped in a DB transaction |

### Realtime & WebSocket (3)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `realtime-config-outside-laravel-config` | Realtime Config Outside Laravel Config | low | advisory | ast | medium | laravel | config | No (-) | Yes (low) | Yes (low) | Detects standalone realtime config files that are not bridged into Laravel config |
| `realtime-inmemory-state-scalability` | Realtime In-Memory State Scalability | low | advisory | ast | medium | laravel | global | No (-) | Yes (low) | Yes (low) | Detects standalone realtime runtimes that keep active room/player state only in process memory |
| `websocket-handler-integration-tests-missing` | WebSocket Handler Integration Tests Missing | low | advisory | ast | medium | laravel | test, php-class | No (-) | Yes (low) | Yes (low) | Detects realtime handlers without handler-level or socket-message integration tests |

### React Accessibility (44)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `accessible-authentication` | Accessible Authentication | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects authentication flows that may be difficult for users with cognitive impairments |
| `animation-no-pause-control` | Animation No Pause Control | medium | advisory | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Detects animation utilities without reduced-motion variants or pause controls |
| `apg-accordion-disclosure-contract` | APG Accordion/Disclosure Contract | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects disclosure widgets missing APG button/expanded/controls signals |
| `apg-combobox-contract` | APG Combobox Contract | high | advisory | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects combobox widgets missing APG expanded/controls/active-option/keyboard signals |
| `apg-menu-button-contract` | APG Menu Button Contract | high | advisory | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects menu button widgets missing APG trigger/menu/keyboard signals |
| `apg-tabs-keyboard-contract` | APG Tabs Keyboard Contract | high | advisory | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects custom tab widgets missing APG role/state/keyboard signals |
| `autocomplete-missing` | Autocomplete Attribute Missing | low | advisory | regex | low | react | react-component, form | No (-) | No (-) | Yes (low) | Detects form fields that could benefit from autocomplete attribute |
| `autoplay-media` | Autoplay Media | high | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects auto-playing audio/video without user controls |
| `button-text-vague` | Button Text Vague | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects buttons with vague text that lacks context |
| `color-contrast-ratio` | Color Contrast Ratio | high | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects potential color contrast issues in text elements |
| `css-color-only-state-indicator` | CSS Color-Only State Indicator | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects likely state/error indicators conveyed only by color |
| `css-focus-outline-without-replacement` | CSS Focus Outline Without Replacement | high | advisory | regex | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects focus styles that remove outline without visible replacement |
| `css-hover-only-interaction` | CSS Hover-Only Interaction | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects hover interaction selectors without corresponding focus styles |
| `dialog-focus-restore-missing` | Dialog Focus Restore Missing | high | advisory | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects dialog/overlay flows missing focus restoration signals on close |
| `error-message-missing` | Error Message Missing | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects form fields with validation but no error message association |
| `focus-indicator-missing` | Focus Indicator Missing | high | advisory | regex | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects explicit focus outline removal without visible replacement |
| `focus-lost-on-route-change` | Focus Lost On Route Change | medium | advisory | regex | low | react | page, layout | No (-) | Yes (medium) | Yes (medium) | Detects SPA route navigation without visible focus restoration logic |
| `focus-not-obscured` | Focus Not Obscured | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects fixed/sticky elements that may obscure focused content |
| `form-double-submit` | Form Double Submit | high | advisory | regex | low | react | form, react-component | No (-) | Yes (high) | Yes (high) | Detects submit buttons without disabled state during submission |
| `form-label-association` | Form Label Association | high | advisory | ast | low | react | react-component, form | Yes (high) | Yes (high) | Yes (high) | Detects labels that are not associated with a form control |
| `h1-singleton-violation` | H1 Singleton Violation | medium | advisory | regex | low | react | react-component, page | Yes (medium) | Yes (medium) | Yes (medium) | Detects missing or multiple H1 headings on page surfaces |
| `heading-order` | Heading Order | medium | advisory | regex | low | react | react-component, page | No (-) | No (-) | Yes (medium) | Detects skipped heading levels that break document outline |
| `img-alt-missing` | Image Alt Text Missing | high | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects <img> tags missing descriptive alt text |
| `interactive-accessible-name-required` | Interactive Accessible Name Required | high | advisory | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects interactive controls that lack a programmatic accessible name |
| `interactive-element-a11y` | Interactive Element Accessibility | high | advisory | ast | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects non-semantic clickable elements missing role/keyboard contracts |
| `jsx-aria-attribute-format` | JSX ARIA Attribute Format | medium | advisory | ast | medium | react | react-component, form | Yes (medium) | Yes (medium) | Yes (medium) | Detects malformed ARIA attribute names in JSX |
| `language-attribute-missing` | Language Attribute Missing | high | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects HTML documents without lang attribute |
| `link-text-vague` | Link Text Vague | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects links with vague text that lacks context |
| `long-page-no-toc` | Long Page Without TOC | low | advisory | regex | low | react | react-component, page | No (-) | No (-) | Yes (low) | Detects long pages without table of contents or navigation landmarks |
| `missing-empty-state` | Missing Empty State | low | advisory | ast | medium | react | react-component | Yes (low) | Yes (low) | Yes (low) | Detects list-heavy page surfaces without explicit empty-state handling |
| `missing-fieldset-legend` | Missing Fieldset Legend | high | advisory | regex | low | react | form, react-component | No (-) | Yes (high) | Yes (high) | Detects radio/checkbox groups without fieldset and legend |
| `missing-key-on-list-render` | Missing Key On List Render | high | advisory | regex | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects list renders that return JSX without a key prop |
| `missing-loading-state` | Missing Loading State | low | advisory | ast | medium | react | react-component | Yes (low) | Yes (low) | Yes (low) | Detects async page surfaces without explicit loading UI |
| `modal-trap-focus` | Modal Focus Trap Missing | high | advisory | ast | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects dialog/modal widgets missing keyboard focus management contracts |
| `outside-click-without-keyboard-fallback` | Outside Click Without Keyboard Fallback | high | advisory | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects outside-click close logic without keyboard fallback |
| `page-title-missing` | Page Title Missing | high | advisory | regex | low | react | react-component, page | No (-) | No (-) | Yes (high) | Detects pages without descriptive title element |
| `placeholder-as-label` | Placeholder Used as Label | medium | advisory | regex | low | react | react-component, form | No (-) | No (-) | Yes (medium) | Detects form fields with placeholder but no associated label |
| `redundant-entry` | Redundant Entry | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects forms that may ask users to re-enter previously provided information |
| `semantic-wrapper-breakage` | Semantic Wrapper Breakage | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects JSX wrappers that break list/table/description-list semantics |
| `skip-link-missing` | Skip Link Missing | high | advisory | regex | low | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects shell/layout files without a valid skip-to-content link |
| `status-message-announcement` | Status Message Announcement | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects status messages that may not be announced to screen readers |
| `table-missing-headers` | Table Missing Headers | high | advisory | regex | low | react | react-component, page | No (-) | Yes (high) | Yes (high) | Detects tables whose first row uses td cells instead of th headers |
| `touch-target-size` | Touch Target Size | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects interactive controls with explicit size below 44x44px |
| `video-missing-captions` | Video Missing Captions | medium | advisory | regex | low | react | react-component, page | No (-) | Yes (medium) | Yes (medium) | Detects video elements without caption tracks |

### React Best Practices (54)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `avoid-props-to-state-copy` | Avoid Props-to-State Copy | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects direct props mirroring into useState initializers |
| `console-log-in-production-code` | Console Log In Production Code | medium | risk | regex | low | react | react-component, page | No (-) | Yes (medium) | Yes (medium) | Detects console calls left in non-test frontend source files |
| `controlled-uncontrolled-input-mismatch` | Controlled/Uncontrolled Input Mismatch | high | advisory | ast | medium | react | react-component, form | Yes (high) | Yes (high) | Yes (high) | Detects React form controls that switch or violate controlled-input contracts |
| `crawlable-internal-navigation-required` | Crawlable Internal Navigation Required | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects internal navigation implemented without crawlable anchor/link semantics |
| `derived-state-in-effect` | Derived State Synced Through useEffect | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects state that is derived in useEffect instead of render/useMemo |
| `duplicate-key-source` | Potential Duplicate Key Source | medium | advisory | ast | high | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects list keys derived from weak/non-unique fields |
| `effect-event-relay-smell` | Effect Event Relay Smell | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects action relays implemented through flag state + useEffect |
| `exhaustive-deps-ast` | Exhaustive Dependencies (AST) | high | advisory | ast | medium | react | react-component | No (-) | Yes (high) | Yes (high) | AST-based detection of missing dependencies in React hooks |
| `hardcoded-user-facing-strings` | Hardcoded User Facing Strings | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects likely user-facing hardcoded strings not wrapped in i18n |
| `hooks-in-conditional-or-loop` | Hooks In Conditional Or Loop | high | advisory | regex | low | react | react-component, hook | Yes (high) | Yes (high) | Yes (high) | Detects React hooks inside conditionals, loops, or callback loops |
| `inline-api-logic` | Inline API Logic Detection | medium | advisory | ast | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects API calls and logic in component bodies |
| `inline-prop-object-array` | Inline Object/Array Prop Creation | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Inline objects or arrays passed as props create new references on every render. |
| `input-debounce-missing` | Input Debounce Missing | high | advisory | regex | low | react | react-component, form | No (-) | Yes (high) | Yes (high) | Detects input search/change handlers that call fetch/search without debounce |
| `large-react-component` | Large React Component Detection | medium | advisory | ast | medium | react | react-component | No (-) | No (-) | Yes (medium) | Detects oversized React components |
| `lazy-without-suspense` | Lazy Component Without Suspense Boundary | high | advisory | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects lazy component usage without a Suspense boundary |
| `loose-default-object-prop` | Loose Default Object Prop | medium | advisory | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Defaulting props to an empty object can hide missing data and lead to runtime bugs. |
| `missing-error-boundary-general` | Missing Error Boundary General | high | advisory | regex | low | react | react-component, page | No (-) | Yes (high) | Yes (high) | Detects large data-heavy feature component trees without ErrorBoundary wrapping |
| `missing-props-type` | Missing Props Type | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects React components without TypeScript props type definitions |
| `missing-usecallback-for-event-handlers` | Missing UseCallback for Event Handlers | medium | advisory | regex | low | react | react-component, hook | No (-) | No (-) | Yes (medium) | Detects event handlers passed as props without useCallback memoization |
| `missing-usememo-for-expensive-calc` | Missing UseMemo for Expensive Calculations | medium | advisory | regex | low | react | react-component, hook | No (-) | No (-) | Yes (medium) | Detects expensive calculations in render without useMemo memoization |
| `multiple-exported-react-components` | Multiple Exported React Components | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects files exporting multiple top-level React components |
| `no-direct-useeffect` | Direct useEffect Is Disallowed | medium | advisory | ast | medium | react | react-component, hook | No (-) | No (-) | Yes (medium) | Flags direct useEffect usage in strict React policy projects |
| `props-state-sync-effect-smell` | Props-State Sync Effect Smell | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects useEffect blocks that mirror props into state |
| `query-key-instability` | Unstable Query Key | medium | risk | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects inline objects/functions in query keys that break cache stability |
| `react-event-listener-cleanup-required` | Event Listener Cleanup Required | medium | risk | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Detects addEventListener in useEffect without removeEventListener cleanup |
| `react-no-array-index-key` | Avoid Array Index as React Key | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects unstable React key props that use array index variables |
| `react-no-props-mutation` | Props Object Mutation | high | defect | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects direct mutation of React props |
| `react-no-random-key` | Random Value Used As React Key | medium | risk | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Detects list keys generated from random/time-based values during render |
| `react-no-state-mutation` | State Variable Mutation | high | defect | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | Detects direct mutation of React state variables |
| `react-parent-child-spacing-overlap` | Parent/Child Spacing Overlap | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects overlapping spacing utilities between direct JSX parent-child nodes |
| `react-side-effects-in-render` | Side Effects During Render | high | defect | ast | medium | react | react-component | No (-) | Yes (high) | Yes (high) | Detects side-effect calls executed directly during React render |
| `react-timer-cleanup-required` | Timer Cleanup Required | medium | risk | regex | low | react | react-component | No (-) | Yes (medium) | Yes (medium) | Detects timer APIs in useEffect without proper cleanup |
| `react-useeffect-deps` | Missing useEffect Dependency Array | medium | advisory | regex | low | react | react-component, hook | Yes (medium) | Yes (medium) | Yes (medium) | Detects useEffect calls without a dependency array |
| `react-useeffect-fetch-without-abort` | UseEffect Fetch Without Abort | medium | advisory | regex | low | react | react-component, hook | Yes (medium) | Yes (medium) | Yes (medium) | Detects fetch in useEffect without abort or cleanup handling |
| `ref-access-during-render` | Ref Access During Render | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects `.current` reads directly inside JSX render expressions |
| `ref-used-as-reactive-state` | Ref Used as Reactive State | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects refs used as primary reactive state instead of useState |
| `route-shell-missing-error-boundary` | Route Shell Missing Error Boundary | low | risk | regex | low | react | react-component, page, layout | Yes (low) | Yes (low) | Yes (low) | Detects route/page shells with async data flow but no error boundary |
| `safe-target-blank` | Unsafe target='_blank' | high | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (high) | Detects usage of target='_blank' without rel='noopener noreferrer' |
| `stale-closure-in-listener` | Stale Closure In Event Listener | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects addEventListener callbacks capturing stale state in empty-deps effects |
| `stale-closure-in-timer` | Stale Closure In Timer Callback | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects timer callbacks capturing stale state in empty-deps effects |
| `state-update-in-render` | State Update During Render | high | defect | ast | medium | react | react-component | Yes (high) | Yes (high) | Yes (high) | Detects direct setState-like calls in React render flow |
| `suspense-fallback-missing` | Suspense Fallback Missing | medium | advisory | ast | medium | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects Suspense boundaries that do not define fallback UI |
| `typescript-type-check` | TypeScript Type Check | high | advisory | process | high | react | react-component | No (-) | No (-) | Yes (high) | Detects TypeScript type errors and syntax issues using tsc |
| `unhandled-promise-in-handler` | Unhandled Promise In Handler | high | advisory | regex | low | react | react-component, form | No (-) | Yes (high) | Yes (high) | Detects async event handlers with await but no local error handling |
| `unsafe-async-handler-without-guard` | Unsafe Async Handler Without Guard | medium | risk | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects async event handlers that can be re-triggered without pending/processing guard |
| `unstable-react-key` | Unstable React Key | high | advisory | regex | low | react | react-component | No (-) | Yes (high) | Yes (high) | React keys must be stable and unique. Unstable keys can cause incorrect UI updates and bugs. |
| `unthrottled-scroll-resize-handler` | Unthrottled Scroll/Resize Handler | high | advisory | regex | low | react | react-component, hook | No (-) | Yes (high) | Yes (high) | Detects scroll or resize listeners without throttle/debounce protection |
| `usecallback-ast` | UseCallback Required (AST) | medium | advisory | ast | medium | react | react-component, hook | No (-) | Yes (medium) | Yes (medium) | AST-based detection of inline handlers needing memoization |
| `usecallback-overuse` | useCallback Overuse | low | advisory | ast | medium | react | react-component, hook | No (-) | No (-) | Yes (low) | Detects useCallback wrappers with little stability/perf benefit |
| `useeffect-cleanup-missing` | UseEffect Cleanup Missing | medium | advisory | regex | low | react | react-component, hook | No (-) | No (-) | Yes (medium) | Detects useEffect with side effects that need cleanup but don't have it |
| `useless-suspense-boundary` | Useless Suspense Boundary | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects Suspense boundaries that wrap only synchronous components |
| `usememo-ast` | UseMemo Required (AST) | medium | advisory | ast | medium | react | react-component, hook | No (-) | Yes (medium) | Yes (medium) | AST-based detection of expensive calculations needing memoization |
| `usememo-overuse` | useMemo Overuse | low | advisory | ast | medium | react | react-component, hook | No (-) | No (-) | Yes (low) | Detects useMemo around trivial computations without measurable benefit |
| `window-any-typing` | Window Any Typing | low | advisory | regex | low | react | react-component | No (-) | No (-) | No (-) | Detects `(window as any)` or `(window as unknown as any)` patterns in TypeScript |

### React SEO (5)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `canonical-missing-or-invalid` | Canonical Missing or Invalid | medium | advisory | regex | low | react | react-component, page | Yes (medium) | Yes (medium) | Yes (medium) | Detects missing or malformed canonical metadata on public/indexable pages |
| `jsonld-structured-data-invalid-or-mismatched` | JSON-LD Structured Data Invalid or Mismatched | medium | advisory | regex | low | react | react-component | Yes (medium) | Yes (medium) | Yes (medium) | Detects invalid or weakly-formed JSON-LD structured data blocks |
| `meta-description-missing-or-generic` | Meta Description Missing or Generic | low | advisory | regex | low | react | react-component | Yes (low) | Yes (low) | Yes (low) | Detects missing or generic page-level meta descriptions on indexable/public surfaces |
| `page-indexability-conflict` | Page Indexability Conflict | high | risk | regex | low | react | react-component, page | Yes (high) | Yes (high) | Yes (high) | Detects conflicting indexability metadata signals on the same page |
| `robots-directive-risk` | Robots Directive Risk | medium | advisory | regex | low | react | react-component, page | Yes (medium) | Yes (medium) | Yes (medium) | Detects risky robots directives on likely public/indexable pages |

### Tailwind & Styling (10)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `css-fixed-layout-px` | CSS Fixed Layout px Dimensions | low | advisory | regex | low | react | react-component, layout | No (-) | No (-) | Yes (low) | Detects rigid large px width/height values in layout declarations |
| `css-font-size-px` | CSS Font Size Uses px | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects font-size declared in px instead of rem |
| `css-spacing-px` | CSS Spacing Uses px | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects margin/padding/gap spacing declared in px instead of rem scale |
| `tailwind-appearance-none-risk` | Tailwind Appearance None Risk | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Flags appearance-none on form controls without compensating focus/usability cues |
| `tailwind-arbitrary-layout-size` | Tailwind Arbitrary Layout Size | low | advisory | regex | low | react | react-component, layout | No (-) | No (-) | Yes (low) | Detects rigid arbitrary width/height Tailwind values |
| `tailwind-arbitrary-radius-shadow` | Tailwind Arbitrary Radius/Shadow | low | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (low) | Detects arbitrary rounded/shadow values where scale tokens are preferred |
| `tailwind-arbitrary-spacing` | Tailwind Arbitrary Spacing | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects p/m/gap/space arbitrary spacing values |
| `tailwind-arbitrary-text-size` | Tailwind Arbitrary Text Size | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects text-[..px] arbitrary sizing instead of Tailwind text scale |
| `tailwind-arbitrary-value-overuse` | Tailwind Arbitrary Value Overuse | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects class strings with excessive arbitrary Tailwind values |
| `tailwind-motion-reduce-missing` | Tailwind Motion Reduce Missing | medium | advisory | regex | low | react | react-component | No (-) | No (-) | Yes (medium) | Detects animation-heavy class strings without motion-safe/motion-reduce variants |

### Testing & Test Quality (1)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `test-no-database-trait` | Test Missing Database Isolation Trait | high | advisory | regex | low | laravel | test | No (-) | Yes (high) | Yes (high) | Detects database-touching tests without RefreshDatabase or transaction traits |

### Third Party Integration (3)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `livewire-public-prop-mass-assignment` | Livewire Public Property Mass Assignment Risk | high | advisory | regex | low | laravel | model | No (-) | Yes (high) | Yes (high) | Detects mutable public Livewire properties without #[Locked] attribute |
| `malformed-authorization-call` | Malformed Authorization Call | high | advisory | regex | low | laravel | controller, service | No (-) | No (-) | No (-) | Detects $this->authorize->method() patterns that silently bypass authorization |
| `phi-encryption-missing` | PHI Encryption Missing | high | advisory | regex | low | laravel | model | No (-) | No (-) | No (-) | Detects patient health information fields in models that are not encrypted at rest |

### Other (10)
| Rule ID | Name | Severity | Class | Detection | Cost | Domain | Applies To | Startup | Balanced | Strict | Description |
|---|---:|---:|---|---|---|---|---|---|---|---|---|
| `column-selection-suggestion` | Column Selection Suggestion | low | advisory | ast | medium | laravel | global | No (-) | No (-) | Yes (low) | Suggests explicit column selection for better query performance |
| `hardcoded-magic-strings` | Hardcoded Magic Strings | low | advisory | regex | low | laravel | php-class, model, service | No (-) | No (-) | Yes (low) | Detects repeated status/type/role strings that should be constants or enums |
| `missing-feature-flag-pattern` | Missing Feature Flag Pattern | low | advisory | ast | medium | laravel | global | No (-) | No (-) | Yes (low) | Suggests a feature flag mechanism for larger Laravel apps with many routes |
| `missing-form-request` | Missing FormRequest | medium | advisory | ast | medium | laravel | controller | Yes (medium) | Yes (medium) | Yes (medium) | Suggests FormRequest for inline validation |
| `missing-list-virtualization` | Missing List Virtualization | high | advisory | regex | low | react | react-component, page | No (-) | Yes (high) | Yes (high) | Detects large-looking list renders without virtualization imports |
| `no-pagination-on-relationship` | No Pagination On Relationship | medium | advisory | ast | medium | laravel | model, service, controller | No (-) | No (-) | Yes (medium) | Detects potentially unbounded Eloquent relationship loads without paginate, limit, or take |
| `null-filtering-suggestion` | Null Filtering Suggestion | low | advisory | regex | low | laravel | global | No (-) | No (-) | Yes (low) | Suggests filtering null values from response arrays |
| `observer-heavy-logic` | Observer Heavy Logic | medium | advisory | ast | medium | laravel | observer | No (-) | Yes (medium) | Yes (medium) | Detects observers with large or side-effect-heavy hook methods |
| `service-provider-heavy-boot` | Heavy ServiceProvider Boot | high | advisory | regex | low | laravel | provider | No (-) | Yes (high) | Yes (high) | Detects DB, HTTP, or filesystem work inside ServiceProvider::boot |
| `unused-service-class` | Unused Service Class | low | advisory | ast | medium | laravel | service | Yes (low) | Yes (low) | Yes (low) | Detects service classes in app/Services that appear to be unused |
