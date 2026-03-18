# Anti Gravity Workspace Rules

Use this file as the coding rules/instructions source for IDE agents so generated code follows the same standards as Best Practices Doctor's current low-noise analysis.

## Goal

- Optimize for correctness, safety, clarity, and maintainability.
- Match the analyzer's current behavior, including its context-aware exceptions.
- Do not mechanically enforce patterns when the local architecture already uses a valid alternative.
- Prefer low-noise, high-signal decisions over stylistic churn.

## Priority Order

1. Security and data integrity
2. Correctness and framework conventions
3. Maintainability and separation of concerns
4. Performance where there is real render/query cost
5. Style consistency without unnecessary refactors

## General Rules

- Keep changes minimal and scoped to the real defect.
- Do not refactor healthy code just to satisfy a generic pattern.
- Preserve established architecture if it is consistent and intentional.
- Add or update tests for behavior changes.
- Prefer explicit code over hidden magic when security or correctness is involved.
- Do not introduce "fixes" for advisory-only concerns unless the code genuinely benefits.

## Laravel Rules

### Backend Writing Defaults

- Write backend code in layered form:
  - Controller for HTTP orchestration
  - Action or Service for business workflow
  - Repository or query object only when query complexity/reuse justifies it
  - Model for persistence concerns, casts, relationships, scopes, and small domain helpers
- Prefer constructor injection over manual instantiation.
- Prefer framework conventions first; add abstractions only when they improve clarity or reuse.
- Keep security checks, authorization, validation, and transaction boundaries explicit.
- Do not introduce architecture ceremony unless the use case is large enough to need it.

### Controllers

- Keep controllers thin.
- Controllers may orchestrate requests, authorization, validation, action/service calls, redirects, and response formatting.
- Do not flag controller code as business logic when it is mostly:
  - guard clauses
  - request validation
  - action/service delegation
  - response shaping
  - auth, verification, callback, or webhook flow handling
- Simple REST reads in controllers are acceptable when they are small and direct.
- Avoid direct query-heavy controller methods or large workflow logic in controllers.
- A good controller method usually looks like:
  - authorize if needed
  - validate request or use Form Request
  - call action/service
  - return response/redirect/resource
- Do not put multi-step domain workflows, persistence coordination, or complex branching in controllers.

### Routes

- Prefer controller routes over closure routes.
- Keep route files declarative.
- Group routes with the correct middleware, prefix, and naming conventions.
- Mutating routes should usually have auth/authorization protection.
- Webhook routes are allowed to differ when third-party constraints require it.

### Services and Actions

- Use services or actions for reusable business workflows.
- Single-method services are acceptable when the project intentionally uses service/facade/orchestrator patterns.
- Do not force Action extraction when the existing architecture is already consistent.
- Contract suggestions should only apply when there is no established interface/contract pattern already in place.
- Use an Action when:
  - there is one clear use case
  - the workflow is called from controllers/jobs/listeners/services
  - the name reads well as a business operation
- Use a Service when:
  - a workflow coordinates multiple collaborators
  - the logic is broader than a single use case
  - the class acts as a domain/application facade
- Keep actions/services focused and named around behavior, not generic helpers.

### Repositories and Queries

- Do not introduce repositories for trivial Eloquent reads/writes.
- Introduce repositories or dedicated query classes when:
  - query logic is reused
  - query composition is non-trivial
  - data access policy needs one place
- Prefer explicit query intent:
  - eager load when relation access would otherwise cause N+1
  - paginate/limit large controller reads
  - select explicit columns only when it clearly improves performance and does not reduce clarity
- Do not blindly add `select(...)` everywhere just to satisfy an optimization suggestion.

### Models

- Models may contain:
  - relationships
  - casts
  - scopes
  - accessors/mutators
  - small domain helpers tied directly to the entity
- Models should not become large workflow coordinators.
- Avoid large multi-responsibility models with mixed orchestration, reporting, persistence coordination, and side effects.
- Enum casts are good when a field is truly enum-shaped; do not invent enums for labels, column names, or loose string repetition.

### Validation

- Prefer Form Requests for substantial controller validation.
- Small auth/onboarding validation flows may stay inline.
- Do not force Form Requests for tiny request payloads or simple auth forms.
- Validation rules that are large, reused, or domain-important should move out of controllers.
- Keep error messages and validation intent explicit.

### Transactions

- Use `DB::transaction(...)` for real multi-write workflows.
- Do not flag thin orchestration methods that delegate the write workflow to an action/service which owns the transaction.
- Put the transaction around the smallest unit that must succeed atomically.
- Keep external side effects outside the critical transaction when possible:
  - emails
  - HTTP calls
  - notifications
  - broadcasts

### Contracts and DI

- Prefer constructor injection.
- Depend on interfaces/contracts when the project already uses that pattern or when multiple implementations are expected.
- Do not introduce interfaces for every class by default.
- If a concrete service already implements a project contract, keep using the established pattern rather than adding duplicate abstractions.

### Authorization and Tenant Safety

- Sensitive reads and writes should have policy/gate/middleware coverage.
- Use policy checks close to the controller boundary unless middleware already enforces the same guarantee.
- Only apply tenant-specific rules when the project clearly has tenant architecture.
- In tenant apps:
  - ensure tenant access middleware exists where needed
  - ensure tenant-scoped queries are explicit or enforced centrally
- In non-tenant apps:
  - do not treat words like `account`, `portal`, or `organization` as automatic tenant signals

### Redirect Safety

- External redirects must use trusted route/domain helpers or explicit validation.
- Treat these patterns as safe:
  - allowlisted hosts
  - trusted redirector/sanitizer helpers
  - explicit redirect validators
  - validated/sanitized redirect URL helper methods
- Do not flag redirects that use a URL already validated by:
  - `TrustedRedirector`
  - `ExternalRedirectValidator`
  - `validateAndSanitizeRedirectUrl(...)`
  - explicit allowlist constants such as `ALLOWED_EXTERNAL_HOSTS`
- Prefer redirect flows like:
  - build or resolve target from trusted helper
  - sanitize/validate against allowlist
  - redirect only after validation
- Do not hand-roll external redirects from request input without validation.

### Security

- Do not suggest signed middleware for ordinary internal auth/verified flows.
- Only require signed routes for true public signed-link behavior such as:
  - tracked links
  - invitations
  - one-click public actions
  - external redirect handlers
- Only enforce tenant protections when the project clearly has tenant architecture.
- Do not assume "account", "portal", or similar words mean multi-tenancy by themselves.
- Never use `env()` outside config files.
- Avoid raw SQL unless parameterized and necessary.
- Prefer policy/gate coverage on sensitive mutations and reads.
- For auth/security-sensitive work:
  - require verified middleware where appropriate
  - dispatch registration events where Laravel expects them
  - validate uploaded files explicitly
  - avoid unsafe eval, unserialize, and shell execution
  - set timeouts/retry policies/idempotency where async or HTTP work matters

### Domain and Persistence

- Avoid mass-assignment risk.
- Prefer eager loading where N+1 is likely.
- Cache stable reference data only when it is truly reference/config-like.
- Do not suggest caching for `Config::get(...)` or framework config reads.
- Do not suggest enums for:
  - column names
  - labels/titles/names
  - generic repeated strings without an enum-shaped field context
- Only suggest enums when a field clearly behaves like a stable state/type/role/priority set.
- Prefer domain-specific exceptions when the project already uses exception-based flow for domain errors.
- Do not create custom exceptions for tiny infrastructure-only cases just for ceremony.

### Jobs, Events, and Side Effects

- Jobs that call external systems should usually have:
  - retry policy
  - timeout
  - idempotency guard when duplicate execution is dangerous
- Use events/listeners to decouple side effects when it improves boundaries.
- Do not move everything to events by default; keep the flow understandable.

### Testing Backend Code

- Add feature tests for HTTP behavior changes.
- Add unit tests for extracted actions/services when business rules move there.
- For security-sensitive behavior, test the safe and unsafe path.
- For analyzer/rule work, always include:
  - a true positive test
  - a false-positive/noise suppression test
  - an intentional architecture test when applicable

### Backend Code Style

- Prefer clear names over short clever names.
- Prefer early returns for guards.
- Keep methods focused.
- Keep constructor dependency count reasonable, but allow orchestrators/facades when the role is intentional.
- Avoid static helper abuse for domain workflows.
- Keep logs meaningful; do not leave debug logging in app code.

## React and Inertia Rules

### Components and Hooks

- Follow the Rules of Hooks strictly.
- Use stable list keys; do not use array index keys for real dynamic lists.
- Keep effect dependencies correct.
- Abort effect-driven fetches when cancellation matters.
- Avoid inline API/business workflows in UI components when they belong in hooks/services.

### `useMemo` and `useCallback`

- Only use `useMemo` for real render-time expensive calculations in React components.
- Do not require `useMemo` for:
  - plain `.ts` or `.js` utility modules
  - hooks without render-time heavy computation
  - cheap math/string operations
  - small metadata/tag rendering
  - simple `Object.entries(...).map(...)` on tiny objects
- Only use `useCallback` when it materially helps:
  - callbacks passed into memoized custom children
  - handlers used as hook dependencies
  - genuinely complex or async callback props
- Do not force `useCallback` for ordinary native DOM handlers like:
  - `<button onClick={() => ...}>`
  - `<input onChange={(e) => ...}>`

### Page Metadata

- Actual route-entry Inertia pages should provide title/head metadata.
- Do not require page titles in:
  - utility modules
  - helper files
  - page-local leaf sections
  - non-component files inside page folders
- Accept custom SEO/head wrappers and `Helmet`-style title handling.

### Accessibility

- Form inputs need accessible labels.
- Interactive elements need accessible names.
- Visible text content may already satisfy the accessible-name requirement.
- Do not force redundant `aria-label` if the visible label is already clear.

## React Project Structure Rules

Use a hybrid feature-plus-shared structure by default unless the local project clearly follows something else.

### Acceptable Patterns

- Shared hooks in top-level `hooks/`
- Shared utilities in top-level `utils/` or `utilities/`
- Shared UI pieces in `components/`
- Feature-specific files colocated under:
  - `pages/<Feature>/...`
  - `features/<feature>/...`
  - `components/<Area>/...`
  - `layouts/...`
- Local helper folders like:
  - `components/.../utils/`
  - `pages/.../components/utils/`
- Co-located files like:
  - `Create.utils.ts`
  - `PatientPortalLayout.utils.ts`
  - `Button.types.ts`

### Do Not Treat These as Structural Problems

- Cross-cutting shared hooks like `useNav`, `useAuth`, `useTheme`, `useLocale`
- Feature-local helpers under component/page trees
- React-specific helper files that live close to the feature they support
- Intentional shared + feature mix in hybrid projects

### Do Treat These as Structural Problems

- Truly random placement with no discernible convention
- Shared files buried inside one feature and imported by unrelated features
- Multiple conflicting roots for the same support type without a clear pattern
- Duplicate helpers/services across domains that should be shared

## No Inline Types / No Inline Services

- Do not extract every local type/helper automatically.
- Inline types are acceptable when they are private to a hook, helper, or module.
- Pure local utilities inside a component are acceptable when they are tiny and UI-specific.
- Do not treat hooks as "inline services".
- Do extract logic when it becomes:
  - widely reused
  - domain-significant
  - API-facing
  - large enough to obscure the component

## Complexity and Size

- Large page/shell components can be acceptable if they are mostly composition.
- Do not flag components only because they are page containers under roughly 300 LOC.
- Do not flag methods only by raw line count when they are slightly over threshold but still low complexity.
- Do flag real complexity: branching, loops, query mix, dense workflow logic, coupling, or responsibility sprawl.

## Testing Rules

- Add tests for real behavioral changes.
- For analyzer or lint-like logic, always add:
  - one positive test
  - one negative/noise test
  - one intentional-architecture test when relevant

## Change Strategy

- If the analyzer and the code disagree, prefer fixing the analyzer when the code is already correct and intentional.
- Prefer reducing false positives over adding stylistic churn to application code.
- Advisory findings should not be treated like hard defects.

## Practical Default

When generating code in this repository, behave as if the active mode is:

- conservative on advisory refactors
- strict on security and data integrity
- context-aware on Laravel architecture
- context-aware on React structure
- tolerant of intentional project conventions

## Source of Truth

These rules are aligned with the current Best Practices Doctor profiles and analyzer behavior:

- [backend/ruleset.default.yaml](/g:/Best-Practices-Doctor/backend/ruleset.default.yaml)
- [backend/rulesets/startup.yaml](/g:/Best-Practices-Doctor/backend/rulesets/startup.yaml)
- [backend/rulesets/balanced.yaml](/g:/Best-Practices-Doctor/backend/rulesets/balanced.yaml)
- [backend/rulesets/strict.yaml](/g:/Best-Practices-Doctor/backend/rulesets/strict.yaml)
