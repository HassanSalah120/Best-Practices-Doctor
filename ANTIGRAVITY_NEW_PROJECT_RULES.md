# Anti Gravity Rules For New Projects

Use these rules as the IDE instruction file for greenfield projects.

They are written for modern Laravel + React/Inertia projects, but the general architecture and quality rules also apply to similar full-stack apps.

## Core Instruction

Generate code that is:

- secure by default
- thin at the edges
- explicit in business workflows
- easy to test
- low-noise in structure
- consistent without over-engineering

Do not generate code that is only "technically clean". Generate code that is practical, scalable, and easy for a team to maintain.

## Non-Negotiable Rules

- Prefer correctness over cleverness.
- Prefer explicitness over hidden magic.
- Keep changes small and focused.
- Do not introduce architecture layers unless they improve clarity, safety, reuse, or testability.
- Do not perform speculative refactors.
- Do not add abstractions only to satisfy style.
- Do not create code that would likely be flagged as a false positive by a practical senior review.

## Backend Rules

### Architecture

- Use this default backend layering:
  - Route
  - Controller
  - Action or Service
  - Model / Repository / Query object when needed
- Controllers handle HTTP orchestration only.
- Actions represent one business use case.
- Services coordinate broader workflows or multiple collaborators.
- Repositories are optional and should only exist for reused or complex data access.
- Models contain relationships, casts, scopes, and small model-specific domain helpers.

### Controllers

- Keep controllers thin.
- Controllers may do:
  - authorization
  - request validation
  - call actions/services
  - redirects/responses/resources
  - simple orchestration
- Controllers must not contain:
  - multi-step domain workflow logic
  - heavy branching business rules
  - query-heavy report building
  - multi-write persistence coordination
- Simple REST reads in controllers are acceptable if small and obvious.

### Routes

- Prefer controller routes over closure routes.
- Group routes by middleware, prefix, and name.
- Protect mutating routes with auth and authorization unless intentionally public.
- Use signed routes only for real public signed-link flows.
- Do not require signed middleware for ordinary internal auth/verified routes.

### Validation

- Use Form Requests for medium and large validation.
- Inline validation is acceptable for very small auth or onboarding flows.
- Keep validation close to the HTTP boundary unless it is reused.

### Actions and Services

- Use an Action when one class maps clearly to one use case.
- Use a Service when a class coordinates a larger domain workflow.
- Name classes by business behavior, not by vague utility language.
- Prefer constructor injection.
- Do not force an interface for every service.
- Use interfaces/contracts when:
  - there are multiple implementations
  - mocking/substitution is an intentional part of the design
  - the codebase already follows contract-based architecture consistently

### Queries and Persistence

- Prefer Eloquent for standard data access.
- Avoid raw SQL unless necessary and safe.
- Use eager loading where relation access would otherwise cause N+1.
- Paginate or limit large list endpoints.
- Use explicit column selection only when it materially improves performance and remains readable.
- Do not blindly add `select(...)` everywhere.

### Transactions

- Wrap real multi-write workflows in `DB::transaction(...)`.
- Keep external side effects outside the transaction when possible.
- Do not force transactions in thin orchestration methods that delegate to a transactional action/service.

### Authorization and Security

- Enforce policy/gate/middleware checks on sensitive reads and writes.
- Validate external redirects using trusted builders or explicit allowlists.
- Never trust request-driven external redirect targets without validation.
- Never use `env()` outside config files.
- Avoid unsafe eval, unserialize, command execution, and weak upload validation.
- Require verified middleware or equivalent where account-sensitive behavior needs it.

### Tenant Safety

- Only apply tenant boundaries when the project is clearly tenant-based.
- In tenant apps:
  - enforce tenant access middleware
  - keep tenant scoping explicit or centrally guaranteed
- In non-tenant apps:
  - do not treat `account`, `organization`, `portal`, or similar naming as tenant proof

### Enums

- Use enums for true state/type/role/priority fields.
- Do not create enums for:
  - labels
  - titles
  - names
  - column identifiers
  - arbitrary repeated strings without field context

### Exceptions

- Use domain-specific exceptions when the project already models domain failures that way.
- Do not add custom exceptions for trivial infrastructure cases just for ceremony.

### Jobs and Async Work

- Jobs that call external systems should usually include:
  - timeout
  - retry policy
  - idempotency guard when needed
- Use events/listeners when it makes boundaries clearer.
- Do not push all side effects into events by default.

## Frontend Rules

### React Basics

- Follow the Rules of Hooks strictly.
- Use stable keys for dynamic lists.
- Keep effect dependency arrays correct.
- Abort async effect work when cancellation matters.
- Prefer named components.

### State and Logic Placement

- Keep render logic in components.
- Move reusable or stateful business/UI logic into hooks.
- Move API or workflow-heavy logic out of leaf UI components.
- Do not treat every helper as a service.

### `useMemo`

- Use `useMemo` only for real render-time expensive calculations.
- Good candidates:
  - filter/sort/map chains on potentially large arrays
  - expensive derived data used during render
  - calculations passed to memoized children
- Do not use `useMemo` for:
  - plain `.ts` utility files
  - cheap math or string formatting
  - tiny metadata/tag rendering
  - trivial object/array operations

### `useCallback`

- Use `useCallback` only when it materially helps.
- Good candidates:
  - callback props passed into memoized custom children
  - handlers used in hook dependency arrays
  - expensive callback recreation in hot render paths
- Do not wrap every native DOM event handler in `useCallback`.

### Accessibility

- Inputs must have labels or equivalent accessible naming.
- Interactive controls must have accessible names.
- Visible text can satisfy accessible naming.
- Do not add redundant ARIA when visible text already covers it.

### Page Metadata

- Real route-entry pages should have title/head metadata.
- Utility modules and non-page files must not be treated as pages.
- Accept custom SEO/head wrappers if consistent.

## Frontend Structure Rules

Default to hybrid feature-plus-shared structure.

### Preferred Structure

```text
src/
  components/
    UI/
    shared/
  hooks/
    useAuth.ts
    useNav.ts
  pages/
    Portal/
      FeatureMatrix/
        Index.tsx
        components/
        utils/
      SeoSettings/
        Index.tsx
        components/
          utils/
  services/
  utils/
  utilities/
  types/
```

### Structure Rules

- Shared cross-cutting hooks may live in top-level `hooks/`.
- Shared generic utilities may live in `utils/` or `utilities/`.
- Feature-specific helpers may live close to the feature:
  - `pages/<Feature>/utils/`
  - `pages/<Feature>/components/utils/`
  - `components/<Area>/utils/`
- Co-located support files are acceptable:
  - `Component.types.ts`
  - `Page.utils.ts`
  - `Layout.utils.ts`
- Do not move feature-local helpers into global shared folders unless they are truly cross-feature.
- Do move files into shared space when multiple unrelated domains depend on them.

### Do Not Treat As Problems

- `useNav`, `useAuth`, `useTheme`, `useLocale` in top-level hooks
- React-specific helpers in feature-local component folders
- co-located `*.utils.ts` and `*.types.ts`
- hybrid shared-plus-feature layouts

### Do Treat As Problems

- random unsupported folder placement
- shared logic buried inside one feature and reused everywhere
- duplicate helpers/services across domains
- multiple conflicting structure patterns with no clear convention

## Complexity Rules

- Large page/shell components are acceptable when mostly compositional.
- Avoid oversized leaf components with mixed state, handlers, and rendering.
- Avoid long methods with real complexity, not just slightly high line count.
- Allow slightly long methods/pages when they are still low-complexity and easy to read.
- Avoid high coupling and circular concrete dependencies.
- Abstraction-only relationships should not be treated as architecture failures.

## Testing Rules

- New backend features need feature tests or integration coverage.
- Extracted business logic should get unit tests.
- Security-sensitive behavior should test safe and unsafe paths.
- New lint/analyzer rules must ship with:
  - one positive test
  - one false-positive/noise test
  - one intentional-architecture test

## What The IDE Should Avoid Generating

- fat controllers
- generic god services
- route closures for real app logic
- unnecessary repositories/contracts/actions
- premature `useMemo` and `useCallback`
- enum creation for labels or column names
- forcing refactors of already valid structure
- security “fixes” that ignore trusted validation already present

## Writing Style

- Prefer clear names.
- Prefer early returns.
- Prefer small composable units.
- Prefer practical architecture over pattern worship.
- Generate code that a senior engineer would keep, not immediately refactor.

## Final Instruction

When there is a choice between:

- strict theoretical purity
- practical, explicit, low-noise maintainability

choose practical, explicit, low-noise maintainability.
