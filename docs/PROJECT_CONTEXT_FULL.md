# Best Practices Doctor: Full Project Context

This document is a high-signal, token-saving reference for contributors and AI agents.
It is intended to replace repeated deep re-reading of the whole repository for common tasks.

If you only read one file before making changes, read this one.

## 1) Project Purpose

Best Practices Doctor (BPD) is a local-first static analysis platform for Laravel/PHP and React/Inertia projects, with:

- FastAPI backend analysis engine
- React + Vite frontend
- Tauri desktop runtime and sidecar orchestration
- MCP bridge (`bpdoctor-mcp`) for agent workflows

The core goal is to produce actionable findings, calibrated by project context/profile, while minimizing false positives.

## 2) Architecture At A Glance

Runtime model:

1. Tauri app boots.
2. Tauri starts backend sidecar (or Python fallback in dev).
3. Backend writes a discovery file (`port + token`).
4. Frontend asks Tauri for backend info via `get_backend_info`.
5. Frontend calls FastAPI endpoints.
6. Optional MCP server calls the same backend API for agent loops.

Main surfaces:

- Backend: `backend/`
- Frontend: `frontend/`
- Tauri shell: `tauri/src-tauri/`
- MCP server: `bpdoctor-mcp/`

## 3) Repository Map (What Lives Where)

Top-level key folders:

- `backend/` Python analysis engine + API
- `frontend/` React UI
- `tauri/` desktop shell
- `bpdoctor-mcp/` MCP server tools
- `docs/` architecture and calibration docs
- `scripts/` PowerShell helpers

Backend subareas:

- `backend/main.py`: FastAPI app startup + ephemeral port
- `backend/api/routes.py`: all HTTP endpoints (scan, baseline, SARIF, fixes, history, incremental, cache)
- `backend/core/`: rule engine, scoring, job manager, baseline, suppression, context calibration
- `backend/core/pipeline/`: stage-based scan pipeline (critical refactor)
- `backend/analysis/`: facts + metrics extraction
- `backend/rules/`: rule implementations (`laravel`, `react`, `php`)
- `backend/schemas/`: Pydantic data contracts (`facts`, `finding`, `report`, etc.)
- `backend/rulesets/`: profile YAML files (`startup`, `balanced`, `strict`)

Frontend subareas:

- `frontend/src/App.tsx`: top-level state machine (`welcome -> progress -> report`)
- `frontend/src/screens/`: screen-level containers
- `frontend/src/components/report/`: report workspace panels
- `frontend/src/lib/api.ts`: all backend HTTP client calls + Tauri discovery integration

Tauri subareas:

- `tauri/src-tauri/src/lib.rs`: sidecar startup/discovery/fallback logic + commands
- `tauri/src-tauri/tauri.conf.json`: dev/build wiring and sidecar binary registration

MCP subareas:

- `bpdoctor-mcp/src/index.ts`: MCP tools (`start_scan`, `next_finding`, baseline/pr-gate helpers, repo snippet/search)

## 4) Scan Execution Flow (Backend)

### API entrypoint

- `POST /api/scan` in `backend/api/routes.py`
- creates job via `JobManager`
- starts async scan task

### Job orchestration

- `backend/core/job_manager.py`
- tracks status, progress, cancellation token, SSE subscribers

### Pipeline entrypoint

- `run_scan()` in `backend/api/routes.py` is now a thin adapter
- delegates to `run_scan_pipeline(...)` in:
  - `backend/core/pipeline/scan_pipeline.py`

### Pipeline stages

1. `detect_project`  
   File: `backend/core/pipeline/stages/detect_project.py`
2. `build_facts`  
   File: `backend/core/pipeline/stages/build_facts.py`
3. `run_rules`  
   File: `backend/core/pipeline/stages/run_rules.py`
4. `scoring`  
   File: `backend/core/pipeline/stages/scoring.py`
5. `reporting` (non-critical enrichments)  
   File: `backend/core/pipeline/stages/reporting.py`

Stage cache:

- `backend/core/pipeline/stage_cache.py`
- caches stage artifacts for `detect_project`, `build_facts`, `run_rules`, `scoring`
- cache stats are attached to `report.pipeline_cache` and `analysis_debug.pipeline_cache`

Error hierarchy:

- `backend/core/pipeline/errors.py`
- `ScanError`, `ProjectDetectionError`, `FactBuildError`, `RuleExecutionError`, `ScoringError`, `ReportingError`

Behavior:

- critical stages fail-fast
- non-critical reporting enrichments log warnings and continue

## 5) Facts, Findings, Reports

Primary contracts:

- `backend/schemas/facts.py`
- `backend/schemas/finding.py`
- `backend/schemas/report.py`
- `backend/schemas/project_type.py`

Important output behavior:

- Findings include metadata, confidence, score impact, fingerprint.
- Findings now also carry additive trust fields when available:
  - `why_flagged`
  - `why_not_ignored`
- Reports include category breakdown, action plan, file summaries, and debug context.
- Reports include additive triage outputs:
  - `triage_plan` (impact/risk/effort/context scoring)
  - `top_5_first`
  - `safe_to_defer`
- `analysis_debug.project_context` is a key explainability surface.

## 6) Rule Engine Model

Core file:

- `backend/core/rule_engine.py`

Registry model:

- Manual registry: `ALL_RULES` (authoritative compatibility surface)
- Auto-discovery: `discover_rules()` via module walk + subclass collection
- Runtime registry: `RUNTIME_RULES` (= manual-only source of truth)
- Diagnostics registry: `REGISTERED_RULES` (manual + discovered; used for drift diagnostics/dev visibility)

Execution pipeline (rule engine level):

1. load configured rules
2. run regex/AST/process rule paths
3. apply confidence filtering
4. apply suppression markers
5. dedupe overlap groups
6. apply differential mode filtering (optional)

Rule corpus snapshot:

- Total rules in registry: `235`
- Laravel rules: `100`
- React rules: `117`
- PHP rules: `18`

## 7) Ruleset Profiles

Ruleset files:

- `backend/rulesets/startup.yaml`
- `backend/rulesets/balanced.yaml`
- `backend/rulesets/strict.yaml`

Profile counts (current snapshot):

- `startup`: 195 total, 142 enabled
- `balanced`: 196 total, 194 enabled
- `strict`: 235 total, 235 enabled

Profile helpers:

- `backend/core/ruleset_profiles.py`

## 8) Context-Aware Calibration (Laravel/PHP)

Context matrix docs:

- `docs/laravel-profile-aware-analysis.md`
- `docs/laravel-context-matrix.md`
- machine-readable matrix:
  - `backend/rulesets/laravel_context_matrix.yaml`

Core calibration engine:

- `backend/core/context_profiles.py`

Design intent:

- detect architecture/business/capabilities
- calibrate severity/thresholds/enabled state based on context
- emit explainability metadata (`decision_profile`) on findings

## 9) False-Positive Guardrails (Important)

The project intentionally hardens several known FP patterns with tests:

- God-class should not flag service facades/coordinators:
  - `backend/tests/test_god_class_matching.py`
- Cache-control rule must recognize middleware patterns including:
  - class references
  - short middleware class names
  - dot-notation alias (`cache.control`)
  - tests in `backend/tests/test_security_batch_s2_rules.py`
- Weak password rule should not flag login-request password presence-only validation:
  - `backend/tests/test_security_batch_s1_rules.py`
- Registration rule should skip interface-only contracts and accept explicit `Registered` dispatch:
  - `backend/tests/test_security_hardening_rules.py`

When changing these rules, keep these guardrails green first.

## 10) API Surface (Backend Routes)

Primary route file:

- `backend/api/routes.py`

Current endpoint count (decorated routes): `40`

Main groups:

- Health/context:
  - `/api/health`
  - `/api/context/suggest`
- Scan lifecycle:
  - `/api/scan`, `/api/scan/{job_id}`, `/api/scan/{job_id}/events`, `/cancel`
- Baseline + PR gate + SARIF:
  - `/baseline`, `/baseline/save`, `/pr-gate`, `/sarif`
- File-level findings/content:
  - `/files`, `/file`, `/file/content`
- Finding intelligence:
  - `/scan/{job_id}/findings/{fingerprint}/explain`
  - `/scan/{job_id}/findings/{fingerprint}/suggest-fix`
  - `/scan/{job_id}/findings/{fingerprint}/status`
  - `/scan/{job_id}/triage`
- Ruleset profile controls:
  - `/ruleset`, `/rulesets`, `/rulesets/active`
- Suppressions, auto-fix, history, incremental, AST cache

Auth behavior:

- `backend/api/auth.py`
- bearer token expected when auth enabled
- token query fallback supported for SSE/EventSource
- local dev can disable auth (`BPD_REQUIRE_AUTH=false`)

## 11) Frontend Flow

Primary files:

- `frontend/src/App.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/screens/WelcomeScreen.tsx`
- `frontend/src/screens/ProgressScreen.tsx`
- `frontend/src/screens/ReportScreen.tsx`

View state:

- `welcome`
- `progress`
- `report`
- `ruleset`
- `advanced`

Important frontend behavior:

- API client initializes via Tauri `invoke("get_backend_info")`
- fetches with Bearer token
- SSE progress subscription via `/scan/{id}/events?token=...`

## 12) Tauri + Sidecar + Discovery

Core file:

- `tauri/src-tauri/src/lib.rs`

Behavior summary:

1. generate run-id
2. spawn sidecar `python-backend`
3. wait for discovery file `bpd-discovery-<run-id>.json`
4. load backend `port + token` into app state
5. expose `get_backend_info` command to frontend

Dev fallback:

- can force Python backend from source when sidecar is unreliable
- also auto-fallback path exists if sidecar discovery fails in dev mode

Config:

- `tauri/src-tauri/tauri.conf.json`

## 13) MCP Bridge (Agent Workflow)

Core files:

- `bpdoctor-mcp/README.md`
- `bpdoctor-mcp/src/index.ts`

Key tools:

- `bpdoctor.start_scan`
- `bpdoctor.wait_scan`
- `bpdoctor.next_finding`
- `bpdoctor.set_status`
- `bpdoctor.explain_finding`
- `bpdoctor.suggest_fix`
- `bpdoctor.group_fixes`
- `bpdoctor.compare_baseline`
- `bpdoctor.pr_gate`
- `repo.snippet`
- `repo.search`

State:

- `~/.bpdoctor-mcp/state.json`
- tracks active scan and per-finding status (`open`, `in_progress`, `fixed`, `skipped`)

## 14) Dev Commands

Common local startup:

1. `./dev.ps1`
2. advanced dev orchestration: `./run-all.ps1`
3. build sidecar: `./build_sidecar.ps1`

Backend:

- `cd backend && python main.py`
- tests: `cd backend && python -m pytest -q`

Frontend:

- `cd frontend && npm run dev`
- tests: `cd frontend && npm run test`
- build: `cd frontend && npm run build`

## 15) Test Strategy Reference

High-value targeted suites:

- Pipeline + discovery:
  - `backend/tests/test_scan_pipeline.py`
  - `backend/tests/test_rule_auto_discovery.py`
- FP-sensitive security/calibration:
  - `backend/tests/test_security_batch_s1_rules.py`
  - `backend/tests/test_security_batch_s2_rules.py`
  - `backend/tests/test_security_hardening_rules.py`
- God-class anti-false-positive:
  - `backend/tests/test_god_class_matching.py`

Note:

- There is a known local environment edge case with a permission-denied folder under `backend/tests/...` that can affect full-suite collection in some Windows setups.

## 16) Common Change Playbooks

### Add a new rule

1. Implement in `backend/rules/<family>/...`
2. Export in family `__init__.py`
3. Register in `ALL_RULES` (`backend/core/rule_engine.py`)
4. Add/adjust ruleset entries in profile YAMLs
5. Add unit tests:
   - valid / near-miss / invalid
6. If profile-aware, ensure `decision_profile` path stays consistent

### Refactor scan flow

1. Prefer adding/changing stage modules in `backend/core/pipeline/stages/`
2. Keep API route thin (`backend/api/routes.py`)
3. Use typed pipeline errors and context-rich logs
4. Keep report output contract stable

### Fix false positives

1. Reproduce with fixture or focused test
2. Add a regression test first
3. Prefer context-aware suppression/calibration over blunt disabling
4. Validate startup/balanced/strict behavior

## 17) Token-Saving Reading Order For AI/Contributors

For quick orientation, read in this exact order:

1. This file (`docs/PROJECT_CONTEXT_FULL.md`)
2. `backend/core/pipeline/scan_pipeline.py`
3. `backend/core/rule_engine.py`
4. `backend/api/routes.py`
5. `frontend/src/lib/api.ts`
6. `tauri/src-tauri/src/lib.rs`
7. `docs/laravel-context-matrix.md`

For FP/security tasks, add:

8. `backend/tests/test_security_batch_s1_rules.py`
9. `backend/tests/test_security_batch_s2_rules.py`
10. `backend/tests/test_god_class_matching.py`

## 18) Maintenance Rule For This Doc

Update this document whenever any of these change:

- backend scan pipeline stage boundaries
- rule registration/discovery model
- route surface in `backend/api/routes.py`
- profile ruleset strategy
- Tauri discovery/sidecar startup flow
- MCP state/tool contract

Keep this doc practical and implementation-close, not marketing-level.

## 19) Complete Rule Inventory (`backend/rules`)

Canonical inventory source:

- runtime registry: `backend/core/rule_engine.py` (`ALL_RULES`)
- rule family folders:
  - `backend/rules/laravel/`
  - `backend/rules/react/`
  - `backend/rules/php/`

Current registry snapshot:

- total rules: `235`
- laravel rules: `100`
- react rules: `117`
- php rules: `18`

What these families represent:

- `backend/rules/laravel/`: Laravel/PHP framework checks (security, routing, middleware, requests, Eloquent/data access, queue/jobs, migrations/schema, model exposure, API governance).
- `backend/rules/react/`: React/Inertia/UI checks (accessibility, hooks/state correctness, rendering/perf, SEO/semantics, Tailwind usage, client-side security).
- `backend/rules/php/`: Framework-agnostic code-quality and risk checks (complexity, coupling, SQL/code injection classes, unsafe eval/unserialize, dead code/testing gaps).

How to regenerate this section (authoritative source = runtime registry):

```powershell
@'
import sys
from pathlib import Path
from collections import defaultdict
sys.path.insert(0, str(Path('backend').resolve()))
from core.rule_engine import ALL_RULES

by = defaultdict(list)
for rid, cls in ALL_RULES.items():
    mod = cls.__module__
    if '.laravel.' in mod:
        by['laravel'].append(rid)
    elif '.react.' in mod:
        by['react'].append(rid)
    elif '.php.' in mod:
        by['php'].append(rid)
    else:
        by['other'].append(rid)

print('total', len(ALL_RULES))
for k in ['laravel', 'react', 'php', 'other']:
    print(k, len(by[k]))
'@ | python -
```

### Laravel Rule IDs (100)

```text
action-class-naming-consistency
action-class-suggestion
api-resource-usage
archive-upload-zip-slip-risk
asset-versioning-check
authorization-bypass-risk
authorization-missing-on-sensitive-reads
blade-queries
blade-xss-risk
broadcast-channel-authorization-missing
column-selection-suggestion
composer-dependency-below-secure-version
contract-suggestion
controller-business-logic
controller-index-filter-duplication
controller-inline-validation
controller-query-direct
controller-returning-view-in-api
cors-misconfiguration
csrf-exception-wildcard-risk
custom-exception-suggestion
debug-mode-exposure
destructive-migration-without-safety-guard
dto-suggestion
duplicate-route-definition
eager-loading
enum-suggestion
env-outside-config
error-pages-missing
fat-controller
hardcoded-secrets
heavy-logic-in-routes
host-header-poisoning-risk
idor-risk-missing-ownership-check
inertia-shared-props-eager-query
inertia-shared-props-payload-budget
inertia-shared-props-sensitive-data
insecure-deserialization
insecure-file-download-response
insecure-random-for-security
insecure-session-cookie-config
ioc-instead-of-new
job-http-call-missing-timeout
job-missing-idempotency-guard
job-missing-retry-policy
listener-shouldqueue-missing-for-io-bound-handler
mass-assignment-risk
massive-model
missing-api-resource
missing-auth-on-mutating-api-routes
missing-cache-for-reference-data
missing-csrf-token-verification
missing-foreign-key-in-migration
missing-form-request
missing-https-enforcement
missing-index-on-lookup-columns
missing-pagination
missing-throttle-on-auth-api-routes
model-cross-model-query
model-hidden-sensitive-attributes-missing
n-plus-one-risk
no-closure-routes
no-json-encode-in-controllers
no-log-debug-in-app
notification-shouldqueue-missing
npm-dependency-below-secure-version
null-filtering-suggestion
observer-heavy-logic
password-reset-token-hardening-missing
path-traversal-file-access
policy-coverage-on-mutations
public-api-versioning-missing
registration-missing-registered-event
repository-suggestion
sanctum-token-scope-missing
security-headers-baseline-missing
sensitive-data-logging
sensitive-model-appends-risk
sensitive-response-cache-control-missing
sensitive-route-rate-limit-missing
sensitive-routes-missing-verified-middleware
service-extraction
session-fixation-regenerate-missing
signed-routes-missing-signature-middleware
ssrf-risk-http-client
tenant-access-middleware-missing
tenant-scope-enforcement
transaction-required-for-multi-write
unsafe-csp-policy
unsafe-external-redirect
unsafe-file-upload
unused-service-class
upload-mime-extension-mismatch
upload-size-limit-missing
user-model-missing-must-verify-email
weak-password-policy-validation
webhook-replay-protection-missing
webhook-signature-missing
xml-xxe-risk
zip-bomb-risk
```

### React Rule IDs (117)

```text
accessible-authentication
anonymous-default-export-component
apg-accordion-disclosure-contract
apg-combobox-contract
apg-menu-button-contract
apg-tabs-keyboard-contract
autocomplete-missing
autoplay-media
avoid-props-to-state-copy
button-text-vague
canonical-missing-or-invalid
client-open-redirect-unvalidated-navigation
color-contrast-ratio
context-oversized-provider
context-provider-inline-value
controlled-uncontrolled-input-mismatch
crawlable-internal-navigation-required
cross-feature-import-boundary
css-color-only-state-indicator
css-fixed-layout-px
css-focus-outline-without-replacement
css-font-size-px
css-hover-only-interaction
css-spacing-px
dangerous-html-sink-without-sanitizer
derived-state-in-effect
dialog-focus-restore-missing
duplicate-key-source
effect-event-relay-smell
error-message-missing
exhaustive-deps-ast
focus-indicator-missing
focus-not-obscured
form-label-association
h1-singleton-violation
hardcoded-user-facing-strings
heading-order
hooks-in-conditional-or-loop
img-alt-missing
inertia-form-uses-fetch
inertia-internal-link-anchor
inertia-page-missing-head
inertia-reload-without-only
inline-api-logic
insecure-postmessage-origin-wildcard
interactive-accessible-name-required
interactive-element-a11y
jsonld-structured-data-invalid-or-mismatched
jsx-aria-attribute-format
language-attribute-missing
large-custom-hook
large-react-component
lazy-without-suspense
link-text-vague
long-page-no-toc
meta-description-missing-or-generic
missing-empty-state
missing-key-on-list-render
missing-loading-state
missing-props-type
missing-usecallback-for-event-handlers
missing-usememo-for-expensive-calc
modal-trap-focus
multiple-exported-react-components
no-dangerously-set-inner-html
no-direct-useeffect
no-inline-hooks
no-inline-services
no-inline-types
no-nested-components
outside-click-without-keyboard-fallback
page-indexability-conflict
page-title-missing
placeholder-as-label
postmessage-receiver-origin-not-verified
props-state-sync-effect-smell
query-key-instability
react-event-listener-cleanup-required
react-no-array-index-key
react-no-props-mutation
react-no-random-key
react-no-state-mutation
react-parent-child-spacing-overlap
react-project-structure-consistency
react-side-effects-in-render
react-timer-cleanup-required
react-useeffect-deps
react-useeffect-fetch-without-abort
redundant-entry
ref-access-during-render
ref-used-as-reactive-state
robots-directive-risk
route-shell-missing-error-boundary
safe-target-blank
semantic-wrapper-breakage
skip-link-missing
stale-closure-in-listener
stale-closure-in-timer
state-update-in-render
status-message-announcement
suspense-fallback-missing
tailwind-appearance-none-risk
tailwind-arbitrary-layout-size
tailwind-arbitrary-radius-shadow
tailwind-arbitrary-spacing
tailwind-arbitrary-text-size
tailwind-arbitrary-value-overuse
tailwind-motion-reduce-missing
token-storage-insecure-localstorage
touch-target-size
typescript-type-check
unsafe-async-handler-without-guard
usecallback-ast
usecallback-overuse
useeffect-cleanup-missing
usememo-ast
usememo-overuse
```

### PHP Rule IDs (18)

```text
circular-dependency
command-injection-risk
config-in-loop
dry-violation
god-class
high-complexity
high-coupling-class
long-method
low-coverage-files
prefer-imports
raw-sql
sql-injection-risk
static-helper-abuse
tests-missing
too-many-dependencies
unsafe-eval
unsafe-unserialize
unused-private-method
```

Notes:

- This list reflects the **active runtime rule registry** used by scans.
- The React folder contains some compatibility wrapper files from split-rule refactors; the registry IDs above are the canonical scan contract.
