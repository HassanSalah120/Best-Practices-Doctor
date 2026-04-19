# Laravel Context Matrix (Profiles + Toggles + Rule Behavior)

This document defines the connected Laravel/PHP context system that separates:

1. `framework support` (Laravel)
2. `project/business context` (SaaS, clinic/ERP, realtime/control, portal, etc.)
3. `architecture profile` (MVC/layered/modular/API-first)
4. `capabilities` (multi-tenant/SaaS/realtime/etc.)
5. `team expectations` (thin controllers/FormRequests/etc.)

Machine-readable source of truth:

- [backend/rulesets/laravel_context_matrix.yaml](g:/Best-Practices-Doctor/backend/rulesets/laravel_context_matrix.yaml)

## Context Resolution Priority

The resolver uses:

1. explicit user selection
2. detected codebase signal
3. default

Implemented in:

- [backend/core/context_profiles.py](g:/Best-Practices-Doctor/backend/core/context_profiles.py)

## Project Business Contexts

- `saas_platform`
- `internal_admin_system`
- `clinic_erp_management`
- `api_backend`
- `realtime_game_control_platform`
- `public_website_with_dashboard`
- `portal_based_business_app`
- `unknown`

## Primary Architecture Profiles

- `mvc` (Classic MVC)
- `layered` (controller -> action/service -> repository/model)
- `modular` (domain/module feature boundaries)
- `api-first` (API resource and response contract focus)

## Capability Toggles

- `multi_tenant`
- `saas`
- `realtime`
- `billing`
- `multi_role_portal`
- `queue_heavy`
- `mixed_public_dashboard`
- `public_marketing_site`
- `notifications_heavy`
- `external_integrations_heavy`

## Team Expectation Toggles

- `thin_controllers`
- `form_requests_expected`
- `services_actions_expected`
- `repositories_expected`
- `resources_expected`
- `dto_data_objects_preferred`

## Rule Behavior Table (Phase 1 Core)

| Rule ID | Baseline | Profile/Toggle Calibration |
|---|---|---|
| `controller-business-logic` | enabled, `medium` | stricter (`high`) in `layered/modular/api-first`; relaxed in `mvc`; stricter with `thin_controllers` |
| `service-extraction` | enabled, `medium` | `low` in `mvc`; `high` in `layered/modular`; stricter with `services_actions_expected` |
| `repository-suggestion` | enabled, `low` | off in `mvc`; stronger in `layered/modular`; stronger with `repositories_expected` |
| `tenant-scope-enforcement` | disabled | enabled only when `multi_tenant=true` |
| `tenant-access-middleware-missing` | disabled | enabled only when `multi_tenant=true` |
| `policy-coverage-on-mutations` | enabled, `medium` | `high` when `multi_role_portal` or `multi_tenant` |
| `authorization-missing-on-sensitive-reads` | enabled, `medium` | `high` when `multi_role_portal` |
| `missing-form-request` | enabled, `medium` | `high` when `form_requests_expected` |
| `missing-api-resource` | enabled, `medium` | `high` in `api-first` or when `resources_expected` |
| `controller-returning-view-in-api` | enabled, `medium` | `high` in `api-first` |
| `n-plus-one-risk` | enabled, `medium` | profile-calibrated confidence thresholds |
| `transaction-required-for-multi-write` | enabled, `medium` | `high` for `billing`, `realtime`, `queue_heavy` |

## Rule Behavior Table (Coverage Expansion)

| Rule ID | Baseline | Profile/Toggle Calibration |
|---|---|---|
| `missing-foreign-key-in-migration` | enabled in `strict/balanced`, `medium` | Laravel-only; emits from extracted migration facts rather than generic file scanning |
| `missing-index-on-lookup-columns` | enabled in `strict/balanced`, `medium` | Laravel-only; performance-oriented and fed by migration/index facts |
| `destructive-migration-without-safety-guard` | enabled in `strict`, off in `balanced/startup`, `high` | intentionally conservative because schema guard detection is still heuristic |
| `model-hidden-sensitive-attributes-missing` | enabled in `strict/balanced`, `high` | Laravel-only; driven by model `$hidden/$visible/$casts/$appends` extraction |
| `sensitive-model-appends-risk` | enabled in `strict/balanced`, `high` | Laravel-only; fires on sensitive-looking `$appends` entries |
| `notification-shouldqueue-missing` | enabled in `strict/balanced`, `medium` | stronger fit in repos with `notifications_heavy`; still emits when notification classes are explicit |
| `listener-shouldqueue-missing-for-io-bound-handler` | enabled in `strict/balanced`, `medium` | leans on `queue_heavy`, `notifications_heavy`, or explicit listener side-effect signals |
| `broadcast-channel-authorization-missing` | enabled in `strict/balanced`, `high` | strongest in repos with `realtime` capability or `routes/channels.php` |
| `observer-heavy-logic` | enabled in `strict/balanced`, `medium` | architecture-oriented; uses observer hook size and side-effect density rather than raw file size |
| `public-api-versioning-missing` | enabled in `strict/balanced`, `medium` | limited to public API routes; skips authenticated/internal SPA JSON flows |

## Explainability Expectations

Each profile-aware finding should expose:

- detected framework
- detected project/business context
- detected architecture profile
- profile confidence and confidence kind
- profile/capability/team toggles that changed rule behavior
- concise decision reason for emit/suppress

This is compatible with current `analysis_debug.project_context` and `metadata.decision_profile` output.
