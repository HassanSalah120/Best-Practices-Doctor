# Changelog

## 1.0.0 (2026-07-14)

Initial public release.

### Features

- 344 static analysis rules across Laravel, React, PHP, and DevOps
- AST-based analysis using Tree-sitter for Laravel/PHP code
- Regex-based analysis for React/TypeScript
- Three ruleset profiles: startup (fast, P1), balanced (default), strict (everything)
- 16 category taxonomy with scoring per category (0-100)
- Inertia.js-aware scanning with architecture profile detection (MVC, Layered, Modular, API-first)
- Auto-fix suggestions with strategy and risk metadata
- MCP server for agent-driven scan workflows (31 tools)
- Triage scoring (impact × risk × effort × context)
- Fingerprint-stable findings with baseline diffing
- FastAPI backend with SSE live progress
- Cross-platform Tauri desktop shell

### Improvements (2026-07-03)

- **Rule registry consolidation**: eliminated 742 lines of duplicated `ALL_RULES` dict from `core/rule_engine.py`; single source of truth in `core/rule_registry.py`
- **Category expansion**: added 6 new categories (DATA_INTEGRITY, OBSERVABILITY, OPERATIONS, RELIABILITY, SEO, COMPATIBILITY); recategorized 52 rules into more appropriate groups
- **SRP removal**: removed dead `Category.SRP` (Single Responsibility Principle) — no rules mapped to it; cleaned up across 7 files (schema, scoring, tests, frontend)
- **Hardcoded path removal**: eliminated 16 hardcoded path fallbacks across 20 rule files (route file defaults, Inertia page paths, HandleInertiaRequests, model factory paths, etc.)
- **Inertia page resolution**: now checks both `Pages/` and `pages/` conventions, plus bare `js/Pages` and `js/pages`
- **Architecture heuristics**: detects `src/Services` and `src/Repositories` alongside `app/` variants
- **Legacy alias fix**: moved `sql-injection-raw-php` out of `ALL_RULES` into `LEGACY_RULE_ALIASES` (resolves at runtime)
- **Temp script cleanup**: removed 8 stale development helper scripts from `backend/`
- **BPD_RULES_CATALOG.md regenerated**: updated from 313 to 332 rules across 26 groups

### Known Issues

- `css_tailwind` rule updated for between-scale value handling (`text-[13px]` no longer flagged as it's an intentional design choice between scale values)
- `test_laravel_architecture_profiles.py` needs maintainer review for updated service detection heuristics
