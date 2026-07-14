# Contributing to Best Practices Doctor

Thank you for contributing.

## Getting started

1. Fork and clone the repository.
2. Create a focused branch from `main`.
3. Install the prerequisites listed in the README.
4. Run:

```shell
npm run setup
npm start
```

The normal app command starts Tauri, which owns the frontend and backend lifecycle. Use `npm run dev:full` only when developing or testing the MCP integration.
The root npm commands dispatch to PowerShell on Windows and Bash on macOS. macOS contributors should read [docs/macos.md](docs/macos.md) before the first desktop build.

## Architecture principles

- Tree-sitter facts are the primary source of structural evidence.
- Raw facts, derived metrics, and findings remain separate.
- Rules do not mutate scanned projects.
- Findings require concrete evidence and stable fingerprints.
- Architecture conventions must be inferred from multiple signals, not exact paths alone.
- False-positive regressions should accompany detector changes.

## Adding or changing a rule

1. Add or reuse raw facts in `backend/analysis/`.
2. Add derived metrics only when raw facts are insufficient.
3. Implement the rule under `backend/rules/`.
4. Register public rule metadata and defaults.
5. Add positive, near-miss, and false-positive tests.
6. Update snapshots or public documentation when contracts change.

## Verification

Before opening a pull request, run:

```shell
npm test
npm run build
npm run lint
```

For backend-only work:

```shell
npm run test:backend
```

## Pull requests

- Keep changes scoped and explain the evidence behind analyzer behavior changes.
- Do not commit runtime tokens, local paths, generated reports, suppressions, caches, or logs.
- Update documentation when user-facing commands or contracts change.
- Never weaken tests merely to make a finding disappear.
- Include screenshots for visible UI changes.

Use clear commit messages such as:

```text
fix(rules): distinguish DTO fields from injected dependencies
```

## Reporting bugs and security issues

Use the GitHub issue templates for bugs and feature requests. Do not report vulnerabilities publicly; follow [SECURITY.md](SECURITY.md).
