# Best Practices Doctor

Best Practices Doctor is a local-first desktop analyzer for Laravel, PHP, React, Inertia, and Tailwind codebases. It combines AST-based inspection, architecture-aware rules, stable finding fingerprints, and evidence-focused remediation guidance.

## What it includes

- Python/FastAPI analysis backend
- React and Vite user interface
- Tauri desktop shell
- Laravel, PHP, React, Tailwind, accessibility, security, performance, and DevOps rules
- Startup, balanced, and strict analysis profiles
- Project architecture detection and context-aware rule calibration
- Incremental scanning, baselines, suppression management, SARIF, and PR-gate support
- Optional MCP bridge for agent-assisted workflows

## Requirements

- Windows 10 or newer
- macOS Catalina 10.15 or newer on Intel, or macOS 11 or newer on Apple Silicon, when running from source
- Node.js 20 LTS or newer
- Python 3.11 or newer
- Rust installed through [rustup](https://rustup.rs/) for the desktop application
- Xcode Command Line Tools on macOS for the desktop application (`xcode-select --install`)

These development tools are required when running or building from source. The prebuilt macOS GitHub artifact contains the packaged backend and does not require Node.js, Python, Rust, or Xcode. Rust and Xcode Command Line Tools are also optional in browser-only mode.

## Quick start

Clone the repository, then run these commands from its root:

```shell
npm run setup
npm start
```

`npm start` is the canonical application command. It performs a lightweight setup check and starts the Tauri desktop application. Tauri owns the frontend and Python backend lifecycle, including startup, authenticated backend discovery, and shutdown.

Windows users can also double-click `setup.cmd` once and then use `start.cmd`.
macOS users can use the same npm commands or run `bash scripts/macos/setup.sh` and `bash scripts/macos/start.sh` directly. See the [macOS guide](docs/macos.md) for installation, native builds, signing, and troubleshooting.

An Apple Silicon `.app` and `.dmg` are also built and tested by [GitHub Actions](https://github.com/HassanSalah120/Best-Practices-Doctor/actions). Open the latest successful **CI** run and download `best-practices-doctor-macos-arm64` from its **Artifacts** section. The artifact is tested on GitHub's current Apple Silicon runner; compatibility with older macOS releases is not yet certified. It is intended for testing and is ad-hoc signed rather than Apple-notarized; see the macOS guide for the first-open steps.

### Browser-only mode

```shell
npm run web
```

### Contributor mode with MCP

```powershell
npm run dev:full
```

Contributor mode starts the desktop app plus the MCP bridge and service monitoring. It is intentionally separate from normal application startup.
The combined `dev:full` monitor is currently a Windows contributor convenience. On macOS, run `npm start` and `npm run mcp` in separate Terminal tabs after `npm run setup:mcp`.

## Commands

| Command | Purpose |
|---|---|
| `npm start` | Start the desktop application |
| `npm run check` | Validate desktop startup prerequisites without launching |
| `npm run web` | Start the backend and browser UI without Tauri |
| `npm run dev:clean` | Free the app ports, then start the desktop application |
| `npm run dev:full` | Start desktop, backend discovery, MCP, and monitoring on Windows |
| `npm run setup` | Install Python, frontend, and Tauri dependencies for the current platform |
| `npm run setup:mcp` | Install normal dependencies plus the optional MCP bridge |
| `npm test` | Run backend and frontend tests |
| `npm run build` | Build the frontend and MCP bridge |
| `npm run build:mac` | Build a native macOS app and DMG on the current Mac |
| `npm run lint` | Run frontend linting |

## Project layout

```text
Best-Practices-Doctor/
├── backend/          Python analysis engine and FastAPI service
├── frontend/         React application
├── tauri/            Desktop shell and backend sidecar lifecycle
├── bpdoctor-mcp/     Optional MCP bridge
├── scripts/          Shared development tooling
└── docs/             Public architecture and analyzer documentation
```

The analysis pipeline is organized as:

```text
detect project → build facts → run rules → score → report
```

Raw AST facts, derived metrics, and rule findings are kept separate. Rules should emit evidence-backed hypotheses and prefer false negatives over conclusions that cannot be supported by local code structure.

## Development

Run individual checks from the repository root:

```shell
npm run test:backend
npm run test:frontend
npm run build:frontend
npm run build:mcp
```

The desktop shell starts the backend from `backend/.venv` during development. Production bundles use the packaged Python sidecar.

Runtime discovery files, MCP tokens, logs, local suppressions, generated reports, caches, and analyzer calibration notes are excluded from version control. `mcp-config-portable.json` is a token-free example; contributor mode writes usable runtime configuration under `.bpdoctor/runtime/`.

## API

Useful endpoints include:

- `GET /api/health`
- `POST /api/scan`
- `GET /api/scan/{job_id}`
- `GET /api/scan/{job_id}/events`
- `GET /api/rulesets`
- `GET /api/scan/{job_id}/project-map`
- `GET /api/scan/{job_id}/project-explainer`

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

Licensed under the [MIT License](LICENSE).
