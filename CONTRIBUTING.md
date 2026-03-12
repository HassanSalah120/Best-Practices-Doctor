# Contributing to Best Practices Doctor

First off, thanks for taking the time to contribute! 🎉

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Pull Requests](#pull-requests)
- [Development Guidelines](#development-guidelines)
  - [Architecture Principles](#architecture-principles)
  - [Adding Rules](#adding-rules)
  - [Testing](#testing)
- [Style Guides](#style-guides)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/Best-Practices-Doctor.git`
3. Create a branch: `git checkout -b feature/my-feature`

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- Rust toolchain (for Tauri)

### Install Dependencies

```powershell
# Python backend
cd backend
python -m pip install -r requirements.txt
cd ..

# Node frontend & tauri
cd frontend && npm install
cd ..\tauri && npm install
cd ..
```

### Run the App

```powershell
# Full dev mode
.\dev.ps1

# Without rebuilding sidecar
.\dev.ps1 -SkipSidecarBuild

# With MCP helper
.\run-all.ps1
```

## How to Contribute

### Reporting Bugs

Before creating a bug report:

1. Check if the issue already exists
2. Use the latest version
3. Collect information about the bug

Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md) and include:

- Clear title and description
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, app version, project type)
- Logs or report JSON (remove sensitive data)

### Suggesting Features

Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md) and explain:

- The problem you are solving
- Your proposed solution
- Alternatives you have considered

### Pull Requests

1. Update your fork to the latest `main`
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

**PR Checklist:**

- [ ] Branch is up to date with `main`
- [ ] Tests pass (`cd backend && python -m pytest -q`)
- [ ] Frontend builds (`cd frontend && npm run build`)
- [ ] Code follows style guidelines
- [ ] Documentation updated if needed
- [ ] No hardcoded paths or secrets

## Development Guidelines

### Architecture Principles

We follow strict architectural rules:

| Principle       | Description                                                     |
|-----------------|-----------------------------------------------------------------|
| **AST-First** | Tree-sitter is the primary parser. Regex is fallback only. |
| **Separation** | Raw Facts ≠ Derived Metrics ≠ Findings |
| **Rules Read-Only** | Rules read Facts/Metrics only. Never parse source directly. |
| **Stable IDs** | Findings use fingerprints for stable identification across refactors. |

### Adding Rules

1. **Add Facts** in `backend/analysis/facts_builder.py`
   - Use Tree-sitter to extract raw facts
   - Example: class names, method signatures

2. **Add Metrics** (if needed) in `backend/analysis/metrics_analyzer.py`
   - Compute derived metrics from facts
   - Example: complexity scores

3. **Implement Rule** in `backend/rules/`
   - Read from Facts/Metrics only
   - Return findings with fingerprints

4. **Register Rule** in `backend/core/rule_engine.py`

5. **Add Tests** in `backend/tests/`

6. **Update snapshots** if report output changes

### Testing

```powershell
# Backend tests
cd backend
python -m pytest -q

# Frontend build check
cd frontend
npm run build

# Linting
cd frontend
npm run lint
```

## Style Guides

### Python

- Use type hints
- Follow PEP 8
- Max line length: 100
- Use f-strings

### TypeScript/React

- Use functional components
- Props interfaces required
- Prefer `const` over `let`
- Use early returns

### Commit Messages

```text
type(scope): subject

body (optional)

footer (optional)
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:

```text
feat(rules): add god class detection

Implement rule to detect classes with too many responsibilities
based on method count and accessor patterns.
```

---

Questions? Open a [Discussion](https://github.com/hassansalah120/Best-Practices-Doctor/discussions) or reach out to maintainers.