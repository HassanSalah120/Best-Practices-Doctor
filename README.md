# Best Practices Doctor

> 🔍 Local-first Laravel/PHP and Inertia/React code auditor with 100+ static analysis rules

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Node 20](https://img.shields.io/badge/node-20-green.svg)](https://nodejs.org/)
[![Rust 1.75](https://img.shields.io/badge/rust-1.75-orange.svg)](https://rust-lang.org/)

**Best Practices Doctor (BPD)** is a desktop application that performs comprehensive static analysis on Laravel/PHP and React/Inertia projects. It uses Tree-sitter for AST parsing and provides actionable recommendations for improving code quality, security, performance, and accessibility.

## ✨ Key Features

### Analysis Capabilities
- 🌳 **AST-first analysis** powered by Tree-sitter for accurate code understanding
- 🔧 **100+ configurable rules** across multiple categories
- 📊 **Scoring system** with category-based weights and trends
- 🏷️ **Rule profiles** (Startup, Balanced, Strict, Advanced) for different needs
- 🎯 **Smart filtering** with layer/category/rule selection
- 🔍 **TypeScript type checking** via `tsc --noEmit` integration

### User Experience
- 🖥️ **Desktop app** built with Tauri (React + TypeScript UI)
- 🔒 **Local-first** - your code never leaves your machine
- 🛠️ **Auto-fix suggestions** with preview and undo capability
- 📈 **Baseline comparison** - track progress over time
- 🚪 **PR Gate validation** - prevent bad code from merging
- 📊 **Visual reports** with charts and detailed findings

### Rule Categories
- 🏗️ **Architecture** - Layer violations, dependency management
- 🔒 **Security** - Secrets, XSS, CSRF, SQL injection detection
- ⚡ **Performance** - N+1 queries, missing caching, pagination
- ♿ **Accessibility** - WCAG 2.1 compliance, ARIA labels, contrast
- 📐 **Code Quality** - Complexity, duplication, maintainability
- 🎯 **Best Practices** - Framework-specific patterns

## 🚀 Quick Start

### Prerequisites

| Component | Version | Download |
|-----------|---------|----------|
| Python | 3.12+ | [python.org](https://www.python.org/downloads/) |
| Node.js | 20+ | [nodejs.org](https://nodejs.org/) |
| Rust | 1.75+ | [rust-lang.org](https://rust-lang.org/) |
| Git | Any | [git-scm.com](https://git-scm.com/) |

### Installation

```bash
# Clone the repository
git clone https://github.com/HassanSalah120/Best-Practices-Doctor.git
cd Best-Practices-Doctor

# Setup Python backend
cd backend
python -m venv venv

# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt

# Setup frontend
cd ../frontend
npm install

# Run development mode
cd ..
npm run dev
```

### Building Production App

```bash
# Build desktop application
cd tauri/src-tauri
cargo build --release
```

## 📚 Usage Guide

## 📘 Project Context Pack

For contributors and AI agents, use this token-saving deep reference first:

- [`docs/PROJECT_CONTEXT_FULL.md`](docs/PROJECT_CONTEXT_FULL.md)

It captures architecture, scan pipeline flow, rule engine behavior, profile calibration, API surface, Tauri sidecar discovery, MCP integration, and high-value test playbooks.

### Starting a Scan

1. **Launch the application**
2. **Select project path** - Browse to your Laravel/React project root
3. **Choose rule profile**:
   - 🚀 **Startup** - Essential rules only (fast)
   - ⚖️ **Balanced** - Recommended rules (default)
   - 🔒 **Strict** - All rules enabled (thorough)
   - ⚙️ **Advanced** - Select specific rules manually
4. **Click "Analyze Project"**

### Understanding Results

The scan results provide:

- **Overall Score** (0-100) - Project health rating
- **Category Scores** - Breakdown by category
- **Findings List** - Detailed issues with:
  - File path and line number
  - Severity level (Critical/High/Medium/Low)
  - Rule description
  - Why it matters
  - Suggested fix with code example

### Rule Profiles

| Profile | Rules | Duration | Best For |
|---------|-------|----------|----------|
| Startup | ~30 | 1-2 min | Quick checks, CI |
| Balanced | ~60 | 3-5 min | Daily development |
| Strict | ~100 | 5-10 min | Pre-release |
| Advanced | Custom | Varies | Specific needs |

### Auto-Fixes

Some rules support automatic fixes:

1. Select finding with 🔧 icon
2. Click "Preview Fix"
3. Review changes
4. Click "Apply Fix" or "Undo"

## 🏗️ Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interface                           │
│              (React 18 + TypeScript + Tailwind)                 │
└──────────────────────┬──────────────────────────────────────────┘
                       │ Tauri Bridge
┌──────────────────────▼──────────────────────────────────────────┐
│                        Tauri Runtime                            │
│                    (Rust + WebView2)                             │
└──────────────────────┬──────────────────────────────────────────┘
                       │ HTTP/WebSocket
┌──────────────────────▼──────────────────────────────────────────┐
│                      FastAPI Backend                            │
│         (Python + Tree-sitter + Rule Engine)                   │
└──────────────────────┬──────────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│   Parser    │ │   Rules     │ │   Facts     │
│ Tree-sitter │ │   Engine    │ │   Store     │
└─────────────┘ └─────────────┘ └─────────────┘
```

### Analysis Pipeline

1. **Discovery** - Identify project type (Laravel, React, PHP)
2. **Parsing** - Build AST with Tree-sitter
3. **Fact Extraction** - Gather code metrics and patterns
4. **Rule Execution** - Run applicable rules in parallel
5. **Finding Generation** - Create structured results
6. **Scoring** - Calculate weighted scores
7. **Reporting** - Format for UI display

### Rule Types

| Type | Execution | Use Case |
|------|-----------|----------|
| `ast` | Facts-based analysis | Structural patterns |
| `regex` | File content scan | Simple lint rules |
| `process` | External commands | tsc, npm audit |

## 📋 Rule Reference

### Laravel Rules

#### Security
- `hardcoded-secrets` - Detects API keys, passwords in code
- `sql-injection-risk` - Raw SQL without parameterization
- `missing-csrf-token-verification` - CSRF protection gaps
- `xss-risk` - Unescaped output in Blade

#### Performance
- `eager-loading-rule` - Missing `with()` calls
- `n-plus-one-risk` - Query loops
- `missing-cache-for-reference-data` - Cacheable data not cached
- `missing-pagination` - Unpaginated queries

#### Architecture
- `fat-controller` - Controllers with business logic
- `service-extraction` - Complex logic needing services
- `repository-suggestion` - Direct model queries
- `action-class-suggestion` - Form handlers needing actions

### React Rules

#### Performance
- `missing-usememo-for-expensive-calc` - Unmemoized calculations
- `missing-usecallback-for-event-handlers` - Unmemoized callbacks
- `useeffect-cleanup-missing` - Memory leak risks
- `context-provider-inline-value` - Unnecessary re-renders

#### Accessibility (WCAG 2.1)
- `color-contrast-ratio` - Low contrast text
- `img-alt-missing` - Images without alt text
- `form-label-association` - Unlabeled inputs
- `button-text-vague` - Unclear button labels
- `keyboard-navigation` - Missing keyboard support
- `focus-indicator-missing` - No visible focus
- `status-message-announcement` - Unannounced status changes

#### Code Quality
- `large-component` - Components over 350 lines
- `inline-logic` - JSX with complex logic
- `no-nested-components` - Nested function components
- `multiple-exported-components` - Multiple components per file

### TypeScript Rules

- `typescript-type-check` - Runs `tsc --noEmit` to find type errors
- `missing-props-type` - Untyped component props
- `no-inline-types` - Types defined inline
- `exhaustive-deps-ast` - Missing useEffect dependencies

## 🛠️ Development

### Project Structure

```
Best-Practices-Doctor/
├── backend/                    # Python FastAPI backend
│   ├── api/                    # REST API endpoints
│   │   ├── routes.py           # Main API routes
│   │   └── scan.py             # Scan orchestration
│   ├── core/                   # Core analysis engines
│   │   ├── rule_engine.py      # Rule execution
│   │   ├── ruleset.py          # Ruleset management
│   │   └── rule_metadata.py    # Rule definitions
│   ├── rules/                  # Analysis rules
│   │   ├── base.py             # Base rule class
│   │   ├── laravel/            # Laravel-specific rules
│   │   ├── react/              # React-specific rules
│   │   └── php/                # PHP generic rules
│   ├── schemas/                # Pydantic models
│   ├── tests/                  # pytest test suite
│   └── requirements.txt        # Python dependencies
├── frontend/                   # React + TypeScript frontend
│   ├── src/
│   │   ├── App.tsx             # Main application
│   │   ├── components/         # UI components
│   │   │   └── AdvancedProfileConfig.tsx
│   │   ├── screens/            # Page screens
│   │   │   └── WelcomeScreen.tsx
│   │   └── lib/                # Utilities
│   ├── package.json
│   └── vite.config.ts
├── tauri/                      # Tauri desktop shell
│   └── src-tauri/
│       ├── Cargo.toml
│       └── src/main.rs
├── rulesets/                   # YAML ruleset profiles
│   ├── default.yaml
│   ├── startup.yaml
│   ├── balanced.yaml
│   └── strict.yaml
└── README.md                   # This file
```

### Adding a New Rule

1. **Create rule file** in appropriate directory:

```python
# backend/rules/react/my_new_rule.py
from rules.base import Rule
from schemas.finding import Finding, Category, Severity

class MyNewRule(Rule):
    id = "my-new-rule"
    name = "My New Rule"
    description = "What this rule checks"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"  # or "ast"
    regex_file_extensions = [".tsx", ".jsx"]
    
    def analyze_regex(self, file_path, content, facts, metrics):
        findings = []
        # Your analysis logic here
        return findings
```

2. **Register in `__init__.py`**:

```python
from .my_new_rule import MyNewRuleRule
__all__ = [..., "MyNewRuleRule"]
```

3. **Add to rule engine** in `core/rule_engine.py`:

```python
ALL_RULES = {
    ...,
    "my-new-rule": MyNewRuleRule,
}
```

4. **Add metadata** in `core/rule_metadata.py`:

```python
RuleInfo(
    id="my-new-rule",
    name="My New Rule",
    description="...",
    category="react_best_practice",
    severity="medium",
    layer="frontend",
    tags=["react"],
)
```

5. **Write tests** in `backend/tests/`

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test

# E2E tests
cd frontend
npx playwright test
```

### Code Style

- **Python**: PEP 8, type hints required
- **TypeScript**: Strict mode enabled
- **Rust**: Clippy warnings as errors

## 📊 API Reference

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Start new scan |
| GET | `/api/scan/{id}` | Get scan results |
| GET | `/api/scan/{id}/events` | Stream scan events |
| GET | `/api/rulesets` | List rulesets |
| PUT | `/api/rulesets/active` | Set active ruleset |
| GET | `/api/rules/grouped` | Get grouped rules metadata |

### WebSocket Events

Connect to `/ws/scan/{id}/events` for real-time scan progress:

```json
{
  "type": "progress",
  "data": {
    "percent": 45,
    "current_rule": "fat-controller",
    "files_scanned": 120
  }
}
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Reporting Issues

Please include:
- BPD version
- Operating system
- Project type (Laravel/React/PHP)
- Sample code that triggers the issue
- Expected vs actual behavior

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [Tree-sitter](https://tree-sitter.github.io/) for fast parsing
- [Tauri](https://tauri.app/) for secure desktop apps
- [FastAPI](https://fastapi.tiangolo.com/) for the backend API
- [React](https://react.dev/) for the UI framework

---

Made with ❤️ for better code quality
