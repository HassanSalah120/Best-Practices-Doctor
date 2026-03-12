# Best Practices Doctor

> 🔍 Local-first Laravel/PHP and Inertia/React code auditor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Node 20](https://img.shields.io/badge/node-20-green.svg)](https://nodejs.org/)

**Best Practices Doctor** is a Tauri desktop app that scans your local Laravel/PHP and React projects, analyzes code patterns using Tree-sitter AST parsing, and provides actionable recommendations for improving code quality.

## ✨ Features

- 🌳 **AST-first analysis** powered by Tree-sitter
- ⚙️ **Configurable rulesets** via YAML (startup, balanced, strict profiles)
- 🖥️ **Desktop app** with modern React + TypeScript UI
- 📊 **Scoring system** with category-based weights
- � **Local-first** - your code never leaves your machine
- 🛠️ **Auto-fix suggestions** with preview and undo
- 📈 **Baseline comparison** track progress over time
- 🚪 **PR Gate** validation before merging

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- Node.js 20+
- Rust 1.75+ (for Tauri)

### Development Setup

```bash
# Clone the repository
git clone <repo-url>
cd Best-Practices-Doctor

# Setup Python backend
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Setup frontend
cd ../frontend
npm install

# Run dev mode
cd ..
npm run dev
```

## 🏗️ Architecture

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Tauri App  │────▶│  FastAPI    │────▶│ Tree-sitter │
│  (React UI) │     │  Backend    │     │   Parser    │
└─────────────┘     └─────────────┘     └─────────────┘
                            │
                            ▼
                     ┌─────────────┐
                     │   Ruleset   │
                     │   Engine    │
                     └─────────────┘
```

## 📦 Project Structure

```text
.
├── backend/          # Python FastAPI + Tree-sitter analysis
│   ├── api/          # REST API endpoints
│   ├── core/         # Analysis engines
│   └── schemas/      # Data models
├── frontend/         # React + TypeScript + Vite
│   └── src/
│       ├── components/
│       ├── screens/
│       └── lib/
├── tauri/            # Tauri desktop shell
└── rulesets/         # YAML ruleset profiles
```

## 🧪 Tech Stack

| Layer       | Technology                          |
|-------------|-------------------------------------|
| Desktop     | Tauri (Rust)                        |
| Frontend    | React 18, TypeScript, Tailwind CSS  |
| Backend     | Python, FastAPI, Tree-sitter        |
| Testing     | pytest, Playwright                  |

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.
