#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INCLUDE_MCP=0
SKIP_NODE=0
SKIP_PYTHON=0

for arg in "$@"; do
  case "$arg" in
    --include-mcp) INCLUDE_MCP=1 ;;
    --skip-node) SKIP_NODE=1 ;;
    --skip-python) SKIP_PYTHON=1 ;;
    *) echo "[BPD] Unknown setup option: $arg" >&2; exit 2 ;;
  esac
done

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[BPD] $1 is required. $2" >&2
    exit 1
  fi
}

install_node_workspace() {
  workspace="$1"
  if [ -d "$REPO_ROOT/$workspace/node_modules" ]; then
    echo "[BPD] Node dependencies already installed in $workspace"
    return
  fi
  echo "[BPD] Installing Node dependencies in $workspace ..."
  npm --prefix "$REPO_ROOT/$workspace" ci
}

if [ "$(uname -s)" != "Darwin" ]; then
  echo "[BPD] This setup script is for macOS." >&2
  exit 1
fi

cd "$REPO_ROOT"
echo "[BPD] Preparing Best Practices Doctor for macOS ..."

if ! xcode-select -p >/dev/null 2>&1; then
  echo "[BPD] Warning: Xcode Command Line Tools are missing. They are required for desktop mode; run: xcode-select --install" >&2
fi

if [ "$SKIP_NODE" -eq 0 ]; then
  require_command node "Install Node.js 20 or newer (for example: brew install node@20)."
  require_command npm "Install Node.js 20 or newer."
  node -e 'const major=Number(process.versions.node.split(".")[0]); if (major < 20) { console.error("Node.js 20 or newer is required."); process.exit(1); }'
  install_node_workspace frontend
  install_node_workspace tauri
  if [ "$INCLUDE_MCP" -eq 1 ]; then
    install_node_workspace bpdoctor-mcp
  fi
fi

if [ "$SKIP_PYTHON" -eq 0 ]; then
  require_command python3 "Install Python 3.11 or newer (for example: brew install python@3.12)."
  python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 or newer is required"'

  VENV_DIR="$REPO_ROOT/backend/.venv"
  VENV_PYTHON="$VENV_DIR/bin/python"
  STAMP="$VENV_DIR/.bpd-setup-stamp"
  if [ ! -x "$VENV_PYTHON" ]; then
    echo "[BPD] Creating backend virtual environment ..."
    python3 -m venv "$VENV_DIR"
  fi

  NEEDS_INSTALL=0
  if [ ! -f "$STAMP" ] || [ "$REPO_ROOT/backend/requirements.txt" -nt "$STAMP" ] || [ "$REPO_ROOT/backend/pyproject.toml" -nt "$STAMP" ]; then
    NEEDS_INSTALL=1
  elif ! "$VENV_PYTHON" -c 'import fastapi, uvicorn, pydantic, tree_sitter' >/dev/null 2>&1; then
    NEEDS_INSTALL=1
  fi

  if [ "$NEEDS_INSTALL" -eq 1 ]; then
    echo "[BPD] Installing backend Python dependencies ..."
    "$VENV_PYTHON" -m ensurepip --upgrade
    "$VENV_PYTHON" -m pip install -r "$REPO_ROOT/backend/requirements.txt"
    date -u +'%Y-%m-%dT%H:%M:%SZ' > "$STAMP"
  else
    echo "[BPD] Backend Python dependencies already installed"
  fi
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "[BPD] Warning: Rust/Cargo is missing. Install it from https://rustup.rs before starting the desktop app."
fi

echo "[BPD] macOS setup complete. Run: npm start"
