#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODE="desktop"
SKIP_SETUP=0
CLEAN_PORTS=0
CHECK_ONLY=0
BACKEND_PORT=50401
FRONTEND_PORT=1420

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --skip-setup) SKIP_SETUP=1; shift ;;
    --clean-ports) CLEAN_PORTS=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    --backend-port) BACKEND_PORT="${2:-}"; shift 2 ;;
    *) echo "[BPD] Unknown start option: $1" >&2; exit 2 ;;
  esac
done

if [ "$MODE" != "desktop" ] && [ "$MODE" != "web" ]; then
  echo "[BPD] --mode must be desktop or web." >&2
  exit 2
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[BPD] $1 is required. $2" >&2
    exit 1
  fi
}

stop_port() {
  port="$1"
  pids="$(lsof -ti "tcp:$port" 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    echo "[BPD] Stopping process(es) on port $port: $pids"
    kill $pids 2>/dev/null || true
  fi
}

if [ "$(uname -s)" != "Darwin" ]; then
  echo "[BPD] This launcher is for macOS." >&2
  exit 1
fi

cd "$REPO_ROOT"
if [ "$SKIP_SETUP" -eq 0 ] && [ "$CHECK_ONLY" -eq 0 ]; then
  /bin/bash "$SCRIPT_DIR/setup.sh"
fi

require_command node "Install Node.js 20 or newer."
require_command npm "Install Node.js 20 or newer."
if [ "$MODE" = "desktop" ]; then
  require_command cargo "Install Rust from https://rustup.rs, or use `npm run web`."
  if ! xcode-select -p >/dev/null 2>&1; then
    echo "[BPD] Xcode Command Line Tools are required. Run: xcode-select --install" >&2
    exit 1
  fi
fi

VENV_PYTHON="$REPO_ROOT/backend/.venv/bin/python"
for required in "$VENV_PYTHON" "$REPO_ROOT/frontend/package.json" "$REPO_ROOT/tauri/package.json"; do
  if [ ! -e "$required" ]; then
    echo "[BPD] Required application path is missing: $required" >&2
    exit 1
  fi
done

if ! "$VENV_PYTHON" -c 'import fastapi, pydantic, tree_sitter, uvicorn' >/dev/null 2>&1; then
  echo "[BPD] Backend dependencies are incomplete. Run: npm run setup" >&2
  exit 1
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "[BPD] macOS startup prerequisites are ready."
  exit 0
fi

if [ "$CLEAN_PORTS" -eq 1 ]; then
  stop_port "$FRONTEND_PORT"
  stop_port "$BACKEND_PORT"
fi

if [ "$MODE" = "desktop" ]; then
  export BPD_DEV_FORCE_PYTHON_BACKEND=1
  export BPD_PORT="$BACKEND_PORT"
  echo "[BPD] Starting Best Practices Doctor desktop app on macOS ..."
  exec npm --prefix tauri run tauri -- dev --config src-tauri/tauri.macos-dev.conf.json
fi

BACKEND_OUT="$REPO_ROOT/.tmp-backend-web.out.log"
FRONTEND_OUT="$REPO_ROOT/.tmp-frontend-web.out.log"
rm -f "$BACKEND_OUT" "$FRONTEND_OUT"

BACKEND_PID=""
FRONTEND_PID=""
cleanup() {
  [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null || true
  [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

export BPD_PORT="$BACKEND_PORT"
export BPD_REQUIRE_AUTH=false
export VITE_BPDOCTOR_API_BASE_URL="http://127.0.0.1:$BACKEND_PORT/api"

(cd "$REPO_ROOT/backend" && exec "$VENV_PYTHON" main.py) >"$BACKEND_OUT" 2>&1 &
BACKEND_PID=$!

healthy=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$BACKEND_PORT/api/health" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 0.5
done
if [ "$healthy" -ne 1 ]; then
  echo "[BPD] Backend did not become healthy. See $BACKEND_OUT" >&2
  exit 1
fi

(cd "$REPO_ROOT/frontend" && exec npm run dev -- --host 127.0.0.1 --port "$FRONTEND_PORT") >"$FRONTEND_OUT" 2>&1 &
FRONTEND_PID=$!
echo "[BPD] Web mode ready: http://127.0.0.1:$FRONTEND_PORT"
echo "[BPD] Press Ctrl+C to stop. Logs: $BACKEND_OUT and $FRONTEND_OUT"

while kill -0 "$BACKEND_PID" 2>/dev/null && kill -0 "$FRONTEND_PID" 2>/dev/null; do
  sleep 2
done
echo "[BPD] A web-mode service stopped; shutting down." >&2
exit 1
