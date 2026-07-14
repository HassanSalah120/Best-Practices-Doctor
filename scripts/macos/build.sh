#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "[BPD] macOS bundles must be built on macOS." >&2
  exit 1
fi

/bin/bash "$SCRIPT_DIR/setup.sh"
cd "$REPO_ROOT"

TARGET_TRIPLE="$(rustc -vV | awk '/^host:/ { print $2 }')"
case "$TARGET_TRIPLE" in
  aarch64-apple-darwin|x86_64-apple-darwin) ;;
  *) echo "[BPD] Unsupported macOS Rust target: $TARGET_TRIPLE" >&2; exit 1 ;;
esac

PYTHON="$REPO_ROOT/backend/.venv/bin/python"
echo "[BPD] Building Python sidecar for $TARGET_TRIPLE ..."
"$PYTHON" -m pip install pyinstaller
(cd "$REPO_ROOT/backend" && "$PYTHON" -m PyInstaller --noconfirm --clean python-backend.spec)

SIDECAR="$REPO_ROOT/backend/dist/python-backend"
DESTINATION="$REPO_ROOT/tauri/src-tauri/binaries/python-backend-$TARGET_TRIPLE"
if [ ! -f "$SIDECAR" ]; then
  echo "[BPD] PyInstaller did not produce $SIDECAR" >&2
  exit 1
fi
mkdir -p "$(dirname "$DESTINATION")"
cp "$SIDECAR" "$DESTINATION"
chmod +x "$DESTINATION"

echo "[BPD] Building native .app and .dmg bundles ..."
if [ -n "${APPLE_SIGNING_IDENTITY:-}" ]; then
  npm --prefix tauri run tauri -- build --target "$TARGET_TRIPLE" --bundles app,dmg
else
  echo "[BPD] No Apple signing identity configured; using an ad-hoc identity for this local build."
  npm --prefix tauri run tauri -- build --target "$TARGET_TRIPLE" --config src-tauri/tauri.macos-build.conf.json --bundles app,dmg
fi
echo "[BPD] macOS build complete under tauri/src-tauri/target/$TARGET_TRIPLE/release/bundle"
