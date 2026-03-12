# Build configuration
$ErrorActionPreference = "Stop"

$SIDE_CAR_NAME = "python-backend"
$TARGET_TRIPLE = "x86_64-pc-windows-msvc"
$OUTPUT_NAME = "$SIDE_CAR_NAME-$TARGET_TRIPLE"

# Ensure we are in the backend directory
cd backend

# Ensure Python dependencies are present (one-command dev experience).
python -m pip install --user -r requirements.txt

# Install PyInstaller
python -m pip install --user pyinstaller

# Build the executable using the spec file (keeps hiddenimports/collect-all in one place).
# --clean avoids stale cached modules when iterating quickly.
python -m PyInstaller --noconfirm --clean python-backend.spec

# Create the binary directory in tauri/src-tauri if it doesn't exist
$BIN_DIR = "../tauri/src-tauri/binaries"
if (-not (Test-Path $BIN_DIR)) {
    New-Item -ItemType Directory -Path $BIN_DIR
}

# If an older sidecar is still running, the destination EXE can be locked on Windows.
# Kill the running sidecar process so we can overwrite the binary deterministically.
$DEST_EXE = Join-Path $BIN_DIR "$OUTPUT_NAME.exe"
$PROC_NAME = [System.IO.Path]::GetFileNameWithoutExtension($DEST_EXE)
Get-Process -Name $PROC_NAME -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 250

# Move and rename the executable to the tauri binaries folder
try {
    Move-Item "dist/$SIDE_CAR_NAME.exe" "$BIN_DIR/$OUTPUT_NAME.exe" -Force
} catch {
    Write-Host "Failed to overwrite the sidecar binary at $BIN_DIR/$OUTPUT_NAME.exe"
    Write-Host "Most likely it is still running (Windows locks .exe files)."
    Write-Host "Close the Tauri app / stop the sidecar process, then rerun build."
    Write-Host "If you just want to start the app without rebuilding the sidecar, run: .\\dev.ps1 -SkipSidecarBuild"
    throw
}

Write-Host "Sidecar built and moved to $BIN_DIR/$OUTPUT_NAME.exe"
