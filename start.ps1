param(
    [ValidateSet("desktop", "web")]
    [string]$Mode = "desktop",
    [switch]$SkipSetup,
    [switch]$CleanPorts,
    [switch]$Check,
    [int]$BackendPort = 50401
)

$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot
Set-Location $repoRoot

function Require-Command([string]$Name, [string]$Hint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required. $Hint"
    }
}

Write-Host "[BPD] Preparing Best Practices Doctor ($Mode)..." -ForegroundColor Cyan

if (-not $SkipSetup -and -not $Check) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoRoot "setup.ps1") -Quiet
    if ($LASTEXITCODE -ne 0) {
        throw "Setup failed with exit code $LASTEXITCODE."
    }
}

if ($Mode -eq "web") {
    $webArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $repoRoot "run-web.ps1"),
        "-BackendPort", "$BackendPort",
        "-SkipInstall"
    )
    if ($CleanPorts) { $webArgs += "-CleanPorts" }
    & powershell @webArgs
    exit $LASTEXITCODE
}

Require-Command "node" "Install Node.js 20 LTS or newer."
Require-Command "npm" "Install Node.js 20 LTS or newer."
Require-Command "cargo" "Install Rust using rustup, or run 'npm run web'."

if ($Check) {
    $requiredPaths = @(
        "backend\.venv\Scripts\python.exe",
        "frontend\package.json",
        "tauri\package.json",
        "tauri\src-tauri\tauri.conf.json"
    )
    foreach ($relativePath in $requiredPaths) {
        if (-not (Test-Path (Join-Path $repoRoot $relativePath))) {
            throw "Required application path is missing: $relativePath"
        }
    }
    Write-Host "[BPD] Startup prerequisites are ready." -ForegroundColor Green
    exit 0
}

Import-Module (Join-Path $repoRoot "scripts\BestPracticesDoctor.psm1") -Force
Set-BPDRoot $repoRoot
if ($CleanPorts) {
    Stop-ProcessOnPort 1420
    Stop-ProcessOnPort $BackendPort
}

# Tauri owns the normal application lifecycle: it starts Vite, launches the
# Python backend, discovers its authenticated port, and stops it with the app.
$env:BPD_DEV_FORCE_PYTHON_BACKEND = "1"
$env:BPD_PORT = "$BackendPort"

Write-Host "[BPD] Starting desktop app..." -ForegroundColor Green
& npm --prefix tauri run tauri -- dev
exit $LASTEXITCODE
