param(
    [switch]$SkipSidecarBuild
)

$ErrorActionPreference = "Stop"

Import-Module "$PSScriptRoot\scripts\BestPracticesDoctor.psm1" -Force
Set-BPDRoot $PSScriptRoot

Push-Location (Get-BPDRoot)
try {
    $setupScript = Join-Path $PSScriptRoot "setup.ps1"
    if (Test-Path $setupScript) {
        Write-Host "Checking development dependencies ..."
        powershell -ExecutionPolicy Bypass -File $setupScript -Quiet
    }

    $venvScripts = Join-Path $PSScriptRoot "backend\.venv\Scripts"
    $venvPython = Join-Path $venvScripts "python.exe"
    if (Test-Path $venvPython) {
        $env:VIRTUAL_ENV = Join-Path $PSScriptRoot "backend\.venv"
        $env:PATH = "$venvScripts;$env:PATH"
    }

    # Kill any running sidecar to avoid file locks during build
    Stop-BPDSidecar

    if (-not $SkipSidecarBuild) {
        Write-Host "Building Python sidecar ..."
        powershell -ExecutionPolicy Bypass -File .\build_sidecar.ps1
    } else {
        Write-Host "Skipping sidecar build (requested)."
    }

    # Ensure dependencies are installed
    Install-NpmDependencies "frontend"
    Install-NpmDependencies "tauri"

    # Start Tauri dev (also starts Vite frontend via beforeDevCommand)
    Write-Host "Starting Tauri dev ..."
    npm --prefix tauri run tauri dev
}
finally {
    Pop-Location
}
