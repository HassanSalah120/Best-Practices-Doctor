param(
    [switch]$SkipSidecarBuild
)

$ErrorActionPreference = "Stop"

Import-Module "$PSScriptRoot\scripts\BestPracticesDoctor.psm1" -Force
Set-BPDRoot $PSScriptRoot

Push-Location (Get-BPDRoot)
try {
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
