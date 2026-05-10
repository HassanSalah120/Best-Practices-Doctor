param(
    [int]$BackendPort = 8000,
    [int]$FrontendPort = 1420,
    [switch]$SkipInstall,
    [switch]$CleanPorts
)

$ErrorActionPreference = "Stop"

function Write-WebStatus([string]$Message, [string]$Type = "INFO") {
    $prefix = switch ($Type) {
        "SUCCESS" { "OK" }
        "WARNING" { "WARN" }
        "ERROR" { "ERR" }
        default { "INFO" }
    }
    Write-Host "[$prefix] $Message"
}

function Ensure-PortFree([int]$Port) {
    try {
        $conns = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -ne 0 }
        foreach ($conn in $conns) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) {
                Write-WebStatus "Freeing port $Port from $($proc.ProcessName) (PID $($proc.Id))..." "WARNING"
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

function Test-BackendHealth([string]$Url) {
    try {
        $response = Invoke-RestMethod -Uri "$Url/api/health" -TimeoutSec 2 -ErrorAction Stop
        return $response.status -eq "ok"
    } catch {
        return $false
    }
}

$repoRoot = $PSScriptRoot
$backendDir = Join-Path $repoRoot "backend"
$frontendDir = Join-Path $repoRoot "frontend"
$backendOut = Join-Path $repoRoot ".tmp-backend-web.out.log"
$backendErr = Join-Path $repoRoot ".tmp-backend-web.err.log"
$frontendOut = Join-Path $repoRoot ".tmp-frontend-web.out.log"
$frontendErr = Join-Path $repoRoot ".tmp-frontend-web.err.log"

if (-not $SkipInstall) {
    powershell -ExecutionPolicy Bypass -File (Join-Path $repoRoot "setup.ps1") -Quiet
}

if ($CleanPorts) {
    Ensure-PortFree $BackendPort
    Ensure-PortFree $FrontendPort
}

$venvScripts = Join-Path $backendDir ".venv\Scripts"
$python = Join-Path $venvScripts "python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}
else {
    $env:VIRTUAL_ENV = Join-Path $backendDir ".venv"
    $env:PATH = "$venvScripts;$env:PATH"
}

$npmCmd = "npm.cmd"
try {
    $resolvedNpm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($resolvedNpm) {
        $npmCmd = $resolvedNpm.Source
    } else {
        $resolvedNpm = Get-Command npm -ErrorAction SilentlyContinue
        if ($resolvedNpm) { $npmCmd = $resolvedNpm.Source }
    }
} catch {}

foreach ($log in @($backendOut, $backendErr, $frontendOut, $frontendErr)) {
    if (Test-Path $log) { Remove-Item $log -Force -ErrorAction SilentlyContinue }
}

$env:BPD_PORT = "$BackendPort"
$env:BPD_REQUIRE_AUTH = "false"
$env:VITE_BPDOCTOR_API_BASE_URL = "http://127.0.0.1:$BackendPort/api"

Write-WebStatus "Starting backend on http://127.0.0.1:$BackendPort ..."
$backendProc = Start-Process -FilePath $python -ArgumentList @("main.py") -WorkingDirectory $backendDir -PassThru -NoNewWindow -RedirectStandardOutput $backendOut -RedirectStandardError $backendErr

$backendUrl = "http://127.0.0.1:$BackendPort"
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    if (Test-BackendHealth $backendUrl) { break }
    Start-Sleep -Milliseconds 500
}

if (-not (Test-BackendHealth $backendUrl)) {
    Write-WebStatus "Backend did not become healthy. See $backendErr" "ERROR"
    try { Stop-Process -Id $backendProc.Id -Force -ErrorAction SilentlyContinue } catch {}
    exit 1
}

Write-WebStatus "Starting frontend on http://127.0.0.1:$FrontendPort ..." "SUCCESS"
$frontendProc = Start-Process -FilePath $npmCmd -ArgumentList @("run", "dev", "--", "--host", "127.0.0.1", "--port", "$FrontendPort") -WorkingDirectory $frontendDir -PassThru -NoNewWindow -RedirectStandardOutput $frontendOut -RedirectStandardError $frontendErr

Write-Host ""
Write-WebStatus "Web mode ready" "SUCCESS"
Write-Host "  App:     http://127.0.0.1:$FrontendPort"
Write-Host "  Backend: $backendUrl"
Write-Host "  Browser mode: paste an absolute local project path in the app; folder browsing is desktop-only."
Write-Host "  Logs:"
Write-Host "    Get-Content -Wait $backendOut"
Write-Host "    Get-Content -Wait $backendErr"
Write-Host "    Get-Content -Wait $frontendOut"
Write-Host "    Get-Content -Wait $frontendErr"
Write-Host ""
Write-Host "Press Ctrl+C to stop."

try {
    while ($true) {
        $backendAlive = Get-Process -Id $backendProc.Id -ErrorAction SilentlyContinue
        $frontendAlive = Get-Process -Id $frontendProc.Id -ErrorAction SilentlyContinue
        if (-not $backendAlive -or -not $frontendAlive) {
            Write-WebStatus "A service stopped; shutting down." "WARNING"
            break
        }
        Start-Sleep -Seconds 2
    }
}
finally {
    try { Stop-Process -Id $backendProc.Id -Force -ErrorAction SilentlyContinue } catch {}
    try { Stop-Process -Id $frontendProc.Id -Force -ErrorAction SilentlyContinue } catch {}
    Write-WebStatus "Web mode stopped" "INFO"
}
