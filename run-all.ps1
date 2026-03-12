param(
    [switch]$SkipSidecarBuild,
    [switch]$SkipMcp,
    [int]$DiscoveryWaitSeconds = 60,
    [int]$StatusIntervalSeconds = 2,
    [int]$BackendPort = 50401,
    [switch]$RestartMcp,
    [switch]$AutoRestart,
    [switch]$CleanPorts
)

$ErrorActionPreference = "Stop"

function Ensure-PortFree([int]$Port) {
    try {
        $conns = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -ne 0 }
        foreach ($c in $conns) {
            try {
                $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                if ($p) {
                    Write-Host "Freeing port $Port from $($p.ProcessName) (PID $($p.Id))..."
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 500
                }
            } catch {}
        }
    } catch {}
}

function Ensure-NpmInstall([string]$Dir) {
    if (-not (Test-Path (Join-Path $Dir "node_modules"))) {
        Write-Host "Installing npm dependencies in $Dir ..."
        npm --prefix $Dir install
    }
}

function Get-LatestDiscoveryFile() {
    $dirs = @(
        (Join-Path $HOME ".best-practices-doctor"),
        (Join-Path $env:APPDATA "com.bestpractices.doctor")
    )
    
    $latestFile = $null
    $latestTime = [datetime]::MinValue
    
    foreach ($dir in $dirs) {
        try {
            if (-not (Test-Path $dir)) { continue }
            $files = Get-ChildItem -Path $dir -Filter "bpd-discovery-*.json" -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if ($file.LastWriteTimeUtc -gt $latestTime) {
                    $latestTime = $file.LastWriteTimeUtc
                    $latestFile = $file.FullName
                }
            }
        } catch {}
    }
    
    return $latestFile
}

function Get-RunIdFromTauriLogs([string]$LogPath, [datetime]$StartTime, [int]$MaxWaitSeconds = 15) {
    $deadline = (Get-Date).AddSeconds($MaxWaitSeconds)
    $rx = [regex]"bpd-discovery-([0-9a-fA-F-]{36})\\.json"
    while ((Get-Date) -lt $deadline) {
        try {
            if (Test-Path $LogPath) {
                $raw = Get-Content -Path $LogPath -Raw -ErrorAction SilentlyContinue
                if ($raw) {
                    $m = $rx.Matches($raw) | Select-Object -Last 1
                    if ($m -and $m.Groups.Count -ge 2) {
                        return $m.Groups[1].Value
                    }
                }
            }
        } catch {}
        Start-Sleep -Milliseconds 250
    }
    return $null
}

function Get-DiscoveryFileForRunId([string]$RunId) {
    if (-not $RunId) { return $null }
    $dirs = @(
        (Join-Path $HOME ".best-practices-doctor"),
        (Join-Path $env:APPDATA "com.bestpractices.doctor")
    )
    foreach ($dir in $dirs) {
        try {
            if (-not (Test-Path $dir)) { continue }
            $p = Join-Path $dir ("bpd-discovery-$RunId.json")
            if (Test-Path $p) { return $p }
        } catch {}
    }
    return $null
}

function Read-JsonFile([string]$Path) {
    return (Get-Content -Raw -Path $Path -ErrorAction Stop | ConvertFrom-Json)
}

function Tail-FromOffset([string]$Path, [ref]$Offset) {
    try {
        if (-not (Test-Path $Path)) { return @() }
        $content = Get-Content -Path $Path -Tail 100 -ErrorAction SilentlyContinue
        $lines = $content -split "`r`n"
        $start = if ($Offset.Value -lt $lines.Count) { $Offset.Value } else { $lines.Count }
        $result = $lines[$start..($lines.Count-1)]
        $Offset.Value = $lines.Count
        return $result
    } catch {
        return @()
    }
}

function Test-BackendHealth([string]$Url) {
    try {
        $response = Invoke-RestMethod -Uri "$Url/api/health" -TimeoutSec 3 -ErrorAction Stop
        return $response.status -eq "ok"
    } catch {
        return $false
    }
}

function Extract-BackendFromLogs([string]$LogPath) {
    try {
        if (-not (Test-Path $LogPath)) { return $null }
        $content = Get-Content -Path $LogPath -Raw -ErrorAction SilentlyContinue
        if (-not $content) { return $null }
        
        # Look for Python fallback backend info
        if ($content -match "Backend info loaded \(python fallback\): Port (\d+), Token found") {
            $port = $matches[1]
            # Look for token in the same area
            if ($content -match "Uvicorn running on http://127\.0\.0\.1:(\d+)") {
                $port = $matches[1]
                return @{
                    Port = [int]$port
                    Host = "127.0.0.1"
                    Token = "python-fallback-token"  # We'll need to extract this differently
                }
            }
        }
        return $null
    } catch {
        return $null
    }
}

function Write-Status([string]$Message, [string]$Type = "INFO") {
    $icon = switch ($Type) {
        "SUCCESS" { "OK" }
        "ERROR" { "ERR" }
        "WARNING" { "WARN" }
        "INFO" { "INFO" }
        default { "LOG" }
    }
    Write-Host "[$icon] $Message"
}

# Main execution
Write-Status "Starting Best Practices Doctor with dynamic configuration..." "INFO"

$repoRoot = $PSScriptRoot
$npmCmd = "npm.cmd"

# Clean ports if requested
if ($CleanPorts) {
    Write-Status "Cleaning up common ports..." "INFO"
    Ensure-PortFree 1420
    Ensure-PortFree 8000
    Ensure-PortFree 27696
    Ensure-PortFree $BackendPort
}

# Ensure Vite port is free
Ensure-PortFree 1420
# Ensure configured backend port is free to avoid fallback to random/failed start.
Ensure-PortFree $BackendPort

# Install dependencies
Write-Status "Checking dependencies..." "INFO"
Ensure-NpmInstall (Join-Path $repoRoot "frontend")
Ensure-NpmInstall (Join-Path $repoRoot "bpdoctor-mcp")

# Start Tauri
Write-Status "Starting Tauri development server..." "INFO"
$tauriOut = Join-Path $repoRoot ".tmp-tauri-dev.out.log"
$tauriErr = Join-Path $repoRoot ".tmp-tauri-dev.err.log"
foreach ($p in @($tauriOut, $tauriErr)) { 
    if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue 
    }
}

$tauriArgs = @("--prefix", "tauri", "run", "tauri", "dev")
if ($SkipSidecarBuild) { $tauriArgs += @("--no-default-features") }

$scriptStartTime = Get-Date
$scriptStartTimeUtc = $scriptStartTime.ToUniversalTime()

# Default in dev: force python backend so the UI always uses the latest backend code
# without requiring rebuilding (and fighting Windows .exe locks).
if (-not $env:BPD_DEV_FORCE_PYTHON_BACKEND) { $env:BPD_DEV_FORCE_PYTHON_BACKEND = "1" }
# Force deterministic backend port so MCP settings remain stable across runs.
$env:BPD_PORT = "$BackendPort"
Write-Status "Forcing backend port via BPD_PORT=$BackendPort" "INFO"

$tauriProc = Start-Process -FilePath $npmCmd -ArgumentList $tauriArgs -WorkingDirectory $repoRoot -PassThru -NoNewWindow -RedirectStandardOutput $tauriOut -RedirectStandardError $tauriErr

if ($SkipMcp) {
    Write-Status "MCP start skipped by request" "WARNING"
    Write-Status "Tauri PID: $($tauriProc.Id)" "INFO"
    Write-Status "Frontend: http://localhost:1420" "SUCCESS"
    Write-Host "Logs:"
    Write-Host "  Get-Content -Wait $tauriOut"
    Write-Host "  Get-Content -Wait $tauriErr"
    
    $offOut = 0L
    $offErr = 0L
    while ($true) {
        try {
            if (-not (Get-Process -Id $tauriProc.Id -ErrorAction SilentlyContinue)) { 
                Write-Status "Tauri process ended" "INFO"
                break 
            }
        } catch { break }

        foreach ($l in (Tail-FromOffset $tauriOut ([ref]$offOut))) { 
            if ($l) { Write-Host "[tauri:out] $l" } 
        }
        foreach ($l in (Tail-FromOffset $tauriErr ([ref]$offErr))) { 
            if ($l) { Write-Host "[tauri:err] $l" } 
        }
        Start-Sleep -Seconds $StatusIntervalSeconds
    }
    exit 0
}

# Wait for backend discovery with enhanced monitoring
Write-Status "Waiting for backend discovery..." "INFO"
$deadline = (Get-Date).AddSeconds($DiscoveryWaitSeconds)
$discoveryPath = $null
$backendUrl = $null
$staleDiscoveryWarned = $false

# Prefer the discovery file for THIS Tauri run (avoids stale ports/tokens).
$runId = Get-RunIdFromTauriLogs $tauriOut $scriptStartTime 15
if ($runId) {
    Write-Status "Tauri run_id detected: $runId" "INFO"
} else {
    Write-Status "Tauri run_id not detected yet; falling back to newest discovery file" "WARNING"
}

while ((Get-Date) -lt $deadline) {
    if ($runId) {
        $discoveryPath = Get-DiscoveryFileForRunId $runId
    }
    if (-not $discoveryPath) {
        $discoveryPath = Get-LatestDiscoveryFile
    }
    $backendInfo = $null
    
    # Try discovery file first
    if ($discoveryPath) {
        try {
            # Only accept discovery files created after this script started
            $fileTime = (Get-Item $discoveryPath).LastWriteTimeUtc
            if ($fileTime -lt $scriptStartTimeUtc.AddSeconds(-5)) {
                if (-not $staleDiscoveryWarned) {
                    Write-Status "Ignoring old discovery file, waiting for new one..." "WARNING"
                    $staleDiscoveryWarned = $true
                }
            } else {
                $disc = Read-JsonFile $discoveryPath
                $backendInfo = @{
                    Host = if ($disc.host) { $disc.host } else { "127.0.0.1" }
                    Port = $disc.port
                    Token = $disc.token
                }
            }
        } catch {
            Write-Status "Discovery file found but invalid, retrying..." "WARNING"
        }
    }
    
    # If no discovery file, try extracting from Tauri logs (Python fallback)
    if (-not $backendInfo) {
        $backendInfo = Extract-BackendFromLogs $tauriOut
        if ($backendInfo) {
            Write-Status "Found Python fallback backend in logs" "INFO"
        }
    }

    # Final fallback: fixed port health probe (works even if discovery file is missing/stale).
    if (-not $backendInfo) {
        $fixedUrl = "http://127.0.0.1:$BackendPort"
        if (Test-BackendHealth $fixedUrl) {
            $backendInfo = @{
                Host = "127.0.0.1"
                Port = $BackendPort
                Token = ""
            }
            Write-Status "Backend detected via fixed-port health probe: $fixedUrl" "SUCCESS"
        }
    }
    
    if ($backendInfo) {
        $apiHost = $backendInfo.Host
        $apiPort = $backendInfo.Port
        $apiToken = $backendInfo.Token
        $backendUrl = "http://$apiHost`:$apiPort"
        
        # Test backend health
        if (Test-BackendHealth $backendUrl) {
            Write-Status "Backend discovered and healthy: $backendUrl" "SUCCESS"
            break
        } else {
            Write-Status "Backend found but not healthy yet, retrying..." "WARNING"
        }
    }
    
    # Show progress
    $elapsed = [math]::Round(($deadline - (Get-Date)).TotalSeconds)
    Write-Host "`rWaiting for backend... ${elapsed}s remaining" -NoNewline
    Start-Sleep -Milliseconds 500
}

if (-not $backendUrl) {
    Write-Host "`r"
    Write-Status "No healthy backend discovered within $DiscoveryWaitSeconds seconds" "ERROR"
    Write-Status "Check the Tauri logs for backend startup issues" "WARNING"
    Write-Status "Tauri PID: $($tauriProc.Id)" "INFO"
    Write-Host "Logs:"
    Write-Host "  Get-Content -Wait $tauriOut"
    Write-Host "  Get-Content -Watch $tauriErr"
    exit 1
}

# Start MCP
Write-Status "Starting MCP server..." "INFO"
$mcpOut = Join-Path $repoRoot ".tmp-bpdoctor-mcp.out.log"
$mcpErr = Join-Path $repoRoot ".tmp-bpdoctor-mcp.err.log"
foreach ($p in @($mcpOut, $mcpErr)) { 
    if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue 
    }
}

$mcpConfig = @{
    "mcpServers" = @{
        "bpdoctor" = @{
            "command" = "npm.cmd"
            "args" = @("run", "dev")
            "cwd" = "G:\Best-Practices-Doctor\bpdoctor-mcp"
            "env" = @{
                "BPDOCTOR_API_BASE_URL" = $backendUrl
                "BPDOCTOR_API_TOKEN" = $apiToken
                # If token is missing (fixed-port fallback mode), prevent MCP from using
                # stale token from old discovery files.
                "BPDOCTOR_DISABLE_DISCOVERY_TOKEN" = $(if ([string]::IsNullOrWhiteSpace($apiToken)) { "1" } else { "0" })
                "BPDOCTOR_WORKSPACE_ROOT" = $repoRoot
            }
        }
    }
}

$configPath = Join-Path $repoRoot "mcp-config-dynamic.json"
$mcpConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath
Write-Status "Dynamic MCP config created: $configPath" "SUCCESS"

$env:BPDOCTOR_API_BASE_URL = $backendUrl
$env:BPDOCTOR_API_TOKEN = $apiToken
$env:BPDOCTOR_DISABLE_DISCOVERY_TOKEN = $(if ([string]::IsNullOrWhiteSpace($apiToken)) { "1" } else { "0" })
$env:BPDOCTOR_WORKSPACE_ROOT = $repoRoot

$mcpProc = Start-Process -FilePath $npmCmd -ArgumentList @("run", "dev") -WorkingDirectory (Join-Path $repoRoot "bpdoctor-mcp") -PassThru -NoNewWindow -RedirectStandardOutput $mcpOut -RedirectStandardError $mcpErr

Write-Host "`n"
Write-Status "All services started successfully!" "SUCCESS"
Write-Host "Service Status:"
Write-Host "  Frontend (Vite): http://localhost:1420"
Write-Host "  Tauri App: Running (PID $($tauriProc.Id))"
Write-Host "  Backend API: $backendUrl"
Write-Host "  MCP Server: Running (PID $($mcpProc.Id))"
Write-Host "  MCP Config: $configPath"
Write-Host "`nLive Logs:"
Write-Host "  Get-Content -Watch $tauriOut"
Write-Host "  Get-Content -Watch $tauriErr"
Write-Host "  Get-Content -Watch $mcpOut"
Write-Host "  Get-Content -Watch $mcpErr"
Write-Host "`nIDE MCP Configuration:"
Write-Host "  Copy the contents of: $configPath"
Write-Host "  Or use these settings in your IDE:"
Write-Host "  - Command: npm.cmd run dev"
Write-Host "  - Working Directory: G:\Best-Practices-Doctor\bpdoctor-mcp"
Write-Host "  - Environment Variables: Set from discovery file"

# Monitor all services
$offTauriOut = 0L
$offTauriErr = 0L
$offMcpOut = 0L
$offMcpErr = 0L

while ($true) {
    $tauriAlive = $false
    $mcpAlive = $false
    
    try {
        if (Get-Process -Id $tauriProc.Id -ErrorAction SilentlyContinue) { $tauriAlive = $true }
    } catch {}
    
    try {
        if (Get-Process -Id $mcpProc.Id -ErrorAction SilentlyContinue) { $mcpAlive = $true }
    } catch {}
    
    if (-not $tauriAlive) {
        Write-Status "Tauri process ended, shutting down..." "WARNING"
        if ($mcpAlive) { 
            try { Stop-Process -Id $mcpProc.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
        break
    }
    
    if (-not $mcpAlive -and -not $SkipMcp) {
        Write-Status "MCP process ended, restarting..." "WARNING"
        if ($AutoRestart) {
            Start-Sleep -Seconds 2
            $mcpProc = Start-Process -FilePath $npmCmd -ArgumentList @("run", "dev") -WorkingDirectory (Join-Path $repoRoot "bpdoctor-mcp") -PassThru -NoNewWindow -RedirectStandardOutput $mcpOut -RedirectStandardError $mcpErr
            Write-Status "MCP restarted (PID $($mcpProc.Id))" "SUCCESS"
        }
    }
    
    foreach ($l in (Tail-FromOffset $tauriOut ([ref]$offTauriOut))) { 
        if ($l) { Write-Host "[tauri:out] $l" } 
    }
    foreach ($l in (Tail-FromOffset $tauriErr ([ref]$offTauriErr))) { 
        if ($l) { Write-Host "[tauri:err] $l" } 
    }
    foreach ($l in (Tail-FromOffset $mcpOut ([ref]$offMcpOut))) { 
        if ($l) { Write-Host "[mcp:out] $l" } 
    }
    foreach ($l in (Tail-FromOffset $mcpErr ([ref]$offMcpErr))) { 
        if ($l) { Write-Host "[mcp:err] $l" } 
    }
    
    Start-Sleep -Seconds $StatusIntervalSeconds
}

Write-Status "Shutdown complete" "INFO"
