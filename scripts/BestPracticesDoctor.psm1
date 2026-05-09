# BestPracticesDoctor.psm1 - Shared PowerShell Module
# Import with: Import-Module "$PSScriptRoot\scripts\BestPracticesDoctor.psm1" -Force

$script:RepoRoot = $null

function Set-BPDRoot([string]$Path) {
    $script:RepoRoot = Resolve-Path $Path
}

function Get-BPDRoot {
    if (-not $script:RepoRoot) {
        throw "Repo root not set. Call Set-BPDRoot first."
    }
    return $script:RepoRoot
}

#region Process Management

function Stop-ProcessOnPort([int]$Port) {
    try {
        $conns = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -ne 0 }
        foreach ($c in $conns) {
            try {
                $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                if ($p) {
                    Write-Host "Stopping process $($p.ProcessName) (PID $($p.Id)) on port $Port ..."
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    } catch {}
}

function Stop-BPDSidecar {
    Get-Process -Name "python-backend" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Test-ProcessAlive([int]$ProcessId) {
    try {
        return [bool](Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
    } catch {
        return $false
    }
}

#endregion

#region Dependency Management

function Test-NpmInstalled([string]$Dir) {
    return Test-Path (Join-Path $Dir "node_modules")
}

function Install-NpmDependencies([string]$Dir) {
    if (-not (Test-NpmInstalled $Dir)) {
        Write-Host "Installing npm dependencies in $Dir ..."
        npm --prefix $Dir install
    }
}

#endregion

#region Discovery File Handling

function Get-LatestDiscoveryFile {
    param(
        [string[]]$SearchDirs = @(
            (Join-Path $HOME ".best-practices-doctor"),
            (Join-Path $env:APPDATA "com.bestpractices.doctor")
        )
    )
    
    $latestFile = $null
    $latestTime = [datetime]::MinValue
    
    foreach ($dir in $SearchDirs) {
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

function Get-RunIdFromLogs([string]$LogPath, [datetime]$StartTime, [int]$MaxWaitSeconds = 15) {
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

function Read-DiscoveryFile([string]$Path) {
    return Get-Content -Raw -Path $Path -ErrorAction Stop | ConvertFrom-Json
}

#endregion

#region Logging

function Write-BPDStatus([string]$Message, [string]$Type = "INFO") {
    $icon = switch ($Type) {
        "SUCCESS" { "OK" }
        "ERROR" { "ERR" }
        "WARNING" { "WARN" }
        "INFO" { "INFO" }
        default { "LOG" }
    }
    Write-Host "[$icon] $Message"
}

function Get-LogPath([string]$Name) {
    $root = Get-BPDRoot
    return @{
        Out = Join-Path $root ".tmp-$Name.out.log"
        Err = Join-Path $root ".tmp-$Name.err.log"
    }
}

function Clear-LogFiles([string[]]$Names) {
    $root = Get-BPDRoot
    foreach ($name in $Names) {
        $paths = @(
            Join-Path $root ".tmp-$name.out.log"
            Join-Path $root ".tmp-$name.err.log"
        )
        foreach ($p in $paths) {
            if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
        }
    }
}

function Read-LogTail([string]$Path, [ref]$Offset, [int]$MaxLines = 100) {
    try {
        if (-not (Test-Path $Path)) { return @() }
        $content = Get-Content -Path $Path -Tail $MaxLines -ErrorAction SilentlyContinue
        $lines = $content -split "`r`n"
        $start = if ($Offset.Value -lt $lines.Count) { $Offset.Value } else { $lines.Count }
        $result = $lines[$start..($lines.Count-1)]
        $Offset.Value = $lines.Count
        return $result
    } catch {
        return @()
    }
}

# Legacy function for backward compatibility
function Tail-FromOffset([string]$Path, [ref]$Offset) {
    return Read-LogTail -Path $Path -Offset $Offset
}

#endregion

#region HTTP/Health Checks

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
        
        if ($content -match "Backend info loaded \(python fallback\): Port (\d+), Token found") {
            $port = $matches[1]
            if ($content -match "Uvicorn running on http://127\.0\.0\.1:(\d+)") {
                $port = $matches[1]
                return @{
                    Port = [int]$port
                    Host = "127.0.0.1"
                    Token = ""
                }
            }
        }
        return $null
    } catch {
        return $null
    }
}

#endregion

#region NPM Command Resolution

function Get-NpmCommand {
    $npmCmd = $null
    try { $npmCmd = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source } catch {}
    if (-not $npmCmd) {
        try { $npmCmd = (Get-Command npm -ErrorAction SilentlyContinue).Source } catch {}
    }
    if (-not $npmCmd) { $npmCmd = "npm.cmd" }
    return $npmCmd
}

#endregion

#region MCP Configuration

function New-MCPConfig([string]$BackendUrl, [string]$Token, [string]$RepoRoot) {
    return @{
        "mcpServers" = @{
            "bpdoctor" = @{
                "command" = "npm.cmd"
                "args" = @("run", "dev")
                "cwd" = (Join-Path $RepoRoot "bpdoctor-mcp")
                "env" = @{
                    "BPDOCTOR_API_BASE_URL" = $BackendUrl
                    "BPDOCTOR_API_TOKEN" = $Token
                    "BPDOCTOR_DISABLE_DISCOVERY_TOKEN" = $(if ([string]::IsNullOrWhiteSpace($Token)) { "1" } else { "0" })
                    "BPDOCTOR_WORKSPACE_ROOT" = $RepoRoot
                }
            }
        }
    }
}

function Save-MCPConfig([hashtable]$Config, [string]$Path) {
    $Config | ConvertTo-Json -Depth 10 | Set-Content -Path $Path
}

#endregion

Export-ModuleMember -Function @(
    "Set-BPDRoot", "Get-BPDRoot"
    "Stop-ProcessOnPort", "Stop-BPDSidecar", "Test-ProcessAlive"
    "Test-NpmInstalled", "Install-NpmDependencies"
    "Get-LatestDiscoveryFile", "Get-DiscoveryFileForRunId", "Get-RunIdFromLogs", "Read-DiscoveryFile"
    "Write-BPDStatus", "Get-LogPath", "Clear-LogFiles", "Read-LogTail", "Tail-FromOffset"
    "Test-BackendHealth", "Extract-BackendFromLogs"
    "Get-NpmCommand"
    "New-MCPConfig", "Save-MCPConfig"
)
