param(
    [switch]$SkipPython,
    [switch]$SkipNode,
    [switch]$IncludeMcp,
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

function Write-SetupStatus([string]$Message, [string]$Type = "INFO") {
    if ($Quiet -and $Type -eq "INFO") { return }
    $prefix = switch ($Type) {
        "SUCCESS" { "OK" }
        "WARNING" { "WARN" }
        "ERROR" { "ERR" }
        default { "INFO" }
    }
    Write-Host "[$prefix] $Message"
}

function Require-Command([string]$Name, [string]$InstallHint) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "$Name was not found. $InstallHint"
    }
    return $cmd.Source
}

function Invoke-NativeChecked([string]$FilePath, [string[]]$Arguments, [string]$Label) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

function Repair-PipIfNeeded([string]$PythonPath) {
    & $PythonPath -m pip --version *> $null
    if ($LASTEXITCODE -eq 0) { return }

    Reset-VenvPip $PythonPath

    & $PythonPath -m pip --version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "pip is still not importable after ensurepip repair."
    }
}

function Reset-VenvPip([string]$PythonPath) {
    Write-SetupStatus "Backend virtualenv pip is not importable; reinstalling pip with ensurepip ..." "WARNING"
    $sitePackages = & $PythonPath -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
    if ($LASTEXITCODE -ne 0 -or -not $sitePackages) {
        throw "Could not locate virtualenv site-packages for pip repair."
    }

    $sitePackagesPath = [System.IO.Path]::GetFullPath([string]$sitePackages)
    $venvRoot = [System.IO.Path]::GetFullPath((Join-Path (Split-Path (Split-Path $PythonPath -Parent) -Parent) ""))
    if (-not $sitePackagesPath.StartsWith($venvRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to repair pip outside backend virtualenv: $sitePackagesPath"
    }

    $pipPackage = Join-Path $sitePackagesPath "pip"
    if (Test-Path $pipPackage) {
        Remove-Item -LiteralPath $pipPackage -Recurse -Force
    }
    Get-ChildItem -Path $sitePackagesPath -Directory -Filter "pip-*.dist-info" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }

    & $PythonPath -m ensurepip --upgrade
    if ($LASTEXITCODE -ne 0) {
        throw "pip repair failed with exit code $LASTEXITCODE."
    }
}

function Invoke-PipInstallChecked([string]$PythonPath, [string[]]$Arguments, [string]$Label) {
    & $PythonPath -m pip @Arguments
    if ($LASTEXITCODE -eq 0) { return }

    Write-SetupStatus "$Label failed; repairing pip and retrying once ..." "WARNING"
    Reset-VenvPip $PythonPath

    & $PythonPath -m pip @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

function Install-NpmWorkspace([string]$Dir) {
    $packageJson = Join-Path $Dir "package.json"
    if (-not (Test-Path $packageJson)) { return }

    $nodeModules = Join-Path $Dir "node_modules"
    if (Test-Path $nodeModules) {
        Write-SetupStatus "Node dependencies already installed in $Dir"
        return
    }

    Write-SetupStatus "Installing Node dependencies in $Dir ..."
    Invoke-NativeChecked "npm" @("--prefix", $Dir, "install") "npm install in $Dir"
}

$repoRoot = $PSScriptRoot
Set-Location $repoRoot

Write-SetupStatus "Preparing Best Practices Doctor development environment..."

if (-not $SkipNode) {
    $null = Require-Command "node" "Install Node.js 20 LTS or newer from https://nodejs.org/"
    $null = Require-Command "npm" "Install Node.js 20 LTS or newer from https://nodejs.org/"

    Install-NpmWorkspace (Join-Path $repoRoot "frontend")
    Install-NpmWorkspace (Join-Path $repoRoot "tauri")
    if ($IncludeMcp) {
        Install-NpmWorkspace (Join-Path $repoRoot "bpdoctor-mcp")
    }
}

if (-not $SkipPython) {
    $null = Require-Command "python" "Install Python 3.11 or newer and ensure it is on PATH."

    $backendDir = Join-Path $repoRoot "backend"
    $venvDir = Join-Path $backendDir ".venv"
    $venvPython = Join-Path $venvDir "Scripts\python.exe"
    $stampPath = Join-Path $venvDir ".bpd-setup-stamp"
    $pyprojectPath = Join-Path $backendDir "pyproject.toml"
    $requirementsPath = Join-Path $backendDir "requirements.txt"

    if (-not (Test-Path $venvPython)) {
        Write-SetupStatus "Creating backend virtual environment at backend\.venv ..."
        Invoke-NativeChecked "python" @("-m", "venv", $venvDir) "python venv creation"
    }

    $needsPythonInstall = -not (Test-Path $stampPath)
    if (-not $needsPythonInstall -and (Test-Path $pyprojectPath)) {
        $needsPythonInstall = (Get-Item $pyprojectPath).LastWriteTimeUtc -gt (Get-Item $stampPath).LastWriteTimeUtc
    }
    if (-not $needsPythonInstall -and (Test-Path $requirementsPath)) {
        $needsPythonInstall = (Get-Item $requirementsPath).LastWriteTimeUtc -gt (Get-Item $stampPath).LastWriteTimeUtc
    }
    if (-not $needsPythonInstall) {
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & $venvPython -c "import fastapi, uvicorn, pydantic, tree_sitter" *> $null
        $probeExitCode = $LASTEXITCODE
        $ErrorActionPreference = $previousErrorActionPreference
        if ($probeExitCode -ne 0) {
            $needsPythonInstall = $true
        }
    }

    if ($needsPythonInstall) {
        Write-SetupStatus "Installing backend Python dependencies ..."
        Repair-PipIfNeeded $venvPython
        Write-SetupStatus "Using virtualenv pip as-is to avoid partial self-upgrade corruption"
        Invoke-PipInstallChecked $venvPython @("install", "-r", $requirementsPath) "backend dependency install"
        Set-Content -Path $stampPath -Value (Get-Date).ToUniversalTime().ToString("o")
    }
    else {
        Write-SetupStatus "Backend Python dependencies already installed"
    }
}

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    Write-SetupStatus "Rust/Cargo was not found. Install Rust from https://rustup.rs/ before building the desktop app." "WARNING"
}

Write-SetupStatus "Setup complete. Run npm start from the repository root." "SUCCESS"
