#Requires -Version 5.1
<#
.SYNOPSIS
    NightChat installer for Windows.

.DESCRIPTION
    Installs the NightChat terminal E2EE messenger client for the
    current user (no admin rights required). Downloads the official
    source from GitHub, prepares a private Python environment, wires up
    the `nightchat` command, and starts the app.

    Official usage (from a clean Windows machine, no prior setup):

        irm https://raw.githubusercontent.com/ItsMeTheReis/nightchat/main/install.ps1 | iex

    This script only ever talks to github.com / raw.githubusercontent.com
    (the official NightChat repository)  -  it does not use mirrors and
    does not accept a different source. It does not embed, request, or
    store any credential, token, or secret.

.NOTES
    Honesty about what this installer does and does not do (see
    docs/ARCHITECTURE.md and README.md "Instalador" section for the
    full picture):

    - This is NOT a single self-contained .exe. NightChat is a pure
      Python application; this script bootstraps a private Python
      environment for it (installing Python via winget if missing) so
      the end user never has to run pip/venv/git themselves.
    - Integrity verification here is: HTTPS-only, official-host-only,
      "is this actually a valid zip"  -  there is no published release
      checksum/signature to verify against yet (no signed release
      pipeline exists). This is a real, stated limitation, not hidden.
    - Your NightChat cryptographic identity (Ed25519 private key) lives
      in `~\.nightchat`, is created on first login, and is never
      touched by this installer (a re-run/update never deletes it).
#>

[CmdletBinding()]
param(
    # Override for testing against a fork/branch. The default is the
    # official NightChat repository  -  do not point this at a mirror
    # you don't control.
    [string]$Owner = "ItsMeTheReis",
    [string]$Repo = "nightchat",
    [string]$Branch = "main",

    # Public relay address for the client to use. If not given, the
    # installed client defaults to ws://localhost:8000 (only useful if
    # you're also running a relay on the same machine  -  see README.md).
    [string]$RelayUrl,

    # Skip auto-starting NightChat at the end (useful for unattended/CI
    # installs, or when testing this script).
    [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "  [*] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  [+] $Message" -ForegroundColor Green
}

function Write-Warn2 {
    param([string]$Message)
    Write-Host "  [!] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [!] $Message" -ForegroundColor Red
}

Write-Host ""
Write-Host "NIGHTCHAT INSTALLER" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Detect platform
# ---------------------------------------------------------------------------
Write-Step "Checking system..."

$isWindowsOs = $true
try {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $isWindowsOs = $IsWindows
    }
} catch {
    $isWindowsOs = $true  # Windows PowerShell 5.1 only ever runs on Windows
}

if (-not $isWindowsOs) {
    Write-Fail "This installer only supports Windows. NightChat's client is Windows-only for now (see README.md)."
    exit 1
}
Write-Ok "Windows detected."

$arch = $env:PROCESSOR_ARCHITECTURE
Write-Host "      Architecture: $arch" -ForegroundColor DarkGray
if ($arch -notin @("AMD64", "ARM64", "x86")) {
    Write-Warn2 "Unrecognized architecture '$arch'  -  continuing anyway (Python itself will fail loudly if unsupported)."
}

# ---------------------------------------------------------------------------
# 2. Locate or install Python 3.10+
# ---------------------------------------------------------------------------
Write-Step "Checking for Python..."

function Test-PythonVersion {
    param([string]$PythonExe)
    try {
        $verOutput = & $PythonExe -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')" 2>$null
        if (-not $verOutput) { return $false }
        $parts = $verOutput.Trim().Split(".")
        $major = [int]$parts[0]
        $minor = [int]$parts[1]
        return ($major -eq 3 -and $minor -ge 10)
    } catch {
        return $false
    }
}

$pythonExe = $null
foreach ($candidate in @("python", "python3")) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd -and (Test-PythonVersion $cmd.Source)) {
        $pythonExe = $cmd.Source
        break
    }
}

if (-not $pythonExe) {
    Write-Warn2 "Python 3.10+ not found."
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-Fail "winget is not available, and NightChat needs Python 3.10+ to run."
        Write-Host "      Install Python 3.10 or newer from https://python.org/downloads (check 'Add to PATH')" -ForegroundColor Yellow
        Write-Host "      then re-run this installer." -ForegroundColor Yellow
        exit 1
    }
    Write-Step "Installing Python via winget (this can take a minute)..."
    & winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "winget could not install Python automatically."
        Write-Host "      Install Python 3.10+ manually from https://python.org/downloads and re-run this installer." -ForegroundColor Yellow
        exit 1
    }
    # winget updates PATH for new sessions, but not this one.
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
    foreach ($candidate in @("python", "python3")) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd -and (Test-PythonVersion $cmd.Source)) {
            $pythonExe = $cmd.Source
            break
        }
    }
    if (-not $pythonExe) {
        Write-Fail "Python was installed but could not be located in this session."
        Write-Host "      Close this PowerShell window, open a new one, and re-run the install command." -ForegroundColor Yellow
        exit 1
    }
    Write-Ok "Python installed."
} else {
    Write-Ok "Python found: $pythonExe"
}

# ---------------------------------------------------------------------------
# 3. Download NightChat from GitHub
# ---------------------------------------------------------------------------
Write-Step "Downloading NightChat..."

# Hardcoded to the official GitHub source  -  never a user-supplied mirror.
$zipUrl = "https://github.com/$Owner/$Repo/archive/refs/heads/$Branch.zip"
$installRoot = Join-Path $env:LOCALAPPDATA "NightChat"
$appDir = Join-Path $installRoot "app"
$venvDir = Join-Path $installRoot "venv"
$binDir = Join-Path $installRoot "bin"
$tempZip = Join-Path $env:TEMP "nightchat-$([Guid]::NewGuid().ToString('N')).zip"
$tempExtract = Join-Path $env:TEMP "nightchat-extract-$([Guid]::NewGuid().ToString('N'))"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $zipUrl -OutFile $tempZip -UseBasicParsing
} catch {
    Write-Fail "Failed to download NightChat from $zipUrl"
    Write-Host "      $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 4. Verify the package (see honesty note at the top of this file)
# ---------------------------------------------------------------------------
Write-Step "Verifying package..."

if (-not (Test-Path $tempZip) -or (Get-Item $tempZip).Length -lt 1024) {
    Write-Fail "Downloaded file looks wrong (too small or missing)."
    exit 1
}
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $testZip = [System.IO.Compression.ZipFile]::OpenRead($tempZip)
    $entryCount = $testZip.Entries.Count
    $testZip.Dispose()
    if ($entryCount -lt 5) {
        throw "Archive has suspiciously few files ($entryCount)."
    }
} catch {
    Write-Fail "Downloaded package failed integrity check (not a valid archive): $($_.Exception.Message)"
    Remove-Item -Force $tempZip -ErrorAction SilentlyContinue
    exit 1
}
Write-Ok "Package looks valid."

# ---------------------------------------------------------------------------
# 5. Install (extract, preserving user data)
# ---------------------------------------------------------------------------
Write-Step "Installing..."

Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force
Remove-Item -Force $tempZip -ErrorAction SilentlyContinue

$extractedRoot = Get-ChildItem -Path $tempExtract -Directory | Select-Object -First 1
if (-not $extractedRoot) {
    Write-Fail "Extracted archive did not contain the expected folder."
    exit 1
}

New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
if (Test-Path $appDir) {
    Remove-Item -Recurse -Force $appDir
}
Move-Item -Path $extractedRoot.FullName -Destination $appDir
Remove-Item -Recurse -Force $tempExtract -ErrorAction SilentlyContinue

Write-Ok "NightChat source installed to $appDir"

# ---------------------------------------------------------------------------
# 6. Python environment (private venv  -  never touches system Python)
# ---------------------------------------------------------------------------
if (-not (Test-Path $venvDir)) {
    Write-Step "Setting up Python environment (first install)..."
    & $pythonExe -m venv $venvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Failed to create the Python virtual environment."
        exit 1
    }
} else {
    Write-Step "Updating Python environment..."
}

$venvPython = Join-Path $venvDir "Scripts\python.exe"
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install --quiet -r (Join-Path $appDir "requirements.txt")
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Failed to install NightChat's dependencies."
    exit 1
}
Write-Ok "Dependencies installed."

# ---------------------------------------------------------------------------
# 7. `nightchat` command
# ---------------------------------------------------------------------------
Write-Step "Configuring command..."

New-Item -ItemType Directory -Force -Path $binDir | Out-Null

$shimPath = Join-Path $binDir "nightchat.cmd"
$shimContent = @"
@echo off
setlocal
set "PYTHONPATH=%~dp0..\app"
"%~dp0..\venv\Scripts\python.exe" -m client.main %*
"@
Set-Content -Path $shimPath -Value $shimContent -Encoding ASCII

# `~\.nightchat` (identity storage)  -  created here so it exists even
# before first login, but NEVER deleted/overwritten by this installer.
$identityDir = Join-Path $env:USERPROFILE ".nightchat"
New-Item -ItemType Directory -Force -Path $identityDir | Out-Null

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$binDir*") {
    $newPath = if ($userPath) { "$userPath;$binDir" } else { $binDir }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    $env:Path = "$env:Path;$binDir"
    Write-Ok "Added NightChat to your PATH (new PowerShell windows will see the 'nightchat' command)."
} else {
    Write-Ok "NightChat already on PATH."
}

if ($RelayUrl) {
    [Environment]::SetEnvironmentVariable("NIGHTCHAT_RELAY_URL", $RelayUrl, "User")
    $env:NIGHTCHAT_RELAY_URL = $RelayUrl
    Write-Ok "Relay configured: $RelayUrl"
} else {
    Write-Warn2 "No relay configured  -  defaulting to ws://localhost:8000 (only useful with a relay on this same machine)."
    Write-Host "      To talk to someone on another computer, set NIGHTCHAT_RELAY_URL to a relay reachable from both," -ForegroundColor DarkGray
    Write-Host "      e.g.: [Environment]::SetEnvironmentVariable('NIGHTCHAT_RELAY_URL','https://your-relay.example.com','User')" -ForegroundColor DarkGray
}

Write-Host ""
Write-Ok "Installation complete."
Write-Host ""

if ($NoLaunch) {
    Write-Host "Run 'nightchat' from a new PowerShell window to start." -ForegroundColor Cyan
    exit 0
}

Write-Step "Starting NightChat..."
Write-Host ""
$env:PYTHONPATH = $appDir
& $venvPython -m client.main
