#Requires -Version 5.1
<#
.SYNOPSIS
    Install Cordyceps as an OpenClaw or Hermes Agent skill on Windows.

.PARAMETER Runtime
    Target runtime: openclaw, hermes, or auto (default).

.PARAMETER MyceliumVersion
    Mycelium release tag, e.g. v1.2.0 (default: latest).

.PARAMETER SkipBinary
    Skip Mycelium download (assume mycelium.exe is already on PATH).

.PARAMETER Link
    Symbolic link instead of copy (developer mode; requires admin or developer mode).

.EXAMPLE
    .\install.ps1
    .\install.ps1 -Runtime hermes
    .\install.ps1 -Runtime openclaw -MyceliumVersion v1.0.0
#>
[CmdletBinding()]
param(
    [ValidateSet('openclaw','hermes','auto')]
    [string]$Runtime = 'auto',
    [string]$MyceliumVersion = 'latest',
    [switch]$SkipBinary,
    [switch]$Link
)

$ErrorActionPreference = 'Stop'

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[ERROR] $msg" -ForegroundColor Red }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Auto-detect runtime
if ($Runtime -eq 'auto') {
    if ($env:HERMES_HOME -or (Test-Path "$env:USERPROFILE\.hermes")) {
        $Runtime = 'hermes'
    } elseif ($env:OPENCLAW_HOME -or (Test-Path "$env:USERPROFILE\.openclaw")) {
        $Runtime = 'openclaw'
    } else {
        Write-Err "Cannot auto-detect runtime. Pass -Runtime openclaw or -Runtime hermes."
        exit 1
    }
    Write-Info "Auto-detected runtime: $Runtime"
}

switch ($Runtime) {
    'openclaw' {
        $base = if ($env:OPENCLAW_HOME) { $env:OPENCLAW_HOME } else { Join-Path $env:USERPROFILE '.openclaw' }
        $target = Join-Path $base 'skills\cordyceps'
    }
    'hermes' {
        $base = if ($env:HERMES_HOME) { $env:HERMES_HOME } else { Join-Path $env:USERPROFILE '.hermes' }
        $target = Join-Path $base 'skills\security\cordyceps'
    }
}

Write-Info "Installing to: $target"
New-Item -ItemType Directory -Path $target -Force | Out-Null

$assets = @('SKILL.md','scanner.py','scan.sh','README.md','LICENSE','pyproject.toml')
foreach ($a in $assets) {
    $src = Join-Path $ScriptDir $a
    if (-not (Test-Path $src)) { Write-Warn "$a missing in $ScriptDir, skipping"; continue }
    $dst = Join-Path $target $a
    if ($Link) {
        if (Test-Path $dst) { Remove-Item $dst -Force }
        New-Item -ItemType SymbolicLink -Path $dst -Target $src | Out-Null
    } else {
        Copy-Item -Path $src -Destination $dst -Force
    }
}
Write-Ok "Skill assets installed."

if ($SkipBinary) {
    Write-Warn "Skipping Mycelium binary download (-SkipBinary). Make sure mycelium.exe is on PATH."
} else {
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'amd64' }
        'ARM64' { 'arm64' }
        default { 'amd64' }
    }
    $assetPat = "mycelium-windows-$arch"

    $apiUrl = if ($MyceliumVersion -eq 'latest') {
        'https://api.github.com/repos/zhugez/Mycelium/releases/latest'
    } else {
        "https://api.github.com/repos/zhugez/Mycelium/releases/tags/$MyceliumVersion"
    }

    Write-Info "Querying Mycelium release: $apiUrl"
    try {
        $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -Headers @{ 'User-Agent' = 'cordyceps-installer' }
    } catch {
        Write-Err "Failed to fetch release metadata: $_"
        exit 1
    }

    $asset = $release.assets | Where-Object { $_.name -like "*$assetPat*" } | Select-Object -First 1
    if (-not $asset) {
        Write-Err "No asset matching '$assetPat' in release."
        Write-Info "Available assets:"
        $release.assets | ForEach-Object { Write-Host "  - $($_.name)" }
        exit 1
    }

    $binPath = Join-Path $target 'mycelium.exe'
    Write-Info "Downloading $($asset.browser_download_url)"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $binPath -UseBasicParsing -Headers @{ 'User-Agent' = 'cordyceps-installer' }
    Write-Ok "Mycelium installed: $binPath"

    # Mirror to BASE\tools\cordyceps for OpenClaw convention
    $toolsDir = Join-Path $base 'tools\cordyceps'
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    Copy-Item -Path $binPath -Destination (Join-Path $toolsDir 'mycelium.exe') -Force
}

Write-Ok "Cordyceps installed for $Runtime runtime."
switch ($Runtime) {
    'openclaw' {
        Write-Host ""
        Write-Info "Try it:  openclaw run cordyceps"
    }
    'hermes' {
        Write-Host ""
        Write-Info "Try it:  hermes /cordyceps"
        Write-Info "         hermes skills list | Select-String cordyceps"
    }
}
