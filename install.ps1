# SCP2P installer for Windows PowerShell.
#
# Installs scp2p-relay (default) or scp2p-cli from pre-built GitHub releases.
#
# One-liner usage (paste in any PowerShell / Windows Terminal):
#   irm https://raw.githubusercontent.com/your-org/scp2p/main/install.ps1 | iex
#
# Install the CLI instead:
#   $env:SCP2P_TOOL="cli"; irm https://raw.githubusercontent.com/your-org/scp2p/main/install.ps1 | iex
#
# Pin a specific version:
#   $env:SCP2P_VERSION="0.1.0"; irm https://raw.githubusercontent.com/your-org/scp2p/main/install.ps1 | iex
#
# Override install directory:
#   $env:SCP2P_INSTALL_DIR="C:\tools"; irm ... | iex
[CmdletBinding()]
param(
    [string]$Tool       = $env:SCP2P_TOOL,
    [string]$Version    = $env:SCP2P_VERSION,
    [string]$InstallDir = $env:SCP2P_INSTALL_DIR
)
$ErrorActionPreference = "Stop"

$Repo = "your-org/scp2p"

# ── Resolve tool ─────────────────────────────────────────────────────────────────
if (-not $Tool) { $Tool = "relay" }
switch ($Tool.ToLower()) {
    "relay" {
        $BinName     = "scp2p-relay.exe"
        $Asset       = "scp2p-relay-windows-x86_64.exe"
        $TagFilter   = "relay-v"
        $DefaultDir  = Join-Path $env:LOCALAPPDATA "scp2p-relay"
        $DocsPath    = "crates/scp2p-relay/README.md"
    }
    "cli" {
        $BinName     = "scp2p.exe"
        $Asset       = "scp2p-windows-x86_64.exe"
        $TagFilter   = "v"
        $DefaultDir  = Join-Path $env:LOCALAPPDATA "scp2p"
        $DocsPath    = "crates/scp2p-cli/README.md"
    }
    default {
        Write-Error "Unknown tool '$Tool'. Use 'relay' or 'cli'."
    }
}

# ── Resolve version ─────────────────────────────────────────────────────────────────
if (-not $Version) {
    Write-Host "Fetching latest $($BinName.Replace('.exe','')) release..."
    try {
        $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases" -UseBasicParsing
        $match    = $releases | Where-Object { $_.tag_name -like "${TagFilter}*" } | Select-Object -First 1
        if (-not $match) { Write-Error "No release found with tag prefix '$TagFilter'. Use -Version." }
        $Version  = $match.tag_name
    } catch {
        Write-Error "Failed to fetch releases: $_"
    }
}
Write-Host "Installing $BinName $Version (windows/x86_64)..."

# ── Resolve install directory ──────────────────────────────────────────────────────────
if (-not $InstallDir) { $InstallDir = $DefaultDir }
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# ── Download ──────────────────────────────────────────────────────────────────
$Url  = "https://github.com/$Repo/releases/download/$Version/$Asset"
$Dest = Join-Path $InstallDir $BinName

Write-Host "Downloading from: $Url"
Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
Write-Host "Saved to: $Dest"

# ── Add to user PATH (if not already present) ─────────────────────────────────
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable(
        "PATH",
        "$UserPath;$InstallDir",
        "User"
    )
    # Also update the current session so the user can run it immediately.
    $env:PATH += ";$InstallDir"
    Write-Host "Added $InstallDir to your user PATH."
} else {
    Write-Host "$InstallDir is already in PATH."
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Installation complete!"
Write-Host "  Verify:  $($BinName.Replace('.exe','')) --version"
Write-Host "  Start:   $($BinName.Replace('.exe',''))"
Write-Host "  Docs:    https://github.com/$Repo/blob/main/$DocsPath"
Write-Host ""
Write-Host "Open a new terminal window to pick up the updated PATH, or run:"
Write-Host "  `$env:PATH += ';$InstallDir'"
