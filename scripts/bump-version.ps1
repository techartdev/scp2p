#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Bump the SCP2P version across all configuration files.

.DESCRIPTION
  Updates the version string in every place it appears:
    - Cargo.toml           (workspace.package.version)
    - crates/*/Cargo.toml  (scp2p-core dependency version pin)
    - app/src-tauri/tauri.conf.json
    - app/package.json
    - app/package-lock.json

.PARAMETER Version
  The new semver version string, e.g. "0.2.0".

.EXAMPLE
  .\scripts\bump-version.ps1 -Version 0.2.0
#>
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+(-[\w.]+)?$')]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Replace-InFile {
    param([string]$Path, [string]$Pattern, [string]$Replacement)
    if (-not (Test-Path $Path)) {
        Write-Warning "  SKIP (not found): $Path"
        return
    }
    $content = Get-Content $Path -Raw
    $updated = $content -replace $Pattern, $Replacement
    if ($content -eq $updated) {
        Write-Host "  UNCHANGED: $Path"
    } else {
        Set-Content $Path -Value $updated -NoNewline
        Write-Host "  UPDATED:   $Path"
    }
}

Write-Host "`nBumping SCP2P version to $Version`n" -ForegroundColor Cyan

# 1. Root Cargo.toml — workspace.package.version
Write-Host "[Cargo workspace]"
Replace-InFile "$root\Cargo.toml" `
    '(?m)(^\[workspace\.package\][\s\S]*?^version\s*=\s*)"[^"]*"' `
    "`${1}`"$Version`""

# 2. scp2p-core dependency version pins in sibling crates
Write-Host "[scp2p-core dep pins]"
$cargoFiles = Get-ChildItem "$root\crates\*\Cargo.toml" -File
foreach ($f in $cargoFiles) {
    Replace-InFile $f.FullName `
        '(scp2p-core\s*=\s*\{[^}]*version\s*=\s*)"[^"]*"' `
        "`${1}`"$Version`""
}

# 3. Tauri config
Write-Host "[Tauri config]"
Replace-InFile "$root\app\src-tauri\tauri.conf.json" `
    '("version"\s*:\s*)"[^"]*"' `
    "`${1}`"$Version`""

# 4. package.json — use regex to avoid PowerShell JSON reformatting
Write-Host "[package.json]"
$pkgPath = "$root\app\package.json"
Replace-InFile $pkgPath `
    '(?m)(^\s*"version"\s*:\s*)"[^"]*"' `
    "`${1}`"$Version`""

# 5. package-lock.json — too large for ConvertFrom-Json, use regex
Write-Host "[package-lock.json]"
$lockPath = "$root\app\package-lock.json"
if (Test-Path $lockPath) {
    # Update only the top-level "version" (line 3) and the root package
    # entry "version" (within the first ~15 lines).  The lock file's
    # nested dependency versions must NOT be touched.
    $lines = Get-Content $lockPath
    $updated = 0
    for ($i = 0; $i -lt [Math]::Min($lines.Count, 15); $i++) {
        if ($lines[$i] -match '^\s*"version"\s*:\s*"[^"]*"') {
            $lines[$i] = $lines[$i] -replace '("version"\s*:\s*)"[^"]*"', "`${1}`"$Version`""
            $updated++
        }
    }
    if ($updated -gt 0) {
        $lines | Set-Content $lockPath
        Write-Host "  UPDATED:   $lockPath ($updated occurrences)"
    } else {
        Write-Host "  UNCHANGED: $lockPath"
    }
}

Write-Host "`nDone. Run 'cargo build --workspace' to verify.`n" -ForegroundColor Green
