# Builds the StarVault Windows installer (installer\out\StarVault-<version>-setup.exe)
# and the browser-extension zip (installer\out\StarVault-Extension-<version>.zip).
#
# StarVault ships as a single PyInstaller one-file exe, so there is nothing to
# stage beyond the exe itself plus the licence notices the app bundles. The
# installer wraps that exe with a Start Menu entry, an "Apps & features" row and
# an uninstaller.
#
#   pwsh -File installer\make_installer.ps1                     # version from starvault\config.py
#   pwsh -File installer\make_installer.ps1 -Version 1.1.0
#   pwsh -File installer\make_installer.ps1 -SkipExe            # reuse the existing dist exe
#
# Needs Inno Setup 6 (iscc on the PATH, or in its normal folder) and, unless
# -SkipExe is passed, PyInstaller in the project venv.

param(
    [string]$Version = "",
    [string]$StageDir = "",
    [switch]$SkipExe
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

# The version has ONE source of truth: APP_VERSION in starvault\config.py.
# Read it unless -Version overrides, so the installer cannot drift from the app.
if (-not $Version) {
    $cfg = Join-Path $root "starvault\config.py"
    $match = Select-String -Path $cfg -Pattern '^APP_VERSION\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $match) { Write-Error "No APP_VERSION found in $cfg"; exit 1 }
    $Version = $match.Matches[0].Groups[1].Value
    Write-Host "Version (from starvault\config.py): $Version" -ForegroundColor Cyan
}

$stage = if ($StageDir) { $StageDir } else { Join-Path $PSScriptRoot "stage-$Version" }
$out = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force $out | Out-Null

# 1. Build the one-file exe unless told to reuse the existing one.
$exe = Join-Path $root "dist\StarVault.exe"
if (-not $SkipExe) {
    Write-Host "Building the exe (PyInstaller)..." -ForegroundColor Yellow
    $py = Join-Path $root ".venv\Scripts\python.exe"
    if (-not (Test-Path $py)) { $py = "python" }
    Push-Location $root
    try {
        & $py -m PyInstaller StarVault.spec --noconfirm
        if ($LASTEXITCODE -ne 0) { Write-Error "PyInstaller failed"; exit 1 }
    } finally {
        Pop-Location
    }
}
if (-not (Test-Path $exe)) { Write-Error "No exe at $exe (build it first, or drop -SkipExe)"; exit 1 }

# 2. A clean staged folder holding just what the installer ships.
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item $exe -Destination $stage -Force
Copy-Item (Join-Path $root "starvault.ico") -Destination $stage -Force
Copy-Item (Join-Path $root "README.md") -Destination $stage -Force

# Font and icon licences travel with the app: they cover assets compiled in.
New-Item -ItemType Directory -Force (Join-Path $stage "licenses") | Out-Null
foreach ($lic in @("LICENSE_OFL.txt", "LICENSE_LUCIDE.txt")) {
    $src = Join-Path $root "starvault\resources\fonts\$lic"
    if (Test-Path $src) { Copy-Item $src -Destination (Join-Path $stage "licenses") -Force }
}

# 3. The installer itself.
$iscc = (Get-Command iscc -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
    foreach ($candidate in @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $candidate) { $iscc = $candidate; break }
    }
}
if (-not $iscc) { Write-Error "Inno Setup 6 was not found (install it, or put iscc on the PATH)."; exit 1 }

Write-Host "Compiling the installer..." -ForegroundColor Yellow
& $iscc "/DAppVersion=$Version" "/DStageDir=$stage" "/DOutputDir=$out" "$PSScriptRoot\starvault.iss"
if ($LASTEXITCODE -ne 0) { Write-Error "Inno Setup failed"; exit 1 }

# 4. The browser-extension zip. It is a separate download on the site, so its
#    name carries its own version (the extension version lives in manifest.json
#    and is deliberately independent of the app version).
$extDir = Join-Path $root "extension"
$manifest = Get-Content (Join-Path $extDir "manifest.json") -Raw | ConvertFrom-Json
$extVersion = $manifest.version
$extZip = Join-Path $out "StarVault-Extension-$extVersion.zip"
if (Test-Path $extZip) { Remove-Item $extZip -Force }

Write-Host "Zipping the browser extension ($extVersion)..." -ForegroundColor Yellow
$extStage = Join-Path $PSScriptRoot "stage-extension"
if (Test-Path $extStage) { Remove-Item -Recurse -Force $extStage }
New-Item -ItemType Directory -Force $extStage | Out-Null
# Only the files the browser needs: no stray scripts, no editor backups.
foreach ($item in @("manifest.json", "popup.html", "popup.js", "icons.js",
                    "background.js", "content.js", "style.css")) {
    $src = Join-Path $extDir $item
    if (Test-Path $src) { Copy-Item $src -Destination $extStage -Force }
}
foreach ($dir in @("icons", "fonts")) {
    $src = Join-Path $extDir $dir
    if (Test-Path $src) { Copy-Item $src -Destination $extStage -Recurse -Force }
}
Compress-Archive -Path (Join-Path $extStage "*") -DestinationPath $extZip -Force
Remove-Item -Recurse -Force $extStage

Write-Host ""
Write-Host "Done:" -ForegroundColor Green
Write-Host "  $out\StarVault-$Version-setup.exe"
Write-Host "  $extZip"
