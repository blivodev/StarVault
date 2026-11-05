# Verifies the installer: silent install, files present, app launches, uninstall.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$setup = Join-Path $root "installer\out\StarVault-1.1.0-setup.exe"
$dir = Join-Path $env:TEMP "svtest"
$log = Join-Path $env:TEMP "svinstall.log"

if (-not (Test-Path $setup)) { Write-Error "no installer at $setup"; exit 1 }
if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }

Write-Host "1. silent install -> $dir" -ForegroundColor Yellow
$p = Start-Process -FilePath $setup -Wait -PassThru -ArgumentList @(
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/DIR=$dir", "/LOG=$log")
Write-Host "   installer exit code: $($p.ExitCode)"

if (-not (Test-Path $dir)) { Write-Error "install dir was not created"; exit 1 }
Write-Host "2. installed files:" -ForegroundColor Yellow
Get-ChildItem -Recurse $dir | ForEach-Object {
    $rel = $_.FullName.Substring($dir.Length + 1)
    $size = if ($_.PSIsContainer) { "" } else { "$($_.Length) bytes" }
    Write-Host "   $rel  $size"
}

$exe = Join-Path $dir "StarVault.exe"
if (-not (Test-Path $exe)) { Write-Error "StarVault.exe missing"; exit 1 }

Write-Host "3. MCP smoke test of the installed exe" -ForegroundColor Yellow
$init = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"verify","version":"1"}}}'
$out = $init | & $exe --mcp --portable 2>&1 | Select-Object -First 1
if ($out -match "starvault-mcp") { Write-Host "   OK: $out" -ForegroundColor Green }
else { Write-Warning "   unexpected output: $out" }

Write-Host "4. uninstall" -ForegroundColor Yellow
$uninst = Join-Path $dir "unins000.exe"
if (-not (Test-Path $uninst)) { Write-Error "uninstaller missing"; exit 1 }
$u = Start-Process -FilePath $uninst -Wait -PassThru -ArgumentList @(
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")
Write-Host "   uninstaller exit code: $($u.ExitCode)"

Start-Sleep -Seconds 2
if (Test-Path (Join-Path $dir "StarVault.exe")) {
    Write-Warning "StarVault.exe still present after uninstall"
} else {
    Write-Host "   StarVault.exe removed" -ForegroundColor Green
}
Write-Host "5. leftover files in install dir:" -ForegroundColor Yellow
if (Test-Path $dir) {
    $left = Get-ChildItem -Recurse $dir -ErrorAction SilentlyContinue
    if ($left) { $left | ForEach-Object { Write-Host "   $($_.Name)" } }
    else { Write-Host "   (none)" -ForegroundColor Green }
} else {
    Write-Host "   (directory removed entirely)" -ForegroundColor Green
}
Write-Host "DONE" -ForegroundColor Green
