# Builds dist\FileLocker-Setup-<version>.exe.
#
# Needs: Rust (MSVC), WinFsp with its Developer feature, LLVM (for the WinFsp
# bindings), and Inno Setup 6. Run from any folder:
#   powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$msiName = "winfsp-2.1.25156.msi"
$msiUrl = "https://github.com/winfsp/winfsp/releases/download/v2.1/$msiName"
# SHA-256 of the official release, as published in the winget manifest.
$msiHash = "073A70E00F77423E34BED98B86E600DEF93393BA5822204FAC57A29324DB9F7A"

Write-Host "Building release binaries..."
cargo build --release -p flk-app -p flk
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$redist = Join-Path $root "target\redist"
New-Item -ItemType Directory -Force $redist | Out-Null
$msi = Join-Path $redist $msiName
if (-not (Test-Path $msi) -or (Get-FileHash $msi -Algorithm SHA256).Hash -ne $msiHash) {
    Write-Host "Downloading $msiName..."
    Invoke-WebRequest $msiUrl -OutFile $msi -UseBasicParsing
}
$actual = (Get-FileHash $msi -Algorithm SHA256).Hash
if ($actual -ne $msiHash) {
    Remove-Item $msi
    throw "WinFsp installer hash mismatch: got $actual"
}

$iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found (winget install JRSoftware.InnoSetup)" }

Write-Host "Building the installer..."
& $iscc /Qp "installer\FileLocker.iss"
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }
Get-ChildItem dist\*.exe | Select-Object Name, @{n = "MB"; e = { [math]::Round($_.Length / 1MB, 1) } }
