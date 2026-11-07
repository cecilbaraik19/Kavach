<#
  Kavach Antivirus — build script
  Developed by Cecil Baraik

  Builds the app and the Windows service as self-contained programs (no .NET install needed on the target PC),
  then creates the installer if Inno Setup 6 is installed.

  Usage (PowerShell, in the Kavach folder):
      .\build.ps1
#>
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$publish = Join-Path $root "publish"

# Version number lives in Directory.Build.props
$version = ([xml](Get-Content "$root\Directory.Build.props")).Project.PropertyGroup.Version
Write-Host "Kavach version $version" -ForegroundColor Cyan

Write-Host "Cleaning old output..." -ForegroundColor Cyan
if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }
Remove-Item "$root\installer\Output\KavachSetup-*.exe" -Force -ErrorAction SilentlyContinue

Write-Host "Building Kavach app..." -ForegroundColor Cyan
dotnet publish "$root\src\Kavach.App\Kavach.App.csproj" -c Release -r win-x64 --self-contained true `
    -p:PublishReadyToRun=true -o "$publish\App"
if ($LASTEXITCODE -ne 0) { throw "App build failed" }

Write-Host "Building Kavach service..." -ForegroundColor Cyan
dotnet publish "$root\src\Kavach.Service\Kavach.Service.csproj" -c Release -r win-x64 --self-contained true `
    -p:PublishReadyToRun=true -o "$publish\Service"
if ($LASTEXITCODE -ne 0) { throw "Service build failed" }

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($iscc) {
    Write-Host "Creating installer..." -ForegroundColor Cyan
    # An antivirus (Windows Defender or Kavach itself) may briefly lock the new setup file
    # while scanning it, so try up to 3 times.
    for ($try = 1; $try -le 3; $try++) {
        & $iscc "/DAppVersion=$version" "$root\installer\Kavach.iss"
        if ($LASTEXITCODE -eq 0) { break }
        if ($try -lt 3) {
            Write-Host "Installer step failed (attempt $try of 3) - retrying in 5 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
        }
    }
    if ($LASTEXITCODE -ne 0) { throw "Installer build failed" }
    Write-Host "Done! Installer: $root\installer\Output\KavachSetup-$version.exe" -ForegroundColor Green
} else {
    Write-Host "Done! Program files are in $publish" -ForegroundColor Green
    Write-Host "Install Inno Setup 6 (https://jrsoftware.org/isinfo.php) and run this script again to create KavachSetup.exe," -ForegroundColor Yellow
    Write-Host "or run installer\install-service.ps1 as administrator to install the service by hand." -ForegroundColor Yellow
}
