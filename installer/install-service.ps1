<#
  Installs the Kavach protection service by hand (for testing without the installer).
  Run in PowerShell **as Administrator** after build.ps1:
      .\installer\install-service.ps1
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$exe = Join-Path $root "publish\Service\KavachService.exe"
if (-not (Test-Path $exe)) { throw "Build first: $exe not found (run build.ps1)" }

$data = Join-Path $env:ProgramData "Kavach"
New-Item -ItemType Directory -Force -Path $data | Out-Null
icacls $data /grant "*S-1-5-32-545:(OI)(CI)M" | Out-Null   # Users: modify

sc.exe stop KavachService 2>$null | Out-Null
sc.exe delete KavachService 2>$null | Out-Null
Start-Sleep -Seconds 1
sc.exe create KavachService binPath= "`"$exe`"" start= auto DisplayName= "Kavach Antivirus Protection"
sc.exe description KavachService "Kavach Antivirus real-time, ransomware and USB protection. Developed by Cecil Baraik."
sc.exe failure KavachService reset= 86400 actions= restart/5000/restart/5000/restart/15000
sc.exe start KavachService
Write-Host "Kavach service installed and started." -ForegroundColor Green
