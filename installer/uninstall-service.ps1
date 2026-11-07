<#
  Removes the Kavach protection service. Run in PowerShell **as Administrator**.
#>
#Requires -RunAsAdministrator
sc.exe stop KavachService
Start-Sleep -Seconds 2
sc.exe delete KavachService
Write-Host "Kavach service removed." -ForegroundColor Green
