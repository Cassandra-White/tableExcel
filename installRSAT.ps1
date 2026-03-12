#Requires -RunAsAdministrator
# Installer les outils d administration sur DC1 Server Core
# Inclut : module ActiveDirectory, Group Policy, DNS, DHCP

# Verifier ce qui est disponible
Get-WindowsFeature | Where-Object {$_.Name -like "RSAT*" -and $_.InstallState -eq "Available"} |
    Select-Object Name, DisplayName | Format-Table

# Installer RSAT-AD-Tools (module PS Get-ADUser, New-ADGroup...)
Install-WindowsFeature -Name RSAT-AD-Tools -IncludeAllSubFeature
Write-Host "[OK] Module ActiveDirectory installe"

# Installer GPMC (cmdlets New-GPO, New-GPLink, Set-GPRegistryValue...)
Install-WindowsFeature -Name GPMC
Write-Host "[OK] GPMC installe"

# Verifier
Import-Module ActiveDirectory
Import-Module GroupPolicy
Get-Command -Module ActiveDirectory | Measure-Object
Get-Command -Module GroupPolicy | Measure-Object

Write-Host "=== RSAT pret sur DC1 ==="
