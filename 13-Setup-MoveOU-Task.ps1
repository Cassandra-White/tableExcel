#Requires -RunAsAdministrator
$scriptPath = "C:\Scripts\BillU\12-Move-ComputersToOU.ps1"

# Deposer le script
New-Item "C:\Scripts\BillU" -ItemType Directory -Force | Out-Null
Copy-Item ".\12-Move-ComputersToOU.ps1" $scriptPath -Force

# Action : lancer le script PS
$action = New-ScheduledTaskAction `
    -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -NonInteractive -File `"$scriptPath`""

# Declencheur : tous les jours a 00h00 avec repetition toutes les 30 min
$trigger = New-ScheduledTaskTrigger -Daily -At "00:00"
$trigger.RepetitionInterval = New-TimeSpan -Minutes 30
$trigger.RepetitionDuration = [System.TimeSpan]::MaxValue

$principal = New-ScheduledTaskPrincipal `
    -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Unregister-ScheduledTask "BillU-MoveComputers" -Confirm:$false -ErrorAction SilentlyContinue

Register-ScheduledTask "BillU-MoveComputers" `
    -Action $action -Trigger $trigger -Principal $principal `
    -Description "Deplace PC-*/LPT-* de CN=Computers vers OU=Ordinateurs toutes les 30 min" `
    -Force | Out-Null

Write-Host "[OK] Tache BillU-MoveComputers : toutes les 30 min"

# Test immediat
Write-Host "Test immediat..."
Start-ScheduledTask "BillU-MoveComputers"
Start-Sleep 5
Get-Content "C:\Windows\Logs\BillU\MoveOU-$(Get-Date -Format 'yyyyMMdd').log" -Tail 5
