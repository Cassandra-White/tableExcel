#Requires -RunAsAdministrator
# 18-Setup-AutoGroups-Task.ps1 -- BillU Sprint 5
# Installe la tache planifiee BillU-AutoGroups (toutes les 15 min)

$scriptSrc = ".\17-Auto-AssignGroups.ps1"
$scriptDst = "C:\Scripts\BillU\17-Auto-AssignGroups.ps1"

New-Item "C:\Scripts\BillU" -ItemType Directory -Force | Out-Null

if (Test-Path $scriptSrc) {
    Copy-Item $scriptSrc $scriptDst -Force
    Write-Host "[OK] $scriptDst"
} else {
    Write-Error "Introuvable : $scriptSrc"; exit 1
}

$action = New-ScheduledTaskAction `
    -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$scriptDst`""

$trigger = New-ScheduledTaskTrigger -Daily -At "00:00"
$trigger.RepetitionInterval = New-TimeSpan -Minutes 15
$trigger.RepetitionDuration = [System.TimeSpan]::MaxValue

$principal = New-ScheduledTaskPrincipal `
    -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Unregister-ScheduledTask "BillU-AutoGroups" -Confirm:$false -EA SilentlyContinue
Register-ScheduledTask "BillU-AutoGroups" `
    -Action $action -Trigger $trigger -Principal $principal `
    -Description "Affecte GG_SVC_* selon GG_*_Users -- toutes les 15 min" `
    -Force | Out-Null

Write-Host "[OK] Tache BillU-AutoGroups creee"
Write-Host ""

# Test immediat
Write-Host "=== Test immediat ==="
Start-ScheduledTask "BillU-AutoGroups"
Start-Sleep 8
Get-Content "C:\Windows\Logs\BillU\AutoGroups-$(Get-Date -f yyyyMMdd).log" -Tail 10 -EA SilentlyContinue

Write-Host ""
Write-Host "=== Fonctionnement automatique ==="
Write-Host "  1. Ajouter un user dans GG_COMM_Users (ou n importe quel GG_*_Users)"
Write-Host "  2. Dans 15 min max : il est ajoute dans tous les GG_SVC_* de son dept"
Write-Host "  3. Au prochain logon : J: et K: se mapperont correctement"
