#Requires -RunAsAdministrator

$gpoName = "BillU-SEC-LogonHours"
$target  = "OU=Paris,OU=France,OU=BillU,DC=billu,DC=local"
$script  = "C:\Scripts\BillU\15-Set-LogonHours.ps1"

# ---- GPO : deconnexion forcee et verrouillage ecran ----
if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
    New-GPO -Name $gpoName | Out-Null
    Write-Host "[OK] GPO $gpoName creee"
}
try { New-GPLink -Name $gpoName -Target $target | Out-Null } catch {}

# Forcer la deconnexion a l expiration des heures de connexion
# (cle de registre du service LanmanServer)
Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "EnableForcedLogoff" -Type DWord -Value 1
Write-Host "[OK] EnableForcedLogoff = 1 (deconnexion automatique a 20h)"

# Verrouiller l ecran apres 10 min d inactivite
$desktopKey = "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
Set-GPRegistryValue -Name $gpoName -Key $desktopKey `
    -ValueName "ScreenSaveTimeOut"   -Type String -Value "600"   # 10 min
Set-GPRegistryValue -Name $gpoName -Key $desktopKey `
    -ValueName "ScreenSaveActive"    -Type String -Value "1"
Set-GPRegistryValue -Name $gpoName -Key $desktopKey `
    -ValueName "ScreenSaverIsSecure" -Type String -Value "1"     # Exige MDP au deverrouillage
Write-Host "[OK] Ecran verrouille apres 10 min d inactivite"

# ---- Tache planifiee : re-appliquer logonHours chaque nuit a 03h00 ----
# (en cas de creation de nouveaux users ou de changement de groupe)
New-Item "C:\Scripts\BillU" -ItemType Directory -Force | Out-Null
Copy-Item ".\15-Set-LogonHours.ps1" $script -Force

$action = New-ScheduledTaskAction `
    -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -NonInteractive -File `"$script`""

$principal = New-ScheduledTaskPrincipal `
    -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Unregister-ScheduledTask "BillU-SetLogonHours" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask "BillU-SetLogonHours" `
    -Action $action `
    -Trigger (New-ScheduledTaskTrigger -Daily -At "03:00") `
    -Principal $principal `
    -Description "Re-applique les restrictions horaires chaque nuit a 03h00" `
    -Force | Out-Null
Write-Host "[OK] Tache BillU-SetLogonHours a 03:00"

# Premiere execution immediate
Write-Host ""
Write-Host "Application immediate des restrictions..."
& $script
