#Requires -RunAsAdministrator
$gpoName = "BillU-LAPS-Config"
$ouPC    = "OU=Ordinateurs,OU=Paris,OU=France,OU=BillU,DC=billu,DC=local"

# Creer la GPO
if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
    New-GPO -Name $gpoName | Out-Null
}
try { New-GPLink -Name $gpoName -Target $ouPC | Out-Null } catch {}

# Cle de registre ou LAPS lit sa configuration
$key = "HKLM\Software\Policies\Microsoft Services\AdmPwd"

# Activer LAPS
Set-GPRegistryValue -Name $gpoName -Key $key `
    -ValueName "AdmPwdEnabled" -Type DWord -Value 1
Write-Host "[OK] LAPS active"

# Longueur du MDP : 14 caracteres (suffisamment complexe)
Set-GPRegistryValue -Name $gpoName -Key $key `
    -ValueName "PasswordLength" -Type DWord -Value 14
Write-Host "[OK] Longueur MDP : 14 caracteres"

# Duree de validite : 30 jours (le MDP change automatiquement)
Set-GPRegistryValue -Name $gpoName -Key $key `
    -ValueName "PasswordAgeDays" -Type DWord -Value 30
Write-Host "[OK] Duree validite : 30 jours"

# Complexite : 4 = majuscules + minuscules + chiffres + symboles
Set-GPRegistryValue -Name $gpoName -Key $key `
    -ValueName "PasswordComplexity" -Type DWord -Value 4
Write-Host "[OK] Complexite : niveau 4 (tous types de caracteres)"

Write-Host ""
Write-Host "=== GPO $gpoName configuree et liee a OU=Ordinateurs ==="
Write-Host "Sur les clients : gpupdate /force puis redemarrer"
