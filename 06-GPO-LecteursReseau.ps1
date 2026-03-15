#Requires -RunAsAdministrator
# 06-GPO-LecteursReseau.ps1 -- BillU Sprint 5
# 1. Corrige la GPO de logon script (ExecutionPolicy Bypass)
# 2. Cree une GPO qui depose Reconnecter-Lecteurs.bat sur le bureau de tous les users

. ".\00-Config.ps1"

$DomInfo = Get-ADDomain -Credential $ADCredential
$SiteDN  = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$($DomInfo.DistinguishedName)"
$OuCible = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$($DomInfo.DistinguishedName)"
$netlogon = "C:\Windows\SYSVOL\sysvol\$($DomInfo.DNSRoot)\scripts"

Write-Host "=== GPO Lecteurs Reseau -- BillU Sprint 5 ==="
Write-Host ""

# ---- 1. Deposer les scripts dans NETLOGON --------------------
Write-Host "--- 1. Depot des scripts dans NETLOGON ---"

# Map-Drives-BillU.ps1
$mapSrc = ".\Map-Drives-BillU.ps1"
$mapDst = "$netlogon\Map-Drives-BillU.ps1"
if (Test-Path $mapSrc) {
    Copy-Item $mapSrc $mapDst -Force
    Write-Host "  [OK] Map-Drives-BillU.ps1 --> $mapDst"
} else {
    Write-Host "  [ERR] Map-Drives-BillU.ps1 introuvable dans le dossier courant"
}

# Reconnecter-Lecteurs.bat
$batSrc = ".\Reconnecter-Lecteurs.bat"
$batDst = "$netlogon\Reconnecter-Lecteurs.bat"
if (Test-Path $batSrc) {
    Copy-Item $batSrc $batDst -Force
    Write-Host "  [OK] Reconnecter-Lecteurs.bat --> $batDst"
} else {
    Write-Host "  [ERR] Reconnecter-Lecteurs.bat introuvable"
}
Write-Host ""

# ---- 2. GPO logon script (Map-Drives) ------------------------
Write-Host "--- 2. GPO BillU-LecteursReseau (logon script) ---"
$gpoLogon = "BillU-LecteursReseau"

if (-not (Get-GPO -Name $gpoLogon -EA SilentlyContinue)) {
    New-GPO -Name $gpoLogon | Out-Null
    Write-Host "  [NEW] GPO creee : $gpoLogon"
} else {
    Write-Host "  [OK]  GPO existe : $gpoLogon"
}

# Lier la GPO a l OU cible
try { New-GPLink -Name $gpoLogon -Target $OuCible -EA SilentlyContinue | Out-Null } catch {}

# Configurer le logon script avec ExecutionPolicy Bypass
# Le script est appele depuis NETLOGON avec le bon parametre
$scriptLine = "powershell.exe -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"\\$($DomInfo.DNSRoot)\NETLOGON\scripts\Map-Drives-BillU.ps1`""

Set-GPRegistryValue -Name $gpoLogon `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
    -ValueName "BillU-MapDrives" `
    -Type String `
    -Value $scriptLine | Out-Null

Write-Host "  [OK]  Cle Run configuree : $scriptLine"
Write-Host ""

# ---- 3. GPO bureau (Reconnecter-Lecteurs.bat) ----------------
Write-Host "--- 3. GPO BillU-Bureau (raccourci sur le bureau) ---"
$gpoBureau = "BillU-Bureau"

if (-not (Get-GPO -Name $gpoBureau -EA SilentlyContinue)) {
    New-GPO -Name $gpoBureau | Out-Null
    Write-Host "  [NEW] GPO creee : $gpoBureau"
} else {
    Write-Host "  [OK]  GPO existe : $gpoBureau"
}

try { New-GPLink -Name $gpoBureau -Target $OuCible -EA SilentlyContinue | Out-Null } catch {}

# Copier le .bat dans un partage accessible par tous les users
$publicShare = "$netlogon\Reconnecter-Lecteurs.bat"

# Script de demarrage (RunOnce) qui cree le raccourci sur le bureau au prochain logon
$shortcutScript = @"
Set oWS = WScript.CreateObject("WScript.Shell")
sDeskTop = oWS.SpecialFolders("Desktop")
Set oLink = oWS.CreateShortcut(sDeskTop & "\Reconnecter les lecteurs.lnk")
oLink.TargetPath = "\\$($DomInfo.DNSRoot)\NETLOGON\scripts\Reconnecter-Lecteurs.bat"
oLink.Description = "Reconnecter les lecteurs reseau I J K"
oLink.IconLocation = "imageres.dll,17"
oLink.Save
"@

# Deposer le VBS dans NETLOGON
$vbsDst = "$netlogon\CreateShortcut.vbs"
$shortcutScript | Set-Content $vbsDst -Encoding ASCII
Write-Host "  [OK]  CreateShortcut.vbs --> $vbsDst"

# Configurer la GPO pour executer le VBS au logon
Set-GPRegistryValue -Name $gpoBureau `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
    -ValueName "BillU-Shortcut" `
    -Type String `
    -Value "wscript.exe `"\\$($DomInfo.DNSRoot)\NETLOGON\scripts\CreateShortcut.vbs`"" | Out-Null

Write-Host "  [OK]  Raccourci bureau configure via Run"
Write-Host ""

# ---- 4. Forcer gpupdate sur les clients ----------------------
Write-Host "--- 4. Pour appliquer immediatement ---"
Write-Host "   Sur chaque client : gpupdate /force"
Write-Host "   Ou depuis DC1 pour tous les PC de l OU :"
Write-Host "   Get-ADComputer -Filter * -SearchBase '$OuCible' |"
Write-Host "     ForEach-Object { Invoke-GPUpdate -Computer `$_.Name -Force -EA SilentlyContinue }"
Write-Host ""
Write-Host "=== Script 06 termine ==="
