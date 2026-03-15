#Requires -RunAsAdministrator
# Update-GPO-HomeFolder.ps1 -- BillU Sprint 5
# Ajoute Create-HomeFolder.ps1 dans la GPO BillU-LecteursReseau
# et le depose dans NETLOGON

. ".\00-Config.ps1"

$DomInfo  = Get-ADDomain -Credential $ADCredential
$dns      = $DomInfo.DNSRoot
$netlogon = "C:\Windows\SYSVOL\sysvol\$dns\scripts"
$unc      = "\\$dns\NETLOGON"

# Copier le script dans NETLOGON
if (Test-Path ".\Create-HomeFolder.ps1") {
    Copy-Item ".\Create-HomeFolder.ps1" "$netlogon\Create-HomeFolder.ps1" -Force
    Write-Host "[OK] Create-HomeFolder.ps1 --> $netlogon"
} else {
    Write-Error "Create-HomeFolder.ps1 introuvable"; exit 1
}

# Ajouter dans la cle Run de la GPO BillU-LecteursReseau
$cmd = "powershell.exe -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$unc\Create-HomeFolder.ps1`""

Set-GPRegistryValue -Name "BillU-LecteursReseau" `
    -Key       "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
    -ValueName "BillU-HomeFolder" `
    -Type      String `
    -Value     $cmd | Out-Null

Write-Host "[OK] Cle Run BillU-HomeFolder ajoutee dans BillU-LecteursReseau"
Write-Host ""
Write-Host "Au prochain logon d un utilisateur :"
Write-Host "  - Si D:\Partages\Homes\[login] n existe pas --> cree automatiquement"
Write-Host "  - Si il existe deja --> rien ne se passe"
Write-Host ""
Write-Host "Sur le client : gpupdate /force puis deconnecter / reconnecter"
