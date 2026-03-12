#Requires -RunAsAdministrator
# Installer LAPS.x64.msi sur DC1
# IMPORTANT : installer avec TOUTES les fonctionnalites (AdmPwd.PS + Fat client UI + CSE)
# /quiet : silencieux | ADDLOCAL=ALL : toutes les fonctionnalites

$msi = "C:\Temp\LAPS.x64.msi"

if (-not (Test-Path $msi)) {
    Write-Error "LAPS.x64.msi introuvable dans C:\Temp\. Verifier le transfert."
    exit 1
}

Write-Host "Installation de LAPS..."
$result = Start-Process msiexec.exe `
    -ArgumentList "/i `"$msi`" /quiet /norestart ADDLOCAL=ALL" `
    -Wait -PassThru

if ($result.ExitCode -eq 0) {
    Write-Host "[OK] LAPS installe avec succes"
} else {
    Write-Host "[ERR] Code retour msiexec : $($result.ExitCode)"
    exit 1
}

# Verifier que le module PS est disponible
try {
    Import-Module AdmPwd.PS -ErrorAction Stop
    Write-Host "[OK] Module AdmPwd.PS charge"
    Get-Command -Module AdmPwd.PS | Select-Object Name
} catch {
    Write-Host "[ERR] Module AdmPwd.PS non disponible : $_"
}

# Verifier les fichiers ADMX (templates GPO)
# Ils doivent etre dans C:\Windows\PolicyDefinitions\ apres installation
if (Test-Path "C:\Windows\PolicyDefinitions\AdmPwd.admx") {
    Write-Host "[OK] Template ADMX LAPS present (AdmPwd.admx)"
} else {
    Write-Host "[WARN] AdmPwd.admx absent de C:\Windows\PolicyDefinitions\"
}

Write-Host "=== LAPS installe et pret pour Sprint 5 ==="
