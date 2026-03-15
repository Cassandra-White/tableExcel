# Reconnect-Drives.ps1 -- BillU Sprint 5
# Force la reconnexion des lecteurs I: J: K: sans se deconnecter
# A executer sur le poste CLIENT en tant qu utilisateur normal (pas admin)

Write-Host "=== Reconnexion des lecteurs BillU ==="

# Lancer le script de mappage depuis NETLOGON
$script = "\\DC1\NETLOGON\scripts\Map-Drives-BillU.ps1"

if (Test-Path $script) {
    Write-Host "Lancement de $script ..."
    & powershell.exe -ExecutionPolicy Bypass -File $script
} else {
    Write-Host "[ERR] Script introuvable : $script"
    Write-Host "      Verifier que DC1 est accessible et que NETLOGON est partage"
}

Write-Host ""
Write-Host "=== Etat des lecteurs ==="
foreach ($l in @("I","J","K")) {
    if (Test-Path "${l}:\") {
        Write-Host "  ${l}: MAPPE"
    } else {
        Write-Host "  ${l}: NON MAPPE"
    }
}
