#Requires -RunAsAdministrator
# 12-Move-ComputersToOU.ps1 -- BillU Sprint 5
# Deplace les PC dont le nom commence par PC- ou LPT-
# depuis CN=Computers vers OU=Ordinateurs
# Log : C:\Windows\Logs\BillU\MoveOU-[date].log

$ouDest = "OU=Ordinateurs,OU=Paris,OU=France,OU=BillU,DC=billu,DC=local"
$cnComp = "CN=Computers,DC=billu,DC=local"  # Conteneur par defaut
$logDir = "C:\Windows\Logs\BillU"
$log    = "$logDir\MoveOU-$(Get-Date -Format 'yyyyMMdd').log"

New-Item $logDir -ItemType Directory -Force | Out-Null

function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Add-Content $log $line
    Write-Host $line
}

Log "=== Debut deplacement OU ==="

# Chercher les PC dans CN=Computers qui commencent par PC- ou LPT-
$pcs = Get-ADComputer -Filter * -SearchBase $cnComp -SearchScope OneLevel `
    -ErrorAction SilentlyContinue

$Moved = 0; $Skip = 0; $Err = 0

foreach ($pc in $pcs) {
    # Ne deplacer que PC-* et LPT-* (convention de nommage BillU)
    if ($pc.Name -notmatch "^(PC|LPT)-") {
        Log "[SKIP] $($pc.Name) -- nom ne correspond pas a la convention PC-/LPT-"
        $Skip++
        continue
    }

    try {
        Move-ADObject -Identity $pc.DistinguishedName -TargetPath $ouDest
        Log "[OK]   $($pc.Name) deplace vers OU=Ordinateurs"
        $Moved++
    } catch {
        Log "[ERR]  $($pc.Name) -- erreur : $_"
        $Err++
    }
}

Log "=== Fin : $Moved deplaces | $Skip ignores | $Err erreurs ==="
