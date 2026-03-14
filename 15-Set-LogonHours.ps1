#Requires -RunAsAdministrator
# 15-Set-LogonHours.ps1 -- BillU Sprint 5
# Plage autorisee : Lun(1) a Sam(6), heures UTC 6 a 19 = 7h a 20h France (UTC+1)
# Le groupe GRP-Bypass-Horaires est exclu des restrictions

$ouUsers = "OU=Utilisateurs,OU=Paris,OU=France,OU=BillU,DC=billu,DC=local"
$grpByp  = "GRP-Bypass-Horaires"
$logDir  = "C:\Windows\Logs\BillU"
$log     = "$logDir\LogonHours-$(Get-Date -Format 'yyyyMMdd').log"
New-Item $logDir -ItemType Directory -Force | Out-Null

# =============================================
# Fonction qui construit le tableau de 21 octets
# $jours : numeros des jours (0=Dim, 1=Lun...6=Sam)
# $heures : heures UTC autorisees (ex: 6..19)
# =============================================
function Build-LogonHours {
    param([int[]]$jours, [int[]]$heures)
    $bytes = [byte[]](,0 * 21)
    foreach ($j in $jours) {
        foreach ($h in $heures) {
            $bit = $j * 24 + $h
            $bytes[[Math]::Floor($bit / 8)] = `
                $bytes[[Math]::Floor($bit / 8)] -bor ([byte](1 -shl ($bit % 8)))
        }
    }
    return $bytes
}

# Heures restreintes : Lun-Sam (1-6), 6h-19h UTC = 7h-20h France
$hoursRestr = Build-LogonHours -jours (1..6) -heures (6..19)
# Heures libres : toute la semaine, 24h/24 (pour le groupe bypass)
$hoursLibre = [byte[]](,0xFF * 21)

# Recuperer la liste des membres du groupe bypass
$bypass = @()
try {
    $bypass = Get-ADGroupMember $grpByp -Recursive -ErrorAction Stop |
        Select-Object -ExpandProperty SamAccountName
    Write-Host "$($bypass.Count) comptes en bypass (aucune restriction)"
} catch {
    Write-Host "Groupe bypass introuvable -- tous les users seront restreints"
}

function Log($msg) { Add-Content $log $msg; Write-Host $msg }

Log "=== LogonHours $(Get-Date) ==="

# Appliquer sur tous les users actifs de OU=Utilisateurs
$users = Get-ADUser -Filter { Enabled -eq $true } `
    -SearchBase $ouUsers -SearchScope Subtree

$Restricted = 0; $BypassCount = 0; $Err = 0

foreach ($u in $users) {
    $isAdmin = $bypass -contains $u.SamAccountName

    # Membres bypass = logonHours libre (0xFF partout = toujours autorise)
    $hours = if ($isAdmin) { $hoursLibre } else { $hoursRestr }
    $label = if ($isAdmin) { "BYPASS" }    else { "RESTR"  }

    try {
        Set-ADUser -Identity $u.SamAccountName -Replace @{ logonHours = $hours }
        Log "  [$label] $($u.SamAccountName)"
        if ($isAdmin) { $BypassCount++ } else { $Restricted++ }
    } catch {
        Log "  [ERR]   $($u.SamAccountName) : $_"
        $Err++
    }
}

Log "=== Fin : $Restricted restreints | $BypassCount bypass | $Err erreurs ==="
