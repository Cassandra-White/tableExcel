# Map-Drives-BillU.ps1 -- BillU Sprint 5
# Mappe I: (home), J: (service), K: (departement) selon les groupes AD
# Deposer dans : \\DC1\NETLOGON\scripts\Map-Drives-BillU.ps1

$user = $env:USERNAME
$dc1  = "\\DC1"

# Supprimer les anciens mappages
foreach ($l in @("I","J","K")) {
    if (Test-Path "${l}:") { net use "${l}:" /delete /y 2>$null }
}

# I: -- Dossier individuel (tous les users)
net use I: "$dc1\Homes\$user" /persistent:yes 2>$null
if (-not (Test-Path "I:")) {
    net use I: "$dc1\Homes" /persistent:yes
}

# Recuperer les groupes AD de l utilisateur courant
$grps = @()
try {
    $grps = (Get-ADUser $user -Properties MemberOf).MemberOf |
        ForEach-Object { (Get-ADGroup $_ -EA SilentlyContinue).Name } |
        Where-Object { $_ }
} catch { exit 0 }

# J: -- Premier groupe GG_SVC_* = service de l utilisateur
$svcGrp = $grps | Where-Object { $_ -like "GG_SVC_*" } | Select-Object -First 1
if ($svcGrp) {
    $svc = $svcGrp -replace "^GG_SVC_",""
    net use J: "$dc1\Services\$svc" /persistent:yes
}

# K: -- Groupe GG_[DEPT]_Users = departement de l utilisateur
$deptMap = @{
    "GG_DIRECTION_Users"  = "Direction";   "GG_DEV_Users"      = "Dev-Logiciel"
    "GG_DSI_Users"        = "DSI";         "GG_COMMERCIAL_Users"= "Commercial"
    "GG_COMM_Users"       = "Communication";"GG_JURIDIQUE_Users" = "Juridique"
    "GG_FINANCE_Users"    = "Finance";     "GG_QHSE_Users"     = "QHSE"
    "GG_RH_Users"         = "Recrutement"
}
foreach ($g in $deptMap.Keys) {
    if ($grps -contains $g) {
        net use K: "$dc1\Departements\$($deptMap[$g])" /persistent:yes
        break
    }
}
