#Requires -RunAsAdministrator
# 17-Auto-AssignGroups.ps1 -- BillU Sprint 5
# Logique : si un user est dans GG_[DEPT]_Users
#           --> l ajouter automatiquement dans tous les GG_SVC_* du meme departement
# Execute toutes les 15 min via tache planifiee BillU-AutoGroups

. ".\00-Config.ps1"

$DomInfo = Get-ADDomain -Credential $ADCredential
$SiteDN  = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$($DomInfo.DistinguishedName)"
$log     = "C:\Windows\Logs\BillU\AutoGroups-$(Get-Date -f yyyyMMdd).log"
New-Item (Split-Path $log) -ItemType Directory -Force | Out-Null

function Log($msg) {
    $line = "[$(Get-Date -f HH:mm:ss)] $msg"
    Add-Content $log $line -Encoding UTF8 -EA SilentlyContinue
    Write-Host $line
}

# ---- Construire la carte Dept -> GG_*_Users + GG_SVC_* ------
# Depuis 00-Config.ps1 : $Departements contient la structure
# Chaque dept a un nom et une liste de services

$deptToUsersGrp = @{
    "Direction"     = "GG_DIRECTION_Users"
    "Dev-Logiciel"  = "GG_DEV_Users"
    "DSI"           = "GG_DSI_Users"
    "Commercial"    = "GG_COMMERCIAL_Users"
    "Communication" = "GG_COMM_Users"
    "Juridique"     = "GG_JURIDIQUE_Users"
    "Finance"       = "GG_FINANCE_Users"
    "QHSE"          = "GG_QHSE_Users"
    "Recrutement"   = "GG_RH_Users"
}

# Construire la carte GG_*_Users -> liste des GG_SVC_* du meme dept
# Depuis $Departements defini dans 00-Config.ps1
$usersGrpToSvcGrps = @{}
foreach ($D in $Departements) {
    $deptName = $D.Name
    if (-not $deptToUsersGrp.ContainsKey($deptName)) { continue }
    $usersGrp = $deptToUsersGrp[$deptName]

    $svcGrps = @()
    foreach ($S in $D.Services) {
        $svcGrps += "GG_SVC_$($S.OUName)"
    }
    $usersGrpToSvcGrps[$usersGrp] = $svcGrps
}

Write-Host "=== Carte departements -> services ==="
foreach ($k in $usersGrpToSvcGrps.Keys) {
    Write-Host "  $k --> $($usersGrpToSvcGrps[$k] -join ', ')"
}
Write-Host ""

Log "=== AutoGroups -- $(Get-Date -f 'dd/MM/yyyy HH:mm') ==="

# ---- Parcourir tous les users actifs ------------------------
$users = Get-ADUser -Filter { Enabled -eq $true } `
    -SearchBase "OU=Utilisateurs,$SiteDN" -SearchScope Subtree `
    -Properties MemberOf `
    -Credential $ADCredential

$added = 0

foreach ($u in $users) {
    # Groupes actuels du user
    $currentGrps = $u.MemberOf | ForEach-Object {
        (Get-ADGroup $_ -EA SilentlyContinue).Name
    } | Where-Object { $_ }

    # Trouver son groupe GG_*_Users
    $usersGrp = $currentGrps | Where-Object { $usersGrpToSvcGrps.ContainsKey($_) } | Select-Object -First 1

    if (-not $usersGrp) { continue }

    # Ajouter dans chaque GG_SVC_* du meme departement si absent
    foreach ($svcGrp in $usersGrpToSvcGrps[$usersGrp]) {
        if ($currentGrps -contains $svcGrp) { continue }

        # Verifier que le groupe existe dans l AD
        $grp = Get-ADGroup -Filter "Name -eq '$svcGrp'" -Credential $ADCredential -EA SilentlyContinue
        if (-not $grp) {
            Log "  [SKIP] $svcGrp introuvable dans l AD"
            continue
        }

        try {
            Add-ADGroupMember -Identity $svcGrp -Members $u.SamAccountName `
                -Credential $ADCredential -EA Stop
            Log "  [OK] $($u.SamAccountName) --> $svcGrp (depuis $usersGrp)"
            $added++
        } catch {
            Log "  [ERR] $($u.SamAccountName) --> $svcGrp : $_"
        }
    }
}

Log "=== Fin : $added affectations ajoutees ==="
