#Requires -RunAsAdministrator
# 17-Auto-AssignGroups.ps1 -- BillU Sprint 5
# 100% dynamique -- aucun groupe code en dur, aucune dependance a $Departements
# Logique pure AD :
#   1. Recupere tous les GG_*_Users et GG_SVC_* depuis l AD
#   2. Pour chaque GG_*_Users, trouve les GG_SVC_* associes
#      en comparant les membres communs (croisement AD)
#   3. Ajoute les membres manquants

. ".\00-Config.ps1"

$DomInfo = Get-ADDomain -Credential $ADCredential
$SiteDN  = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$($DomInfo.DistinguishedName)"
$OuSecu  = "OU=Groupes-Securite,OU=Groupes,$SiteDN"
$log     = "C:\Windows\Logs\BillU\AutoGroups-$(Get-Date -f yyyyMMdd).log"
New-Item (Split-Path $log) -ItemType Directory -Force | Out-Null

function Log($msg) {
    $line = "[$(Get-Date -f HH:mm:ss)] $msg"
    Add-Content $log $line -Encoding UTF8 -EA SilentlyContinue
    Write-Host $line
}

Log "=== AutoGroups -- $(Get-Date -f 'dd/MM/yyyy HH:mm') ==="

# ---- 1. Recuperer tous les groupes depuis l AD ---------------
$allUsersGrps = @(Get-ADGroup -Filter "Name -like 'GG_*_Users'" `
    -SearchBase $OuSecu -Credential $ADCredential -EA SilentlyContinue)

$allSvcGrps = @(Get-ADGroup -Filter "Name -like 'GG_SVC_*'" `
    -SearchBase $OuSecu -Credential $ADCredential -EA SilentlyContinue)

Log "  GG_*_Users trouves ($($allUsersGrps.Count)) : $($allUsersGrps.Name -join ', ')"
Log "  GG_SVC_*   trouves ($($allSvcGrps.Count))   : $($allSvcGrps.Name -join ', ')"
Log ""

if ($allUsersGrps.Count -eq 0 -or $allSvcGrps.Count -eq 0) {
    Log "  [ERR] Groupes absents -- verifier scripts 02 et 04"
    exit 1
}

# ---- 2. Charger les membres de chaque groupe en cache --------
# (evite de requeter l AD a chaque iteration)
$membersCache = @{}

foreach ($g in ($allUsersGrps + $allSvcGrps)) {
    $members = @(Get-ADGroupMember $g.Name -Credential $ADCredential -EA SilentlyContinue |
        Select-Object -ExpandProperty SamAccountName)
    $membersCache[$g.Name] = $members
}

# ---- 3. Construire la carte GG_*_Users --> GG_SVC_* associes
# Methode : pour chaque GG_*_Users, trouver les GG_SVC_*
# dont les membres se chevauchent le plus avec ce groupe
# Un GG_SVC_* appartient au meme dept si au moins 1 membre est commun

$usersGrpToSvcGrps = @{}

foreach ($ug in $allUsersGrps) {
    $ugMembers = $membersCache[$ug.Name]
    if ($ugMembers.Count -eq 0) {
        Log "  [SKIP] $($ug.Name) vide -- pas de membres"
        continue
    }

    $matchedSvc = @()
    foreach ($sg in $allSvcGrps) {
        $sgMembers = $membersCache[$sg.Name]
        if ($sgMembers.Count -eq 0) { continue }

        # Chevauchement : au moins 1 membre en commun
        $overlap = $ugMembers | Where-Object { $sgMembers -contains $_ }
        if ($overlap.Count -gt 0) {
            $matchedSvc += $sg.Name
        }
    }

    if ($matchedSvc.Count -gt 0) {
        $usersGrpToSvcGrps[$ug.Name] = $matchedSvc
        Log "  [MAP] $($ug.Name) --> $($matchedSvc -join ', ')"
    } else {
        Log "  [WARN] $($ug.Name) : aucun GG_SVC_* avec membres communs"
    }
}

Log ""

# ---- 4. Appliquer les affectations manquantes ----------------
$users = Get-ADUser -Filter { Enabled -eq $true } `
    -SearchBase "OU=Utilisateurs,$SiteDN" -SearchScope Subtree `
    -Properties MemberOf `
    -Credential $ADCredential

$added = 0

foreach ($u in $users) {
    # Groupes actuels du user
    $currentGrps = @($u.MemberOf | ForEach-Object {
        (Get-ADGroup $_ -EA SilentlyContinue).Name
    } | Where-Object { $_ })

    # Trouver son GG_*_Users
    $usersGrp = $currentGrps |
        Where-Object { $usersGrpToSvcGrps.ContainsKey($_) } |
        Select-Object -First 1

    if (-not $usersGrp) { continue }

    # Ajouter dans chaque GG_SVC_* associe si absent
    foreach ($svcGrp in $usersGrpToSvcGrps[$usersGrp]) {
        if ($currentGrps -contains $svcGrp) { continue }

        try {
            Add-ADGroupMember -Identity $svcGrp -Members $u.SamAccountName `
                -Credential $ADCredential -EA Stop
            # Mettre a jour le cache
            $membersCache[$svcGrp] += $u.SamAccountName
            Log "  [OK] $($u.SamAccountName) --> $svcGrp"
            $added++
        } catch {
            Log "  [ERR] $($u.SamAccountName) --> $svcGrp : $_"
        }
    }
}

Log ""
Log "=== Fin : $added affectations ajoutees ==="
