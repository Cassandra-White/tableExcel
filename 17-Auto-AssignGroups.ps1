#Requires -RunAsAdministrator
# 17-Auto-AssignGroups.ps1 -- BillU Sprint 5
# Recupere dynamiquement depuis l AD tous les groupes GG_*_Users et GG_SVC_*
# Pour chaque user : si dans GG_[X]_Users --> ajouter dans GG_SVC_[X] du meme dept
# Aucun groupe n est code en dur -- tout vient de l AD et de 00-Config.ps1

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

# ---- Recuperer dynamiquement tous les groupes depuis l AD ---

# Tous les groupes GG_*_Users (groupes de departement)
$allUsersGrps = Get-ADGroup -Filter "Name -like 'GG_*_Users'" `
    -SearchBase $OuSecu -Credential $ADCredential -EA SilentlyContinue |
    Select-Object -ExpandProperty Name

# Tous les groupes GG_SVC_* (groupes de service)
$allSvcGrps = Get-ADGroup -Filter "Name -like 'GG_SVC_*'" `
    -SearchBase $OuSecu -Credential $ADCredential -EA SilentlyContinue |
    Select-Object -ExpandProperty Name

Log "  Groupes GG_*_Users trouves : $($allUsersGrps -join ', ')"
Log "  Groupes GG_SVC_*   trouves : $($allSvcGrps -join ', ')"
Log ""

# ---- Construire la carte dept -> services depuis 00-Config.ps1
# $Departements est defini dans 00-Config.ps1
# Structure : $Departements = @( @{ Name="..."; Services=@( @{ OUName="..." } ) } )

$deptToSvcGrps = @{}   # "Communication" -> @("GG_SVC_Communication", ...)

foreach ($D in $Departements) {
    $svcList = @()
    foreach ($S in $D.Services) {
        $grpName = "GG_SVC_$($S.OUName)"
        # Ne garder que les groupes qui existent reellement dans l AD
        if ($allSvcGrps -contains $grpName) {
            $svcList += $grpName
        }
    }
    if ($svcList.Count -gt 0) {
        $deptToSvcGrps[$D.Name] = $svcList
    }
}

# ---- Construire la carte GG_*_Users -> dept depuis 00-Config.ps1
# On cherche quel dept correspond a chaque GG_*_Users
# Le nom du groupe GG_[X]_Users est derive du nom du dept via la convention BillU
# On fait la correspondance depuis les groupes AD existants

$usersGrpToDept = @{}  # "GG_COMM_Users" -> "Communication"

foreach ($D in $Departements) {
    # Chercher dans les groupes AD lequel correspond a ce dept
    foreach ($grp in $allUsersGrps) {
        # Le groupe est trouve si son DN ou ses membres le rattachent au dept
        # Approche : chercher un groupe GG_*_Users dont le nom contient
        # une partie du nom du dept (approche flexible)
        # Ex: "GG_COMM_Users" pour "Communication" est defini dans 00-Config.ps1
        # On utilise directement la propriete DeptUsersGroup si elle existe
        # Sinon on se base sur la structure $Departements

        # Verifier si 00-Config.ps1 definit DeptGroup ou UsersGroup par dept
        if ($D.ContainsKey("UsersGroup") -and $D.UsersGroup -eq $grp) {
            $usersGrpToDept[$grp] = $D.Name
        }
    }
}

# Si 00-Config.ps1 ne definit pas UsersGroup, on recupere la correspondance
# depuis les membres : le groupe GG_*_Users dont les membres ont les memes
# GG_SVC_* que le dept
# Fallback : demander directement a l AD les membres de chaque GG_SVC_*
# et voir quel GG_*_Users les contient aussi

if ($usersGrpToDept.Count -eq 0) {
    Log "  [INFO] UsersGroup non defini dans 00-Config.ps1 -- deduction par croisement AD"

    foreach ($usersGrp in $allUsersGrps) {
        # Membres de ce GG_*_Users
        $members = Get-ADGroupMember $usersGrp -Credential $ADCredential -EA SilentlyContinue |
            Select-Object -ExpandProperty SamAccountName

        if (-not $members) { continue }

        # Chercher dans quel dept de 00-Config.ps1 les membres de ce groupe
        # ont le plus de GG_SVC_* en commun
        $bestDept  = $null
        $bestScore = 0

        foreach ($D in $Departements) {
            $score = 0
            foreach ($S in $D.Services) {
                $svcGrp = "GG_SVC_$($S.OUName)"
                if ($allSvcGrps -notcontains $svcGrp) { continue }
                $svcMembers = Get-ADGroupMember $svcGrp -Credential $ADCredential -EA SilentlyContinue |
                    Select-Object -ExpandProperty SamAccountName
                # Compter le chevauchement
                $score += ($members | Where-Object { $svcMembers -contains $_ }).Count
            }
            if ($score -gt $bestScore) {
                $bestScore = $score
                $bestDept  = $D.Name
            }
        }

        if ($bestDept) {
            $usersGrpToDept[$usersGrp] = $bestDept
            Log "  [MAP] $usersGrp --> dept : $bestDept (score : $bestScore)"
        }
    }
}

Log ""
Log "  Correspondances trouvees :"
foreach ($k in $usersGrpToDept.Keys) {
    $svcList = if ($deptToSvcGrps.ContainsKey($usersGrpToDept[$k])) {
        $deptToSvcGrps[$usersGrpToDept[$k]] -join ', '
    } else { "(aucun service)" }
    Log "    $k --> $($usersGrpToDept[$k]) --> $svcList"
}
Log ""

# ---- Parcourir tous les users actifs -------------------------
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

    # Trouver dans quel GG_*_Users il est
    $usersGrp = $currentGrps |
        Where-Object { $usersGrpToDept.ContainsKey($_) } |
        Select-Object -First 1

    if (-not $usersGrp) { continue }

    $deptName = $usersGrpToDept[$usersGrp]
    if (-not $deptToSvcGrps.ContainsKey($deptName)) { continue }

    # Ajouter dans chaque GG_SVC_* du dept si absent
    foreach ($svcGrp in $deptToSvcGrps[$deptName]) {
        if ($currentGrps -contains $svcGrp) { continue }

        try {
            Add-ADGroupMember -Identity $svcGrp -Members $u.SamAccountName `
                -Credential $ADCredential -EA Stop
            Log "  [OK] $($u.SamAccountName) --> $svcGrp"
            $added++
        } catch {
            Log "  [ERR] $($u.SamAccountName) --> $svcGrp : $_"
        }
    }
}

Log ""
Log "=== Fin : $added affectations ajoutees ==="
