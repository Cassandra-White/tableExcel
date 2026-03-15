#Requires -RunAsAdministrator
# 02-Create-Folders-And-Groups.ps1 -- BillU Sprint 5
# CORRECTION : utilise les SIDs (invariants selon la langue Windows)
# Ajoute GG_DSI_Admins (FullControl partout)
# Ajoute Authenticated Users (Traverse/List RACINE seulement) pour la visibilite ABE

. ".\00-Config.ps1"

$DomInfo     = Get-ADDomain -Credential $ADCredential
$DN          = $DomInfo.DistinguishedName
$SiteDN      = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$DN"
$OuSecu      = "OU=Groupes-Securite,OU=Groupes,$SiteDN"
$script:Base = "D:\Partages"
$script:NB   = $DomInfo.NetBIOSName

# SIDs recuperes une seule fois -- accessibles dans les fonctions via $script:
$script:DomAdminsSID = (Get-ADGroup "Domain Admins" -Credential $ADCredential).SID
$script:DSIAdminsSID = (Get-ADGroup "GG_DSI_Admins" -Credential $ADCredential).SID

# SID Authenticated Users (S-1-5-11) -- invariant toutes langues
$script:AuthUsersSID = [System.Security.Principal.SecurityIdentifier]"S-1-5-11"

Write-Host "=== SIDs resolus ==="
Write-Host "  S-1-5-32-544 : Administrators"
Write-Host "  S-1-5-18     : SYSTEM"
Write-Host "  S-1-5-11     : Authenticated Users"
Write-Host "  Domain Admins  : $($script:DomAdminsSID)"
Write-Host "  GG_DSI_Admins  : $($script:DSIAdminsSID)"
Write-Host ""

# ============================================================
# Get-AdminACL
# Pose les 4 SIDs admin avec FullControl + regles $Extra
# Heritage coupe (SetAccessRuleProtection $true $false)
# ============================================================
function Get-AdminACL {
    param([System.Security.AccessControl.FileSystemAccessRule[]]$Extra = @())

    $acl  = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)

    $inh  = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $prop = [System.Security.AccessControl.PropagationFlags]::None
    $alw  = [System.Security.AccessControl.AccessControlType]::Allow
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl

    # 4 admins en FullControl sur ce dossier et tous ses enfants
    foreach ($sid in @(
        [System.Security.Principal.SecurityIdentifier]"S-1-5-32-544",
        [System.Security.Principal.SecurityIdentifier]"S-1-5-18",
        $script:DomAdminsSID,
        $script:DSIAdminsSID
    )) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, $full, $inh, $prop, $alw)))
    }

    foreach ($r in $Extra) { $acl.AddAccessRule($r) }
    return $acl
}

# ============================================================
# Get-RootACL
# Identique a Get-AdminACL PLUS Authenticated Users en
# ReadAndExecute sur CE DOSSIER UNIQUEMENT (pas de propagation)
#
# Pourquoi ? Avec ABE (AccessBased Enumeration) active sur le
# partage SMB, Windows n affiche a un user que les sous-dossiers
# sur lesquels il a des droits explicites. Mais pour que Windows
# puisse meme lister le contenu de la racine du partage, le user
# doit avoir au minimum Traverse/List sur ce dossier racine.
# "ThisFolderOnly" = InheritanceFlags.None + PropagationFlags.None
# ============================================================
function Get-RootACL {
    $acl = Get-AdminACL   # 4 admins FullControl herites

    # Authenticated Users : ReadAndExecute sur ce dossier UNIQUEMENT
    # InheritanceFlags.None  = ne se propage pas aux sous-dossiers
    # PropagationFlags.None  = s applique uniquement ici
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $script:AuthUsersSID,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )))

    return $acl
}

$inh  = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$prop = [System.Security.AccessControl.PropagationFlags]::None
$alw  = [System.Security.AccessControl.AccessControlType]::Allow
$mod  = [System.Security.AccessControl.FileSystemRights]::Modify

# ---- 1. Dossiers racines avec Get-RootACL ----------------------
Write-Host "=== Dossiers racines ==="
foreach ($d in @("$script:Base\Homes","$script:Base\Services","$script:Base\Departements")) {
    New-Item $d -ItemType Directory -Force | Out-Null
    Set-Acl $d (Get-RootACL)
    Write-Host "  [OK] $d"
    Write-Host "         Admins (x4) = FullControl | Authenticated Users = ReadAndExecute (racine seule)"
}

# ---- 2. Dossiers de service J: ---------------------------------
Write-Host ""
Write-Host "=== Groupes et dossiers de service (J:) ==="
foreach ($Dept in $Departements) {
    foreach ($Svc in $Dept.Services) {
        $grp = "GG_SVC_$($Svc.OUName)"
        $dir = "$script:Base\Services\$($Svc.OUName)"

        if (-not (Get-ADGroup -Filter "Name -eq '$grp'" -Credential $ADCredential -EA SilentlyContinue)) {
            New-ADGroup -Name $grp -GroupScope Global -GroupCategory Security `
                -Path $OuSecu -Description "Acces J: $($Svc.OUName)" -Credential $ADCredential
            Write-Host "  [NEW] Groupe : $grp"
        } else {
            Write-Host "  [OK]  Groupe : $grp existe"
        }

        New-Item $dir -ItemType Directory -Force | Out-Null

        $grpSID = (Get-ADGroup $grp -Credential $ADCredential).SID
        $rSvc   = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $grpSID, $mod, $inh, $prop, $alw)

        # Get-AdminACL (sans Authenticated Users) car ce dossier
        # doit etre visible UNIQUEMENT par les membres de GG_SVC_*
        Set-Acl $dir (Get-AdminACL -Extra @($rSvc))
        Write-Host "  [ACL] $dir"
        Write-Host "         Admins (x4) = FullControl | $grp = Modify"
    }
}

# ---- 3. Dossiers de departement K: -----------------------------
Write-Host ""
Write-Host "=== Dossiers de departement (K:) ==="
$deptMap = @{
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

foreach ($dept in $deptMap.Keys) {
    $dir    = "$script:Base\Departements\$dept"
    $grpUsr = $deptMap[$dept]

    New-Item $dir -ItemType Directory -Force | Out-Null

    $grpSID = (Get-ADGroup $grpUsr -Credential $ADCredential).SID
    $rDept  = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $grpSID, $mod, $inh, $prop, $alw)

    Set-Acl $dir (Get-AdminACL -Extra @($rDept))
    Write-Host "  [OK] $dept"
    Write-Host "         Admins (x4) = FullControl | $grpUsr = Modify"
}

# ---- 4. Verification finale ------------------------------------
Write-Host ""
Write-Host "=== Verification ACL ==="

# Racines : verifier que Authenticated Users est bien present (ThisFolderOnly)
Write-Host "-- Racines (doivent avoir Authenticated Users ReadAndExecute) --"
foreach ($racine in @("Homes","Services","Departements")) {
    $path = "$script:Base\$racine"
    $acl  = Get-Acl $path
    $hasAuth = $acl.Access | Where-Object {
        try {
            $_.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value -eq "S-1-5-11" -and
            $_.InheritanceFlags -eq [System.Security.AccessControl.InheritanceFlags]::None
        } catch { $false }
    }
    $hasDSI = $acl.Access | Where-Object {
        try {
            $_.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value -eq $script:DSIAdminsSID.Value
        } catch { $false }
    }
    $tagAuth = if ($hasAuth) { "OK" } else { "!!! MANQUANT" }
    $tagDSI  = if ($hasDSI)  { "OK" } else { "!!! MANQUANT" }
    Write-Host "  $racine : Auth Users=[$tagAuth]  GG_DSI_Admins=[$tagDSI]"
}

# Sous-dossiers : verifier GG_DSI_Admins
Write-Host ""
Write-Host "-- Sous-dossiers (GG_DSI_Admins doit avoir FullControl) --"
$allDirs = Get-ChildItem $script:Base -Recurse -Directory
foreach ($d in $allDirs) {
    $acl = Get-Acl $d.FullName
    $hasDSI = $acl.Access | Where-Object {
        try {
            $_.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value -eq $script:DSIAdminsSID.Value -and
            $_.FileSystemRights -match "FullControl"
        } catch { $false }
    }
    $tag = if ($hasDSI) { "OK" } else { "!!! GG_DSI_Admins MANQUANT" }
    Write-Host "  [$tag] $($d.FullName)"
}

Write-Host ""
Write-Host "=== Script 02 termine -- lancer 03-Create-UserHomeFolders.ps1 ==="
