#Requires -RunAsAdministrator
# 02-Create-Folders-And-Groups.ps1 -- BillU Sprint 5

. ".\00-Config.ps1"

$DomInfo     = Get-ADDomain -Credential $ADCredential
$DN          = $DomInfo.DistinguishedName
$SiteDN      = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$DN"
$OuSecu      = "OU=Groupes-Securite,OU=Groupes,$SiteDN"
$script:Base = "D:\Partages"
$script:NB   = $DomInfo.NetBIOSName

# ---- Resolution des SIDs avec validation explicite ----------------
Write-Host "=== Resolution des SIDs ==="

# SIDs hardcodes (jamais null)
$script:SID_Admins = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
$script:SID_System = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
$script:SID_Auth   = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")

Write-Host "  [OK] S-1-5-32-544 = Administrators"
Write-Host "  [OK] S-1-5-18     = SYSTEM"
Write-Host "  [OK] S-1-5-11     = Authenticated Users"

# SIDs AD -- avec null-check explicite
$grpDomAdmins = Get-ADGroup "Domain Admins" -Credential $ADCredential -EA SilentlyContinue
if (-not $grpDomAdmins) { Write-Error "Groupe 'Domain Admins' introuvable"; exit 1 }
$script:SID_DomAdmins = $grpDomAdmins.SID
Write-Host "  [OK] Domain Admins : $($script:SID_DomAdmins)"

$grpDSIAdmins = Get-ADGroup "GG_DSI_Admins" -Credential $ADCredential -EA SilentlyContinue
if (-not $grpDSIAdmins) { Write-Error "Groupe 'GG_DSI_Admins' introuvable -- verifier script 01 (creation groupes)"; exit 1 }
$script:SID_DSIAdmins = $grpDSIAdmins.SID
Write-Host "  [OK] GG_DSI_Admins : $($script:SID_DSIAdmins)"

Write-Host ""

# ============================================================
# Helper interne : creer une regle NTFS a partir d un SID
# avec validation null pour eviter l erreur .ctor
# ============================================================
function New-AclRule {
    param(
        [System.Security.Principal.SecurityIdentifier]$Sid,
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [System.Security.AccessControl.InheritanceFlags]$Inherit,
        [System.Security.AccessControl.PropagationFlags]$Propagate
    )

    if ($null -eq $Sid) {
        Write-Error "New-AclRule : SID est null -- impossible de creer la regle"
        return $null
    }

    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Sid,
        $Rights,
        $Inherit,
        $Propagate,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
}

# ============================================================
# Get-AdminACL
# 4 SIDs admin avec FullControl + regles $Extra
# Heritage coupe
# ============================================================
function Get-AdminACL {
    param([System.Security.AccessControl.FileSystemAccessRule[]]$Extra = @())

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)

    $inhAll = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $propNo = [System.Security.AccessControl.PropagationFlags]::None
    $full   = [System.Security.AccessControl.FileSystemRights]::FullControl

    foreach ($sid in @(
        $script:SID_Admins,
        $script:SID_System,
        $script:SID_DomAdmins,
        $script:SID_DSIAdmins
    )) {
        $rule = New-AclRule -Sid $sid -Rights $full -Inherit $inhAll -Propagate $propNo
        if ($rule) { $acl.AddAccessRule($rule) }
    }

    foreach ($r in $Extra) {
        if ($r) { $acl.AddAccessRule($r) }
    }

    return $acl
}

# ============================================================
# Get-RootACL
# Comme Get-AdminACL + Authenticated Users ReadAndExecute
# sur CE dossier UNIQUEMENT (InheritanceFlags.None)
# Permet aux users de traverser la racine pour atteindre
# leur sous-dossier (ABE masquera le reste)
# ============================================================
function Get-RootACL {
    $acl = Get-AdminACL   # 4 admins FullControl

    # Authenticated Users : ReadAndExecute, ce dossier seulement
    $rAuth = New-AclRule `
        -Sid       $script:SID_Auth `
        -Rights    ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) `
        -Inherit   ([System.Security.AccessControl.InheritanceFlags]::None) `
        -Propagate ([System.Security.AccessControl.PropagationFlags]::None)

    if ($rAuth) { $acl.AddAccessRule($rAuth) }
    return $acl
}

$inhAll = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$propNo = [System.Security.AccessControl.PropagationFlags]::None
$mod    = [System.Security.AccessControl.FileSystemRights]::Modify

# ---- 1. Dossiers racines avec Get-RootACL ----------------------
Write-Host "=== Dossiers racines ==="
foreach ($d in @("$script:Base\Homes","$script:Base\Services","$script:Base\Departements")) {
    New-Item $d -ItemType Directory -Force | Out-Null
    Set-Acl $d (Get-RootACL)
    Write-Host "  [OK] $d"
    Write-Host "         4 admins = FullControl | Authenticated Users = ReadAndExecute (racine seule)"
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
            Write-Host "  [OK]  Groupe : $grp"
        }

        New-Item $dir -ItemType Directory -Force | Out-Null

        $grpObj = Get-ADGroup $grp -Credential $ADCredential -EA SilentlyContinue
        if (-not $grpObj) {
            Write-Warning "  [SKIP ACL] $grp introuvable apres creation -- verifier l AD"
            continue
        }

        $rSvc = New-AclRule -Sid $grpObj.SID -Rights $mod -Inherit $inhAll -Propagate $propNo
        Set-Acl $dir (Get-AdminACL -Extra @($rSvc))
        Write-Host "  [ACL] $dir -- 4 admins=FullControl | $grp=Modify"
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

    $grpObj = Get-ADGroup $grpUsr -Credential $ADCredential -EA SilentlyContinue
    if (-not $grpObj) {
        Write-Warning "  [SKIP ACL] $grpUsr introuvable -- le groupe existe dans l AD ?"
        Set-Acl $dir (Get-AdminACL)
        continue
    }

    $rDept = New-AclRule -Sid $grpObj.SID -Rights $mod -Inherit $inhAll -Propagate $propNo
    Set-Acl $dir (Get-AdminACL -Extra @($rDept))
    Write-Host "  [OK] $dept -- 4 admins=FullControl | $grpUsr=Modify"
}

# ---- 4. Verification finale ------------------------------------
Write-Host ""
Write-Host "=== Verification ACL ==="
Write-Host "-- Racines (Authenticated Users doit etre present) --"
foreach ($racine in @("Homes","Services","Departements")) {
    $path = "$script:Base\$racine"
    $acl  = (Get-Acl $path).Access

    $hasAuth = $acl | Where-Object {
        try {
            $_.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]).Value -eq "S-1-5-11"
        } catch { $false }
    }
    $hasDSI = $acl | Where-Object {
        try {
            $_.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]).Value -eq $script:SID_DSIAdmins.Value
        } catch { $false }
    }

    $tAuth = if ($hasAuth) { "OK" } else { "!!! MANQUANT" }
    $tDSI  = if ($hasDSI)  { "OK" } else { "!!! MANQUANT" }
    Write-Host "  $racine : Auth Users=[$tAuth]  GG_DSI_Admins=[$tDSI]"
}

Write-Host ""
Write-Host "=== Script 02 termine -- lancer 03-Create-UserHomeFolders.ps1 ==="
