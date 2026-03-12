#Requires -RunAsAdministrator
# 02-Create-Folders-And-Groups.ps1 -- BillU Sprint 5
# Cree l arborescence D:\Partages, les groupes GG_SVC_* et les ACL NTFS
# Dot-source 00-Config.ps1 pour heriter de $Departements

. ".\00-Config.ps1"

$DomInfo = Get-ADDomain -Credential $ADCredential
$DN      = $DomInfo.DistinguishedName
$SiteDN  = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$DN"
$OuSecu  = "OU=Groupes-Securite,OU=Groupes,$SiteDN"
$Base    = "D:\Partages"

# ---- 1. Arborescence de base ----
foreach ($dir in @("$Base\Homes","$Base\Services","$Base\Departements")) {
    New-Item $dir -ItemType Directory -Force | Out-Null
}

# ---- 2. Groupes et dossiers de service (J:) ----
Write-Host "=== Groupes de service ==="
foreach ($Dept in $Departements) {
    foreach ($Svc in $Dept.Services) {
        $grpName = "GG_SVC_$($Svc.OUName)"
        $dir     = "$Base\Services\$($Svc.OUName)"

        # Creer le groupe GG_SVC_ si absent
        if (-not (Get-ADGroup -Filter "Name -eq '$grpName'" -Credential $ADCredential -EA SilentlyContinue)) {
            New-ADGroup -Name $grpName -GroupScope Global -GroupCategory Security `
                -Path $OuSecu -Description "Acces J: service $($Svc.OUName)" `
                -Credential $ADCredential
            Write-Host "  [NEW] $grpName"
        } else { Write-Host "  [OK] $grpName existe" }

        # Creer le dossier
        New-Item $dir -ItemType Directory -Force | Out-Null

        # ACL NTFS : Administrateurs = FullControl | GG_SVC_ = Modify | autres = rien
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)   # Couper l heritage
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BILLU\$grpName","Modify","ContainerInherit,ObjectInherit","None","Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
        Set-Acl $dir $acl
    }
}

# ---- 3. Dossiers et ACL de departement (K:) ----
Write-Host "=== Dossiers de departement ==="
$deptMap = @{
    "Direction"="GG_DIRECTION_Users"; "Dev-Logiciel"="GG_DEV_Users"
    "DSI"="GG_DSI_Users"; "Commercial"="GG_COMMERCIAL_Users"
    "Communication"="GG_COMM_Users"; "Juridique"="GG_JURIDIQUE_Users"
    "Finance"="GG_FINANCE_Users"; "QHSE"="GG_QHSE_Users"
    "Recrutement"="GG_RH_Users"
}
foreach ($dept in $deptMap.Keys) {
    $dir = "$Base\Departements\$dept"
    New-Item $dir -ItemType Directory -Force | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BILLU\$($deptMap[$dept])","Modify","ContainerInherit,ObjectInherit","None","Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
    Set-Acl $dir $acl
    Write-Host "  [OK] $dept -> $($deptMap[$dept])"
}

# ---- 4. Dossier Homes (I:) -- acces parent interdit, sous-dossiers crees par script ----
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
Set-Acl "$Base\Homes" $acl

Write-Host ""
Write-Host "=== Arborescence cree dans D:\Partages ==="
Get-ChildItem "$Base" -Recurse -Directory | Select-Object FullName | Format-Table
