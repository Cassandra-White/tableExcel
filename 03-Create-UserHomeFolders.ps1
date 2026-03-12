# 03-Create-UserHomeFolders.ps1 -- BillU Sprint 5
# Cree D:\Partages\Homes\[login] pour chaque user actif
# Permission : utilisateur seul = FullControl, admins = FullControl

. ".\00-Config.ps1"
$DomInfo = Get-ADDomain -Credential $ADCredential
$SiteDN  = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$($DomInfo.DistinguishedName)"
$HomesRoot = "D:\Partages\Homes"
$Created = 0

$users = Get-ADUser -Filter {Enabled -eq $true} `
    -SearchBase "OU=Utilisateurs,$SiteDN" -SearchScope Subtree `
    -Credential $ADCredential

foreach ($u in $users) {
    $dir = "$HomesRoot\$($u.SamAccountName)"
    if (Test-Path $dir) { continue }

    New-Item $dir -ItemType Directory -Force | Out-Null

    # ACL : uniquement l utilisateur + Administrateurs
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BILLU\$($u.SamAccountName)","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
    Set-Acl $dir $acl
    Write-Host "[OK] $dir"
    $Created++
}
Write-Host "=== $Created dossiers homes crees ==="
