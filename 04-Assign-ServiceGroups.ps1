# 04-Assign-ServiceGroups.ps1 -- BillU Sprint 5
# Met chaque user dans son groupe GG_SVC_[service]
# La Description AD du user (renseignee par 03-Import-Users.ps1) = CSVName du service

. ".\00-Config.ps1"
$DomInfo = Get-ADDomain -Credential $ADCredential
$SiteDN  = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$($DomInfo.DistinguishedName)"

# Index CSVName -> OUName (depuis $Departements de 00-Config.ps1)
$SvcIdx = @{}
foreach ($D in $Departements) {
    foreach ($S in $D.Services) {
        $SvcIdx[$S.CSVName.ToLower().Trim()] = $S.OUName
    }
}

$users = Get-ADUser -Filter {Enabled -eq $true} `
    -SearchBase "OU=Utilisateurs,$SiteDN" -SearchScope Subtree `
    -Properties Description -Credential $ADCredential

$Added = 0
foreach ($u in $users) {
    $key = $u.Description?.ToLower().Trim()
    if (-not $key -or -not $SvcIdx.ContainsKey($key)) { continue }
    $grp = "GG_SVC_$($SvcIdx[$key])"
    try {
        Add-ADGroupMember -Identity $grp -Members $u.SamAccountName `
            -Credential $ADCredential -ErrorAction Stop
        $Added++
    } catch { }
}
Write-Host "=== $Added affectations de service effectuees ==="
