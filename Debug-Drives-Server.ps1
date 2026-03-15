#Requires -RunAsAdministrator
# Debug-Drives-Server.ps1 -- BillU Sprint 5
# Diagnostic depuis DC1 : partages, dossiers, ACL, user specifique
# Ne necessite pas les groupes AD -- verification directe

$base    = "D:\Partages"
$dc1     = "\\DC1"

# Modifier ces deux lignes avant de lancer
$domaine = "billu.local"
$testUser = "prenom.nom"   # login de l utilisateur qui a le probleme

Write-Host "================================================="
Write-Host " DIAGNOSTIC DC1 -- $domaine"
Write-Host "================================================="
Write-Host ""

# -- 1. Partages SMB -------------------------------------------
Write-Host "--- 1. Partages SMB ---"
foreach ($share in @("Homes","Services","Departements")) {
    $s = Get-SmbShare -Name $share -EA SilentlyContinue
    if ($s) {
        Write-Host "  [OK]  $share --> $($s.Path)"
    } else {
        Write-Host "  [!!!] $share ABSENT -- relancer le script 05"
    }
}
Write-Host ""

# -- 2. Dossiers physiques -------------------------------------
Write-Host "--- 2. Dossiers physiques D:\Partages ---"
foreach ($d in @("Homes","Services","Departements")) {
    $path = "$base\$d"
    if (Test-Path $path) {
        $subs = (Get-ChildItem $path -Directory -EA SilentlyContinue).Count
        Write-Host "  [OK]  $path ($subs sous-dossiers)"
    } else {
        Write-Host "  [!!!] $path ABSENT -- relancer le script 02"
    }
}
Write-Host ""

# -- 3. Contenu des sous-dossiers ------------------------------
Write-Host "--- 3. Contenu de D:\Partages\Services ---"
Get-ChildItem "$base\Services" -Directory -EA SilentlyContinue |
    ForEach-Object { Write-Host "  $($_.Name)" }

Write-Host ""
Write-Host "--- 4. Contenu de D:\Partages\Departements ---"
Get-ChildItem "$base\Departements" -Directory -EA SilentlyContinue |
    ForEach-Object { Write-Host "  $($_.Name)" }
Write-Host ""

# -- 4. ACL sur les racines ------------------------------------
Write-Host "--- 5. ACL sur les dossiers racines ---"
foreach ($d in @("Homes","Services","Departements")) {
    $path = "$base\$d"
    if (-not (Test-Path $path)) { continue }
    Write-Host "  $path :"
    (Get-Acl $path).Access |
        Format-Table IdentityReference, FileSystemRights, InheritanceFlags -AutoSize |
        Out-String | ForEach-Object { Write-Host "  $_" }
}

# -- 5. ACL sur les sous-dossiers Services ---------------------
Write-Host "--- 6. ACL sous-dossiers Services ---"
Get-ChildItem "$base\Services" -Directory -EA SilentlyContinue | ForEach-Object {
    Write-Host "  $($_.FullName) :"
    (Get-Acl $_.FullName).Access |
        Format-Table IdentityReference, FileSystemRights -AutoSize |
        Out-String | ForEach-Object { Write-Host "  $_" }
}

# -- 6. ACL sur les sous-dossiers Departements -----------------
Write-Host "--- 7. ACL sous-dossiers Departements ---"
Get-ChildItem "$base\Departements" -Directory -EA SilentlyContinue | ForEach-Object {
    Write-Host "  $($_.FullName) :"
    (Get-Acl $_.FullName).Access |
        Format-Table IdentityReference, FileSystemRights -AutoSize |
        Out-String | ForEach-Object { Write-Host "  $_" }
}

# -- 7. Groupes AD de l utilisateur test -----------------------
Write-Host "--- 8. Groupes AD de $testUser ---"
try {
    $u = Get-ADUser $testUser -Properties MemberOf -EA Stop
    Write-Host "  User trouve : $($u.SamAccountName) -- $($u.DisplayName)"
    Write-Host "  Groupes :"
    $u.MemberOf | ForEach-Object {
        $g = Get-ADGroup $_ -EA SilentlyContinue
        if ($g) { Write-Host "    - $($g.Name)" }
    }
} catch {
    Write-Host "  [!!!] Utilisateur '$testUser' introuvable : $_"
}
Write-Host ""

Write-Host "================================================="
Write-Host " Fin du diagnostic -- copiez le resultat"
Write-Host "================================================="
