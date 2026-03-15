# Debug-Drives.ps1 -- BillU Sprint 5
# Diagnostic complet des lecteurs J: et K: non mappes
# A executer sur le CLIENT en tant que l utilisateur concerne

$dc1  = "\\DC1"
$user = $env:USERNAME

Write-Host "================================================="
Write-Host " DIAGNOSTIC LECTEURS BILLU -- $user"
Write-Host "================================================="
Write-Host ""

# -- 1. Groupes dans le token ----------------------------------
Write-Host "--- 1. Groupes GG_* dans votre token Kerberos ---"
$raw  = whoami /groups /fo csv 2>$null | ConvertFrom-Csv
$grps = $raw |
    Where-Object { $_.'Group Name' -match '\\GG_' } |
    ForEach-Object { ($_.'Group Name' -split '\\')[-1] }

if ($grps.Count -eq 0) {
    Write-Host "  [!!!] AUCUN groupe GG_* trouve dans votre token"
    Write-Host "        Cause probable : vous avez ete ajoute aux groupes APRES"
    Write-Host "        votre derniere connexion."
    Write-Host "        Solution : deconnectez-vous completement et reconnectez-vous."
} else {
    Write-Host "  Groupes trouves ($($grps.Count)) :"
    foreach ($g in $grps) { Write-Host "    - $g" }
}
Write-Host ""

# -- 2. Groupe de service (J:) ---------------------------------
Write-Host "--- 2. Groupe de service pour J: ---"
$svcGrps = @($grps | Where-Object { $_ -like "GG_SVC_*" })
if ($svcGrps.Count -eq 0) {
    Write-Host "  [!!!] Aucun groupe GG_SVC_* dans votre token"
    Write-Host "        Le script 04 a-t-il ete execute sur DC1 ?"
    Write-Host "        Verifier : Get-ADGroupMember GG_SVC_[service] sur DC1"
} else {
    foreach ($sg in $svcGrps) {
        $svc   = $sg -replace "^GG_SVC_",""
        $jPath = "$dc1\Services\$svc"
        Write-Host "  Groupe : $sg"
        Write-Host "  Chemin : $jPath"
        if (Test-Path $jPath) {
            Write-Host "  Acces  : [OK] dossier accessible"
        } else {
            Write-Host "  Acces  : [!!!] DOSSIER INACCESSIBLE"
            Write-Host "           Cause 1 : dossier absent sur DC1 (script 02 non execute)"
            Write-Host "           Cause 2 : permissions NTFS insuffisantes sur $jPath"
            Write-Host "           Cause 3 : partage SMB Services non cree (script 05)"
        }
    }
}
Write-Host ""

# -- 3. Groupe de departement (K:) ----------------------------
Write-Host "--- 3. Groupe de departement pour K: ---"
$deptMap = @{
    "GG_DIRECTION_Users"  = "Direction"
    "GG_DEV_Users"        = "Dev-Logiciel"
    "GG_DSI_Users"        = "DSI"
    "GG_COMMERCIAL_Users" = "Commercial"
    "GG_COMM_Users"       = "Communication"
    "GG_JURIDIQUE_Users"  = "Juridique"
    "GG_FINANCE_Users"    = "Finance"
    "GG_QHSE_Users"       = "QHSE"
    "GG_RH_Users"         = "Recrutement"
}

$grpTrouve = $false
foreach ($grp in $deptMap.Keys) {
    if ($grps -contains $grp) {
        $dept  = $deptMap[$grp]
        $kPath = "$dc1\Departements\$dept"
        Write-Host "  Groupe : $grp"
        Write-Host "  Chemin : $kPath"
        if (Test-Path $kPath) {
            Write-Host "  Acces  : [OK] dossier accessible"
        } else {
            Write-Host "  Acces  : [!!!] DOSSIER INACCESSIBLE"
            Write-Host "           Cause 1 : dossier absent sur DC1 (script 02 non execute)"
            Write-Host "           Cause 2 : permissions NTFS insuffisantes sur $kPath"
            Write-Host "           Cause 3 : partage SMB Departements non cree (script 05)"
        }
        $grpTrouve = $true
        break
    }
}
if (-not $grpTrouve) {
    Write-Host "  [!!!] Aucun groupe GG_*_Users reconnu dans votre token"
    Write-Host "        Groupes dispo : $($grps -join ', ')"
    Write-Host "        Le script 04 a-t-il ete execute sur DC1 ?"
}
Write-Host ""

# -- 4. Partages SMB accessibles -------------------------------
Write-Host "--- 4. Partages SMB sur DC1 ---"
foreach ($share in @("Homes","Services","Departements")) {
    $unc = "$dc1\$share"
    if (Test-Path $unc) {
        Write-Host "  [OK]  $unc accessible"
    } else {
        Write-Host "  [!!!] $unc INACCESSIBLE"
        Write-Host "        Verifier le script 05 sur DC1 : Get-SmbShare -Name $share"
    }
}
Write-Host ""

# -- 5. Log du dernier mappage ---------------------------------
Write-Host "--- 5. Dernier log de mappage ---"
$log = "$env:TEMP\BillU-MapDrives.log"
if (Test-Path $log) {
    Write-Host "  Fichier : $log"
    Write-Host "  Contenu (10 dernieres lignes) :"
    Get-Content $log -Tail 10 | ForEach-Object { Write-Host "    $_" }
} else {
    Write-Host "  [!!!] Aucun log trouve -- le script Map-Drives n a pas encore tourne"
    Write-Host "        Verifier la GPO BillU-LecteursReseau dans GPMC sur DC1"
}
Write-Host ""

# -- Conclusion ------------------------------------------------
Write-Host "================================================="
Write-Host " Copiez tout ce qui s affiche et donnez-le"
Write-Host " pour identifier la cause exacte"
Write-Host "================================================="
