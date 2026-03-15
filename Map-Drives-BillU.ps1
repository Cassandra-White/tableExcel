#Requires -Version 3
# Map-Drives-BillU.ps1 -- BillU Sprint 5
# Deposer dans : \\DC1\NETLOGON\scripts\Map-Drives-BillU.ps1

$dc1  = "\\DC1"
$user = $env:USERNAME
$log  = "$env:TEMP\BillU-MapDrives.log"

function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    try { Add-Content $log $line -Encoding UTF8 -EA SilentlyContinue } catch {}
    Write-Host $line
}

# Refresh Explorateur Windows apres mappage
function Refresh-Shell {
    try {
        $code = @'
using System;
using System.Runtime.InteropServices;
public class ShellRefresh {
    [DllImport("shell32.dll")]
    public static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
    public static void Refresh() { SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero); }
}
'@
        Add-Type -TypeDefinition $code -EA SilentlyContinue
        [ShellRefresh]::Refresh()
    } catch {}
}

Log "=== BillU MapDrives -- $user ==="

# -- Supprimer les anciens mappages ----------------------------
foreach ($l in @("I","J","K")) {
    net use "${l}:" /delete /y 2>$null | Out-Null
}
Log "  Anciens mappages supprimes"

# -- Recuperer les groupes via whoami --------------------------
$grps = @()
try {
    $raw  = whoami /groups /fo csv 2>$null | ConvertFrom-Csv
    $grps = $raw |
        Where-Object { $_.'Group Name' -match '\\GG_' } |
        ForEach-Object { ($_.'Group Name' -split '\\')[-1] }
    Log "  [OK] $($grps.Count) groupes GG_* : $($grps -join ', ')"
} catch { Log "  [ERR] whoami : $_" }

# Fallback ADSI
if ($grps.Count -eq 0) {
    try {
        $s = [adsisearcher]"(samaccountname=$user)"
        $s.PropertiesToLoad.Add("memberof") | Out-Null
        $r = $s.FindOne()
        if ($r) {
            $grps = $r.Properties["memberof"] | ForEach-Object {
                if ($_ -match '^CN=([^,]+)') { $matches[1] }
            } | Where-Object { $_ -like "GG_*" }
            Log "  [ADSI] $($grps.Count) groupes : $($grps -join ', ')"
        }
    } catch { Log "  [ERR] ADSI : $_" }
}

# -- Detecter si l utilisateur est admin -----------------------
# Domain Admins SID = S-1-5-domain-512, plus simple : tester whoami /groups
$isAdmin = $false
try {
    $allGrps = whoami /groups /fo csv 2>$null | ConvertFrom-Csv
    $isAdmin = $allGrps | Where-Object {
        $_.'Group Name' -match 'Domain Admins|Administrateurs du domaine|BUILTIN\\Administrators|BUILTIN\\Administrateurs'
    }
    if ($isAdmin) { Log "  Compte admin detecte -- acces complet J: K:" }
} catch {}

# -- I: -- Dossier individuel ----------------------------------
net use I: "$dc1\Homes\$user" /persistent:yes 2>$null | Out-Null
if (Test-Path "I:\") {
    Log "  [OK] I: --> $dc1\Homes\$user"
} else {
    net use I: "$dc1\Homes" /persistent:yes 2>$null | Out-Null
    if (Test-Path "I:\") {
        Log "  [OK] I: --> $dc1\Homes (racine)"
    } else {
        Log "  [ERR] I: echec sur $dc1\Homes"
    }
}

# -- J: -- Service ou racine pour les admins -------------------
$jMapped = $false

# Cas 1 : user normal avec groupe GG_SVC_*
$svcGrps = @($grps | Where-Object { $_ -like "GG_SVC_*" })
foreach ($sg in $svcGrps) {
    $svc = $sg -replace "^GG_SVC_",""
    net use J: "$dc1\Services\$svc" /persistent:yes 2>$null | Out-Null
    if (Test-Path "J:\") {
        Log "  [OK] J: --> $dc1\Services\$svc ($sg)"
        $jMapped = $true
        break
    }
}

# Cas 2 : admin ou pas de groupe -- mapper la racine Services
if (-not $jMapped) {
    net use J: "$dc1\Services" /persistent:yes 2>$null | Out-Null
    if (Test-Path "J:\") {
        Log "  [OK] J: --> $dc1\Services (racine -- tous les services visibles)"
        $jMapped = $true
    } else {
        Log "  [ERR] J: echec meme sur $dc1\Services"
        Log "         Verifier que le partage SMB 'Services' existe sur DC1"
    }
}

# -- K: -- Departement ou racine pour les admins ---------------
$kMapped = $false

# Cas 1 : user normal avec groupe GG_*_Users
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
foreach ($grp in $deptMap.Keys) {
    if ($grps -contains $grp) {
        $dept = $deptMap[$grp]
        net use K: "$dc1\Departements\$dept" /persistent:yes 2>$null | Out-Null
        if (Test-Path "K:\") {
            Log "  [OK] K: --> $dc1\Departements\$dept ($grp)"
            $kMapped = $true
            break
        }
    }
}

# Cas 2 : admin ou pas de groupe -- mapper la racine Departements
if (-not $kMapped) {
    net use K: "$dc1\Departements" /persistent:yes 2>$null | Out-Null
    if (Test-Path "K:\") {
        Log "  [OK] K: --> $dc1\Departements (racine -- tous les departements visibles)"
        $kMapped = $true
    } else {
        Log "  [ERR] K: echec meme sur $dc1\Departements"
        Log "         Verifier que le partage SMB 'Departements' existe sur DC1"
    }
}

# -- Refresh Explorateur ---------------------------------------
Refresh-Shell
Log ""
Log "=== Bilan : I=$(Test-Path 'I:\') J=$(Test-Path 'J:\') K=$(Test-Path 'K:\') ==="
Log "  Log : $log"
