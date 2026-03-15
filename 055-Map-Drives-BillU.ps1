#Requires -Version 3
# Map-Drives-BillU.ps1 -- BillU Sprint 5
# Mappe I: (home), J: (service), K: (departement) selon les groupes AD
# Deposer dans : \\DC1\NETLOGON\scripts\Map-Drives-BillU.ps1
# Utilise comme logon script via GPO BillU-LecteursReseau

# -- Parametres ------------------------------------------------
$dc1    = "\\DC1"
$user   = $env:USERNAME
$domain = $env:USERDOMAIN
$log    = "$env:TEMP\BillU-MapDrives.log"

# -- Log -------------------------------------------------------
function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    try { Add-Content -Path $log -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    Write-Host $line
}

Log "=== Mappage lecteurs BillU -- $user ($domain) ==="

# -- Supprimer les anciens mappages ----------------------------
foreach ($lettre in @("I","J","K")) {
    $drive = "${lettre}:"
    if (Get-PSDrive -Name $lettre -PSProvider FileSystem -ErrorAction SilentlyContinue) {
        try {
            Remove-PSDrive -Name $lettre -Force -ErrorAction SilentlyContinue
            net use "$drive" /delete /y 2>$null | Out-Null
            Log "  [OK] $drive supprime"
        } catch {
            net use "$drive" /delete /y 2>$null | Out-Null
        }
    }
}

# -- Charger le module AD (avec retry) ------------------------
$adOk = $false
for ($i = 1; $i -le 3; $i++) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adOk = $true
        break
    } catch {
        Log "  [WAIT] Module AD non disponible, tentative $i/3 -- attente 5s"
        Start-Sleep -Seconds 5
    }
}

if (-not $adOk) {
    Log "  [WARN] Module AD introuvable -- mappages J: et K: impossibles"
    Log "         Installer RSAT : Add-WindowsCapability -Online -Name Rsat.ActiveDirectory*"
}

# -- I: -- Dossier individuel ----------------------------------
$iPath = "$dc1\Homes\$user"
$mapped = $false
try {
    $result = net use I: "$iPath" /persistent:yes 2>&1
    if (Test-Path "I:\") {
        Log "  [OK] I: --> $iPath"
        $mapped = $true
    }
} catch {}

if (-not $mapped) {
    # Fallback : racine du partage Homes
    net use I: "$dc1\Homes" /persistent:yes 2>$null | Out-Null
    if (Test-Path "I:\") {
        Log "  [FALLBACK] I: --> $dc1\Homes (dossier personnel absent, utilise la racine)"
    } else {
        Log "  [ERR] I: echec total -- verifier que $dc1\Homes est accessible"
    }
}

# -- Recuperer les groupes AD ----------------------------------
$grps = @()
if ($adOk) {
    try {
        $memberOf = (Get-ADUser $user -Properties MemberOf -ErrorAction Stop).MemberOf
        $grps = $memberOf | ForEach-Object {
            (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name
        } | Where-Object { $_ -ne $null -and $_ -ne "" }
        Log "  [AD] $($grps.Count) groupes recuperes pour $user"
    } catch {
        Log "  [ERR] Impossible de recuperer les groupes AD : $_"
    }
}

# -- J: -- Dossier de service ----------------------------------
$jMapped = $false

if ($grps.Count -gt 0) {
    $svcGrps = $grps | Where-Object { $_ -like "GG_SVC_*" }

    if ($svcGrps) {
        foreach ($svcGrp in $svcGrps) {
            $svc   = $svcGrp -replace "^GG_SVC_", ""
            $jPath = "$dc1\Services\$svc"

            if (Test-Path $jPath) {
                net use J: "$jPath" /persistent:yes 2>$null | Out-Null
                if (Test-Path "J:\") {
                    Log "  [OK] J: --> $jPath  (groupe : $svcGrp)"
                    $jMapped = $true
                    break
                } else {
                    Log "  [WARN] J: net use echoue sur $jPath -- chemin pourtant accessible"
                }
            } else {
                Log "  [WARN] J: dossier absent : $jPath -- verifier script 02"
            }
        }
    } else {
        Log "  [WARN] J: aucun groupe GG_SVC_* trouve pour $user"
    }
} else {
    Log "  [SKIP] J: pas de groupes AD disponibles"
}

if (-not $jMapped) {
    Log "  [ERR] J: non mappe"
}

# -- K: -- Dossier de departement -----------------------------
$kMapped = $false

$deptMap = @{
    "GG_DIRECTION_Users"   = "Direction"
    "GG_DEV_Users"         = "Dev-Logiciel"
    "GG_DSI_Users"         = "DSI"
    "GG_COMMERCIAL_Users"  = "Commercial"
    "GG_COMM_Users"        = "Communication"
    "GG_JURIDIQUE_Users"   = "Juridique"
    "GG_FINANCE_Users"     = "Finance"
    "GG_QHSE_Users"        = "QHSE"
    "GG_RH_Users"          = "Recrutement"
}

if ($grps.Count -gt 0) {
    foreach ($grp in $deptMap.Keys) {
        if ($grps -contains $grp) {
            $dept  = $deptMap[$grp]
            $kPath = "$dc1\Departements\$dept"

            if (Test-Path $kPath) {
                net use K: "$kPath" /persistent:yes 2>$null | Out-Null
                if (Test-Path "K:\") {
                    Log "  [OK] K: --> $kPath  (groupe : $grp)"
                    $kMapped = $true
                    break
                } else {
                    Log "  [WARN] K: net use echoue sur $kPath"
                }
            } else {
                Log "  [WARN] K: dossier absent : $kPath -- verifier script 02"
            }
        }
    }

    if (-not $kMapped) {
        Log "  [WARN] K: aucun groupe GG_*_Users reconnu parmi les groupes de $user"
        Log "         Groupes de l utilisateur : $($grps -join ', ')"
    }
} else {
    Log "  [SKIP] K: pas de groupes AD disponibles"
}

if (-not $kMapped) {
    Log "  [ERR] K: non mappe"
}

# -- Bilan -----------------------------------------------------
Log ""
Log "=== Bilan ==="
foreach ($lettre in @("I","J","K")) {
    $drive = "${lettre}:"
    if (Test-Path "$drive\") {
        $target = (net use $drive 2>$null) | Select-String "Remote" |
                  ForEach-Object { ($_ -split "\s{2,}")[1] }
        Log "  $drive  MAPPE  --> $target"
    } else {
        Log "  $drive  NON MAPPE"
    }
}
Log "  Log complet : $log"
