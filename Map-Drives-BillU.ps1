#Requires -Version 3
# Map-Drives-BillU.ps1 -- BillU Sprint 5
# Mappe I: J: K: et force le rafraichissement de l Explorateur Windows
# Deposer dans : \\DC1\NETLOGON\scripts\Map-Drives-BillU.ps1

$dc1  = "\\DC1"
$user = $env:USERNAME
$log  = "$env:TEMP\BillU-MapDrives.log"

function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    try { Add-Content $log $line -Encoding UTF8 -EA SilentlyContinue } catch {}
    Write-Host $line
}

Log "=== BillU MapDrives -- $user ==="

# -- Supprimer les anciens mappages ----------------------------
foreach ($l in @("I","J","K")) {
    net use "${l}:" /delete /y 2>$null | Out-Null
}
Log "  Anciens mappages supprimes"

# -- Recuperer les groupes via whoami (natif, sans RSAT) -------
$grps = @()
try {
    $raw  = whoami /groups /fo csv 2>$null | ConvertFrom-Csv
    $grps = $raw |
        Where-Object { $_.'Group Name' -match '\\GG_' } |
        ForEach-Object { ($_.'Group Name' -split '\\')[-1] }
    Log "  [OK] $($grps.Count) groupes GG_* : $($grps -join ', ')"
} catch {
    Log "  [ERR] whoami : $_"
}

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

# -- Fonction de mappage avec refresh shell --------------------
function Map-Drive {
    param([string]$Letter, [string]$Path, [string]$Label)

    net use "${Letter}:" "$Path" /persistent:yes 2>$null | Out-Null

    if (Test-Path "${Letter}:\") {
        # Forcer Windows a voir le lecteur dans l Explorateur
        # via la cle de registre UserShellFolders si besoin
        $wsh = New-Object -ComObject WScript.Shell -EA SilentlyContinue
        if ($wsh) {
            try { $wsh.AppActivate("explorer") | Out-Null } catch {}
        }

        # Nommer le lecteur (etiquette visible dans l Explorateur)
        try {
            $shell = New-Object -ComObject Shell.Application
            $shell.NameSpace("${Letter}:\").Self.Name = $Label
        } catch {}

        Log "  [OK] ${Letter}: --> $Path"
        return $true
    }
    Log "  [ERR] ${Letter}: echec sur $Path"
    return $false
}

# -- I: -- Dossier individuel ----------------------------------
Map-Drive -Letter "I" -Path "$dc1\Homes\$user" -Label "Mon dossier ($user)" | Out-Null
if (-not (Test-Path "I:\")) {
    Map-Drive -Letter "I" -Path "$dc1\Homes" -Label "Homes" | Out-Null
}

# -- J: -- Dossier de service ----------------------------------
$jMapped = $false
$svcGrps = @($grps | Where-Object { $_ -like "GG_SVC_*" })
foreach ($sg in $svcGrps) {
    $svc = $sg -replace "^GG_SVC_",""
    $ok  = Map-Drive -Letter "J" -Path "$dc1\Services\$svc" -Label "Service - $svc"
    if ($ok) { $jMapped = $true; break }
}
if (-not $jMapped) { Log "  [ERR] J: non mappe -- groupes : $($grps -join ', ')" }

# -- K: -- Dossier de departement ------------------------------
$kMapped = $false
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
        $ok   = Map-Drive -Letter "K" -Path "$dc1\Departements\$dept" -Label "Departement - $dept"
        if ($ok) { $kMapped = $true; break }
    }
}
if (-not $kMapped) { Log "  [ERR] K: non mappe -- groupes : $($grps -join ', ')" }

# -- Forcer le rafraichissement de l Explorateur Windows -------
# Sans ca les lecteurs apparaissent dans "Ce PC" mais pas toujours
# dans le panneau gauche de l Explorateur immediatement
try {
    # Methode 1 : notifier le shell d un changement de lecteurs
    $code = @'
using System;
using System.Runtime.InteropServices;
public class ShellRefresh {
    [DllImport("shell32.dll")]
    public static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
    }
}
'@
    Add-Type -TypeDefinition $code -EA SilentlyContinue
    [ShellRefresh]::Refresh()
    Log "  [OK] Shell notifie (SHChangeNotify)"
} catch {
    # Methode 2 : relancer l Explorateur si methode 1 echoue
    try {
        Stop-Process -Name explorer -Force -EA SilentlyContinue
        Start-Sleep -Seconds 1
        Start-Process explorer
        Log "  [OK] Explorateur redemarre pour rafraichissement"
    } catch {
        Log "  [WARN] Refresh shell impossible : $_"
    }
}

# -- Bilan -----------------------------------------------------
Log ""
Log "=== Bilan : I=$(Test-Path 'I:\') J=$(Test-Path 'J:\') K=$(Test-Path 'K:\') ==="
Log "  Log : $log"
