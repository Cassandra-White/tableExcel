#Requires -Version 3
# Map-Drives-BillU.ps1 -- BillU Sprint 5
# Mappe I: J: K: + cree le raccourci bureau "Reconnecter les lecteurs"
# Deposer dans : \\DC1\NETLOGON\scripts\Map-Drives-BillU.ps1

$dc1  = "\\DC1"
$user = $env:USERNAME
$log  = "$env:TEMP\BillU-MapDrives.log"

function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    try { Add-Content $log $line -Encoding UTF8 -EA SilentlyContinue } catch {}
    Write-Host $line
}

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

# -- I: --------------------------------------------------------
net use I: "$dc1\Homes\$user" /persistent:yes 2>$null | Out-Null
if (Test-Path "I:\") {
    Log "  [OK] I: --> $dc1\Homes\$user"
} else {
    net use I: "$dc1\Homes" /persistent:yes 2>$null | Out-Null
    if (Test-Path "I:\") { Log "  [OK] I: --> $dc1\Homes (racine)" }
    else                  { Log "  [ERR] I: echec sur $dc1\Homes" }
}

# -- J: --------------------------------------------------------
$jMapped = $false
foreach ($sg in @($grps | Where-Object { $_ -like "GG_SVC_*" })) {
    $svc = $sg -replace "^GG_SVC_",""
    net use J: "$dc1\Services\$svc" /persistent:yes 2>$null | Out-Null
    if (Test-Path "J:\") { Log "  [OK] J: --> $dc1\Services\$svc"; $jMapped = $true; break }
}
if (-not $jMapped) {
    net use J: "$dc1\Services" /persistent:yes 2>$null | Out-Null
    if (Test-Path "J:\") { Log "  [OK] J: --> $dc1\Services (racine)"; $jMapped = $true }
    else                  { Log "  [ERR] J: echec -- verifier partage SMB Services sur DC1" }
}

# -- K: --------------------------------------------------------
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
        net use K: "$dc1\Departements\$dept" /persistent:yes 2>$null | Out-Null
        if (Test-Path "K:\") { Log "  [OK] K: --> $dc1\Departements\$dept"; $kMapped = $true; break }
    }
}
if (-not $kMapped) {
    net use K: "$dc1\Departements" /persistent:yes 2>$null | Out-Null
    if (Test-Path "K:\") { Log "  [OK] K: --> $dc1\Departements (racine)"; $kMapped = $true }
    else                  { Log "  [ERR] K: echec -- verifier partage SMB Departements sur DC1" }
}

# -- Raccourci bureau ------------------------------------------
# Cree directement ici sans VBS ni GPO supplementaire
try {
    $desktop  = [Environment]::GetFolderPath("Desktop")
    $lnkPath  = "$desktop\Reconnecter les lecteurs.lnk"
    $batPath  = "\\$env:USERDNSDOMAIN\NETLOGON\scripts\Reconnecter-Lecteurs.bat"

    $wsh  = New-Object -ComObject WScript.Shell
    $link = $wsh.CreateShortcut($lnkPath)
    $link.TargetPath       = $batPath
    $link.Description      = "Reconnecter les lecteurs reseau I J K"
    $link.IconLocation     = "imageres.dll,17"
    $link.WorkingDirectory = $desktop
    $link.Save()

    Log "  [OK] Raccourci cree : $lnkPath"
} catch {
    Log "  [WARN] Raccourci non cree : $_"
}

# -- Refresh + bilan -------------------------------------------
Refresh-Shell
Log ""
Log "=== Bilan : I=$(Test-Path 'I:\') J=$(Test-Path 'J:\') K=$(Test-Path 'K:\') ==="
Log "  Log : $log"
