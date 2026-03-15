#Requires -RunAsAdministrator
# Install-RSAT.ps1 -- BillU Sprint 5
# Installe toutes les fonctionnalites RSAT utiles pour administrer billu.local
# A executer sur les postes d administration (pas sur les clients standard)

$log = "C:\Windows\Logs\BillU\Install-RSAT-$(Get-Date -f yyyyMMdd-HHmm).log"
New-Item (Split-Path $log) -ItemType Directory -Force | Out-Null

function Log($msg) {
    $line = "[$(Get-Date -f HH:mm:ss)] $msg"
    Add-Content $log $line -Encoding UTF8 -EA SilentlyContinue
    Write-Host $line
}

# -- Detection de l OS ----------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
Log "=== Installation RSAT -- $($os.Caption) ==="
Log "  $env:COMPUTERNAME -- $env:USERNAME"
Log ""

$isServer  = $os.Caption -match "Server"
$isCoreOS  = $os.Caption -match "Core"

Log "  Type : $(if ($isServer) { 'Windows Server' } else { 'Windows Client' })"
Log ""

# ============================================================
# WINDOWS SERVER
# Sur WS2019/2022 les outils AD sont des Features (Add-WindowsFeature)
# ============================================================
if ($isServer) {
    Log "=== Mode Windows Server -- Add-WindowsFeature ==="

    $features = @(
        @{ Name="RSAT-AD-Tools"; Desc="Outils AD DS et AD LDS (ensemble complet)" },
        @{ Name="RSAT-AD-AdminCenter"; Desc="Centre d admin Active Directory" },
        @{ Name="RSAT-ADDS-Tools"; Desc="Outils AD DS (Users & Computers, Sites...)" },
        @{ Name="RSAT-AD-PowerShell"; Desc="Module PowerShell ActiveDirectory" },
        @{ Name="RSAT-DNS-Server"; Desc="Outils DNS" },
        @{ Name="RSAT-DHCP"; Desc="Outils DHCP" },
        @{ Name="RSAT-GP-Tools"; Desc="Gestion des strategies de groupe (GPMC)" },
        @{ Name="RSAT-File-Services"; Desc="Outils services de fichiers" }
    )

    $ok = 0; $err = 0; $deja = 0

    foreach ($f in $features) {
        $state = Get-WindowsFeature -Name $f.Name -EA SilentlyContinue
        if (-not $state) {
            Log "  [SKIP] $($f.Name) -- introuvable sur cet OS"
            continue
        }
        if ($state.Installed) {
            Log "  [DEJA] $($f.Name) -- $($f.Desc)"
            $deja++
            continue
        }
        try {
            $r = Add-WindowsFeature -Name $f.Name -IncludeManagementTools -EA Stop
            if ($r.Success) {
                Log "  [OK] $($f.Name) -- $($f.Desc)"
                $ok++
            } else {
                Log "  [ERR]  $($f.Name) -- echec sans exception"
                $err++
            }
        } catch {
            Log "  [ERR]  $($f.Name) -- $_"
            $err++
        }
    }

    Log ""
    Log "=== Bilan Server : $ok installes | $deja deja presents | $err erreurs ==="
    if ($ok -gt 0) {
        Log "  Redemarrage recommande si les outils ne s affichent pas"
    }
}

# ============================================================
# WINDOWS CLIENT (10/11)
# Sur les clients les RSAT sont des Capabilities (Add-WindowsCapability)
# Necessite une connexion Internet ou un serveur WSUS configure
# ============================================================
else {
    Log "=== Mode Windows Client -- Add-WindowsCapability ==="

    # Verifier si Windows Update est accessible (pour telecharger les caps)
    $wuOk = $false
    try {
        $null = Invoke-WebRequest "https://www.microsoft.com" -UseBasicParsing -TimeoutSec 5 -EA Stop
        $wuOk = $true
        Log "  [OK] Acces Internet disponible -- telechargement depuis Windows Update"
    } catch {
        Log "  [WARN] Pas d acces Internet -- si echec, configurer WSUS ou monter l ISO Windows"
    }
    Log ""

    $caps = @(
        @{ Name="Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"; Desc="AD DS / LDS Tools + module PS" },
        @{ Name="Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"; Desc="Gestion des GPO (GPMC)" },
        @{ Name="Rsat.Dns.Tools~~~~0.0.1.0"; Desc="Outils DNS" },
        @{ Name="Rsat.DHCP.Tools~~~~0.0.1.0"; Desc="Outils DHCP" },
        @{ Name="Rsat.FileServices.Tools~~~~0.0.1.0"; Desc="Outils services de fichiers" },
        @{ Name="Rsat.RemoteDesktop.Services.Tools~~~~0.0.1.0"; Desc="Outils Bureau a distance" }
    )

    $ok = 0; $err = 0; $deja = 0

    foreach ($c in $caps) {
        $state = Get-WindowsCapability -Online -Name $c.Name -EA SilentlyContinue
        if (-not $state) {
            Log "  [SKIP] $($c.Name) -- introuvable"
            continue
        }
        if ($state.State -eq "Installed") {
            Log "  [DEJA] $($c.Desc)"
            $deja++
            continue
        }
        Log "  [...]  Installation : $($c.Desc)"
        try {
            Add-WindowsCapability -Online -Name $c.Name -EA Stop | Out-Null
            Log "  [OK] $($c.Desc)"
            $ok++
        } catch {
            Log "  [ERR]  $($c.Desc) -- $_"
            $err++
        }
    }

    Log ""
    Log "=== Bilan Client : $ok installes | $deja deja presents | $err erreurs ==="
}

# -- Verification finale : tester le module PS ----------------
Log ""
Log "=== Test du module ActiveDirectory ==="
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $dom = (Get-ADDomain -EA Stop).DNSRoot
    Log "  [OK] Module charge -- domaine detecte : $dom"
} catch {
    Log "  [ERR] Module AD non fonctionnel apres installation : $_"
    Log "  Solutions possibles :"
    Log "  1. Redemarrer le poste et relancer le test"
    Log "  2. Verifier que le PC est joint au domaine billu.local"
    Log "  3. Sans Internet : monter l ISO Windows et pointer DISM"
}

Log ""
Log "=== Fin -- Log : $log ==="
