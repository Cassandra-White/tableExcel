#Requires -RunAsAdministrator
###########################################################################
#  Disable-Telemetry.ps1
#  BillU - Groupe 1 - Sprint 3 - Securite
#  Objectif : Desactiver la collecte de donnees Windows 10/11
#  Execution : local (admin) ou via tache planifiee SYSTEM
#  Version   : 2.0 - corrigee
###########################################################################

# CORRECTION 1 : ErrorActionPreference sur 'Continue' et non 'SilentlyContinue'
# SilentlyContinue masque toutes les erreurs, meme les critiques
# Continue : le script continue en cas d'erreur non bloquante mais les affiche
$ErrorActionPreference = 'Continue'

# CORRECTION 2 : on cree le dossier de log s'il n'existe pas
$logDir  = 'C:\Windows\Logs\BillU'
$logFile = "$logDir\Telemetry-$(Get-Date -f 'yyyy-MM-dd').log"

if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Fonction de log avec niveau (INFO / OK / WARN / ERROR)
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $line = "[$(Get-Date -f 'HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    switch ($Level) {
        'OK'    { Write-Host $line -ForegroundColor Green  }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red    }
        default { Write-Host $line }
    }
}

# CORRECTION 3 : fonction centralisee pour ecrire dans le registre
# Gere la creation de la cle si absente + capture les erreurs
function Set-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        [int]   $Value
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -ErrorAction Stop
        Write-Log "Registre OK : $Name = $Value dans $Path" 'OK'
    }
    catch {
        Write-Log "Registre ECHEC : $Name dans $Path - Erreur : $_" 'ERROR'
    }
}

# CORRECTION 4 : fonction centralisee pour arreter un service
# Verifie que le service existe avant d'agir (evite les erreurs silencieuses)
function Disable-Svc {
    param([string]$Name)

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue

    if ($null -eq $svc) {
        Write-Log "Service $Name : non trouve sur ce systeme" 'WARN'
        return
    }

    try {
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $Name -Force -ErrorAction Stop
        }
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
        Write-Log "Service $Name : arrete et desactive" 'OK'
    }
    catch {
        Write-Log "Service $Name : erreur - $_" 'ERROR'
    }
}

# ==========================================================================

Write-Log "=== DEBUT desactivation telemetrie sur $env:COMPUTERNAME ==="
Write-Log "Compte d'execution : $env:USERNAME"

# --------------------------------------------------------------------------
# 1. NIVEAU DE TELEMETRIE -> Basique (valeur 1)
#    Cle : HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection
# --------------------------------------------------------------------------
Write-Log '--- Section 1 : Niveau de telemetrie'

$dc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
Set-RegValue -Path $dc -Name 'AllowTelemetry'                 -Value 1
Set-RegValue -Path $dc -Name 'DoNotShowFeedbackNotifications' -Value 1
Set-RegValue -Path $dc -Name 'DisableOneSettingsDownloads'    -Value 1

# --------------------------------------------------------------------------
# 2. SERVICES DE COLLECTE -> Desactives
# --------------------------------------------------------------------------
Write-Log '--- Section 2 : Services de collecte'

Disable-Svc -Name 'DiagTrack'        # Connected User Experiences and Telemetry
Disable-Svc -Name 'dmwappushservice' # WAP Push Message Routing Service
Disable-Svc -Name 'WerSvc'           # Windows Error Reporting Service

# --------------------------------------------------------------------------
# 3. CORTANA -> Desactivee
# --------------------------------------------------------------------------
Write-Log '--- Section 3 : Cortana et recherche web'

$wsh = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
Set-RegValue -Path $wsh -Name 'AllowCortana'             -Value 0
Set-RegValue -Path $wsh -Name 'AllowCortanaAboveLock'    -Value 0
Set-RegValue -Path $wsh -Name 'AllowSearchToUseLocation' -Value 0
Set-RegValue -Path $wsh -Name 'DisableWebSearch'         -Value 1

# --------------------------------------------------------------------------
# 4. PUBLICITE PERSONNALISEE -> Desactivee
#
#    IMPORTANT : cette cle est HKCU (HKEY_CURRENT_USER).
#    Quand le script tourne en SYSTEM via tache planifiee, HKCU pointe
#    vers le profil SYSTEM, pas vers les profils des utilisateurs.
#    Ce parametre doit donc AUSSI etre gere via GPO (Configuration
#    utilisateur) pour s'appliquer a tous les comptes du domaine.
# --------------------------------------------------------------------------
Write-Log '--- Section 4 : Publicite personnalisee (utilisateur courant)'

$adv = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
Set-RegValue -Path $adv -Name 'Enabled' -Value 0

# --------------------------------------------------------------------------
# 5. RAPPORT D'ERREURS WINDOWS -> Desactive
# --------------------------------------------------------------------------
Write-Log "--- Section 5 : Rapport d'erreurs Windows"

$wer = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
Set-RegValue -Path $wer -Name 'Disabled'               -Value 1
Set-RegValue -Path $wer -Name 'DontSendAdditionalData' -Value 1

# --------------------------------------------------------------------------
# 6. EXPERIENCES PERSONNALISEES -> Desactivees
# --------------------------------------------------------------------------
Write-Log '--- Section 6 : Experiences personnalisees (utilisateur courant)'

$cp = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
Set-RegValue -Path $cp -Name 'DisableWindowsConsumerFeatures'               -Value 1
Set-RegValue -Path $cp -Name 'DisableTailoredExperiencesWithDiagnosticData' -Value 1

# --------------------------------------------------------------------------
Write-Log "=== FIN - Telemetrie desactivee sur $env:COMPUTERNAME ==="
Write-Host ""
Write-Host "  Log disponible dans : $logFile" -ForegroundColor Cyan

# CORRECTION 5 : code de sortie explicite pour le planificateur de taches
# Le planificateur lit le code de retour pour determiner succes/echec
# 0 = succes, autre valeur = echec
exit 0
