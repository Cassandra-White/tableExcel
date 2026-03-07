#Requires -RunAsAdministrator
###########################################################################
#  Disable-Telemetry.ps1
#  BillU — Groupe 1 — Sprint 3 · Sécurité
#  Objectif : Désactiver la collecte de données Windows 10/11
#  Exécution : local (admin) ou via tâche planifiée
###########################################################################

$ErrorActionPreference = 'SilentlyContinue'
$logFile = "C:\Windows\Logs\BillU-Telemetry-$(Get-Date -f 'yyyy-MM-dd').log"

function Write-Log($msg) {
    $line = "[$(Get-Date -f 'HH:mm:ss')] $msg"
    Add-Content -Path $logFile -Value $line
    Write-Host  $line
}

Write-Log "=== DÉBUT désactivation télémétrie sur $env:COMPUTERNAME ==="

# ────────────────────────────────────────────────────────────────────────
# 1. NIVEAU DE TÉLÉMÉTRIE → Basique (1)
#    Clé : HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection
# ────────────────────────────────────────────────────────────────────────
$dc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
if (-not (Test-Path $dc)) { New-Item -Path $dc -Force | Out-Null }

Set-ItemProperty -Path $dc -Name 'AllowTelemetry'                -Value 1   -Type DWord
Set-ItemProperty -Path $dc -Name 'DoNotShowFeedbackNotifications' -Value 1   -Type DWord
Set-ItemProperty -Path $dc -Name 'DisableOneSettingsDownloads'    -Value 1   -Type DWord
Write-Log '[OK] Télémétrie réglée sur niveau 1 (Basique)'

# ────────────────────────────────────────────────────────────────────────
# 2. SERVICES DE COLLECTE → Désactivés
# ────────────────────────────────────────────────────────────────────────
$services = @(
    'DiagTrack',          # Connected User Experiences and Telemetry
    'dmwappushservice',   # WAP Push Message Routing Service
    'WerSvc'              # Windows Error Reporting Service
)
foreach ($svc in $services) {
    Stop-Service  -Name $svc -Force
    Set-Service   -Name $svc -StartupType Disabled
    Write-Log "[OK] Service $svc arrêté et désactivé"
}

# ────────────────────────────────────────────────────────────────────────
# 3. CORTANA → Désactivée
# ────────────────────────────────────────────────────────────────────────
$wsh = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
if (-not (Test-Path $wsh)) { New-Item -Path $wsh -Force | Out-Null }
Set-ItemProperty -Path $wsh -Name 'AllowCortana'                            -Value 0 -Type DWord
Set-ItemProperty -Path $wsh -Name 'AllowCortanaAboveLock'                   -Value 0 -Type DWord
Set-ItemProperty -Path $wsh -Name 'AllowSearchToUseLocation'               -Value 0 -Type DWord
Set-ItemProperty -Path $wsh -Name 'DisableWebSearch'                        -Value 1 -Type DWord
Write-Log '[OK] Cortana et recherche web désactivées'

# ────────────────────────────────────────────────────────────────────────
# 4. PUBLICITÉ PERSONNALISÉE → Désactivée
#    (clé HKCU : s'applique à l'utilisateur courant)
# ────────────────────────────────────────────────────────────────────────
$adv = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
if (-not (Test-Path $adv)) { New-Item -Path $adv -Force | Out-Null }
Set-ItemProperty -Path $adv -Name 'Enabled' -Value 0 -Type DWord
Write-Log '[OK] Publicité personnalisée désactivée'

# ────────────────────────────────────────────────────────────────────────
# 5. RAPPORT D'ERREURS WINDOWS → Désactivé
# ────────────────────────────────────────────────────────────────────────
$wer = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
if (-not (Test-Path $wer)) { New-Item -Path $wer -Force | Out-Null }
Set-ItemProperty -Path $wer -Name 'Disabled'         -Value 1 -Type DWord
Set-ItemProperty -Path $wer -Name 'DontSendAdditionalData' -Value 1 -Type DWord
Write-Log '[OK] Rapport d erreurs Windows désactivé'

# ────────────────────────────────────────────────────────────────────────
# 6. EXPÉRIENCES PERSONNALISÉES → Désactivées
# ────────────────────────────────────────────────────────────────────────
$cp = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
if (-not (Test-Path $cp)) { New-Item -Path $cp -Force | Out-Null }
Set-ItemProperty -Path $cp -Name 'DisableWindowsConsumerFeatures'  -Value 1 -Type DWord
Set-ItemProperty -Path $cp -Name 'DisableTailoredExperiencesWithDiagnosticData' -Value 1 -Type DWord
Write-Log '[OK] Expériences personnalisées désactivées'

Write-Log "=== FIN — Télémétrie désactivée sur $env:COMPUTERNAME === "
Write-Host "`n  Log enregistré dans : $logFile" -ForegroundColor Cyan
