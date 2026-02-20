# ============================================================================
# Script      : 04-Cleanup-AD.ps1
# Description : Suppression de TOUS les objets crees par les scripts BillU
#               Utilisateurs, Ordinateurs, Groupes, OUs (en cascade)
# Prerequis   : 00-Config.ps1 dans le meme dossier
# ============================================================================

<#
.SYNOPSIS
    Supprime toute la structure AD BillU (OUs, groupes, utilisateurs, PCs).

.DESCRIPTION
    ATTENTION : operation IRREVERSIBLE.
    Supprime dans l'ordre :
      1. Tous les utilisateurs sous OU=Utilisateurs,OU=Paris,...
      2. Tous les ordinateurs sous OU=Ordinateurs,OU=Paris,...
      3. Tous les groupes sous OU=Groupes,OU=Paris,...
      4. Toute l arborescence des OUs a partir de OU=BillU (recursivement)

    Une confirmation double est demandee avant execution (sauf -Force).
    Toutes les operations utilisent $ADCredential (BILLU\Administrateur).

.PARAMETER LogFile
    Chemin du fichier de log (defaut : $LogBaseDir\Cleanup.log)

.PARAMETER Force
    Supprime sans demander de confirmation (DANGEREUX - a utiliser avec prudence)

.PARAMETER WhatIf
    Mode simulation - liste ce qui serait supprime sans rien supprimer

.EXAMPLE
    .\04-Cleanup-AD.ps1
    Demande deux confirmations avant de supprimer

    .\04-Cleanup-AD.ps1 -WhatIf
    Liste tous les objets qui seraient supprimes

    .\04-Cleanup-AD.ps1 -Force
    Supprime sans confirmation (scripts automatises uniquement)
#>

[CmdletBinding()]
param(
    [string]$LogFile = "",
    [switch]$Force,
    [switch]$WhatIf
)

# ============================================================================
# CHARGEMENT CONFIG
# ============================================================================

$ConfigFile = Join-Path $PSScriptRoot "00-Config.ps1"
if (-not (Test-Path $ConfigFile)) { Write-Error "00-Config.ps1 introuvable : $ConfigFile"; exit 1 }
. $ConfigFile

if (-not $LogFile) { $LogFile = Join-Path $LogBaseDir "Cleanup.log" }

# ============================================================================
# INITIALISATION
# ============================================================================

$LogDir = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }

try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Write-Error "Module ActiveDirectory non disponible. Installez RSAT."; exit 1 }

try {
    $DomainInfo = Get-ADDomain -Credential $ADCredential -ErrorAction Stop
}
catch {
    Write-Error "Echec d'authentification avec $ADAdminUser : $($_.Exception.Message)"
    exit 1
}

$DomainDN = $DomainInfo.DistinguishedName
$RootDN   = "OU=$RootOU,$DomainDN"

$Script:DeletedUsers     = 0
$Script:DeletedComputers = 0
$Script:DeletedGroups    = 0
$Script:DeletedOUs       = 0
$Script:Errors           = 0

# ============================================================================
# FONCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR')]
        [string]$Level = 'INFO'
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$ts] [$Level] $Message"
    switch ($Level) {
        'SUCCESS' { Write-Host $Message -ForegroundColor Green  }
        'WARNING' { Write-Host $Message -ForegroundColor Yellow }
        'ERROR'   { Write-Host $Message -ForegroundColor Red    }
        default   { Write-Host $Message -ForegroundColor White  }
    }
}

function Remove-OURecursive {
    # Supprime une OU et tout son contenu recursivement
    # Desactive d'abord la protection contre la suppression accidentelle
    param([string]$OUDN)

    # Recuperer tous les enfants (OUs imbriquees en premier, profondeur d'abord)
    $Children = Get-ADOrganizationalUnit -Filter * -SearchBase $OUDN `
        -SearchScope OneLevel -Credential $ADCredential -EA SilentlyContinue

    foreach ($Child in $Children) {
        Remove-OURecursive -OUDN $Child.DistinguishedName
    }

    # Supprimer l'OU elle-meme
    try {
        if ($WhatIf) {
            Write-Log "  [SIM] Suppression OU : $OUDN" -Level INFO
            $Script:DeletedOUs++; return
        }
        # Desactiver la protection
        Set-ADOrganizationalUnit -Identity $OUDN `
            -ProtectedFromAccidentalDeletion $false `
            -Credential $ADCredential -ErrorAction Stop

        Remove-ADOrganizationalUnit -Identity $OUDN `
            -Credential $ADCredential -Confirm:$false -Recursive -ErrorAction Stop

        Write-Log "  - OU supprimee : $OUDN" -Level SUCCESS
        $Script:DeletedOUs++
    }
    catch {
        Write-Log "  ERREUR suppression OU $OUDN : $($_.Exception.Message)" -Level ERROR
        $Script:Errors++
    }
}

# ============================================================================
# VERIFICATION D'EXISTENCE
# ============================================================================

$RootExists = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$RootDN'" `
    -Credential $ADCredential -EA SilentlyContinue

if (-not $RootExists) {
    Write-Host ""
    Write-Host "L'OU racine OU=$RootOU n'existe pas dans AD." -ForegroundColor Yellow
    Write-Host "Rien a supprimer." -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

# ============================================================================
# CONFIRMATION (sauf -Force ou -WhatIf)
# ============================================================================

if (-not $Force -and -not $WhatIf) {
    Write-Host ""
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host "!!         ATTENTION - OPERATION IRREVERSIBLE            !!" -ForegroundColor Red
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host "!!  Ce script va supprimer DEFINITIVEMENT :              !!" -ForegroundColor Red
    Write-Host "!!    - Tous les utilisateurs BillU                      !!" -ForegroundColor Red
    Write-Host "!!    - Tous les ordinateurs BillU                       !!" -ForegroundColor Red
    Write-Host "!!    - Tous les groupes BillU                           !!" -ForegroundColor Red
    Write-Host "!!    - Toute l arborescence OU=$RootOU et son contenu   !!" -ForegroundColor Red
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Domaine cible : $($DomainInfo.DNSRoot)" -ForegroundColor Yellow
    Write-Host "Compte utilise : $ADAdminUser"          -ForegroundColor Yellow
    Write-Host "OU racine ciblee : $RootDN"             -ForegroundColor Yellow
    Write-Host ""

    $Confirm1 = Read-Host "Premiere confirmation - Tapez exactement OUI pour continuer"
    if ($Confirm1 -ne "OUI") {
        Write-Host "Annule." -ForegroundColor Green
        exit 0
    }

    $Confirm2 = Read-Host "Deuxieme confirmation - Tapez le nom de l organisation ($OrgName) pour confirmer"
    if ($Confirm2 -ne $OrgName) {
        Write-Host "Annule." -ForegroundColor Green
        exit 0
    }

    Write-Host ""
}

# ============================================================================
# SCRIPT PRINCIPAL
# ============================================================================

Write-Log "========================================" -Level INFO
Write-Log "DEBUT - Nettoyage AD [$OrgName]"         -Level INFO
Write-Log "Compte  : $ADAdminUser"                  -Level INFO
Write-Log "Cible   : $RootDN"                       -Level INFO
if ($WhatIf) { Write-Log "!!! MODE SIMULATION - aucune suppression !!!" -Level WARNING }
Write-Log "========================================" -Level INFO
Write-Host ""

$CountryDN = "OU=$CountryOU,$RootDN"
$SiteDN    = "OU=$SiteOU,$CountryDN"

# -----------------------------------------------------------------------
# ETAPE 1 : SUPPRESSION DES UTILISATEURS
# -----------------------------------------------------------------------

Write-Log "--- ETAPE 1 : Suppression des utilisateurs ---" -Level INFO
Write-Host ""

$UtilBase = "OU=Utilisateurs,$SiteDN"
$UtilExists = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$UtilBase'" `
    -Credential $ADCredential -EA SilentlyContinue

if ($UtilExists) {
    $Users = Get-ADUser -Filter * -SearchBase $UtilBase `
        -Credential $ADCredential -EA SilentlyContinue

    Write-Log "  Utilisateurs trouves : $($Users.Count)" -Level INFO

    foreach ($User in $Users) {
        try {
            if ($WhatIf) {
                Write-Log "  [SIM] Suppression user : $($User.SamAccountName)" -Level INFO
                $Script:DeletedUsers++; continue
            }
            Remove-ADUser -Identity $User.DistinguishedName `
                -Credential $ADCredential -Confirm:$false -ErrorAction Stop
            Write-Log "  - $($User.SamAccountName) ($($User.Name))" -Level SUCCESS
            $Script:DeletedUsers++
        }
        catch {
            Write-Log "  ERREUR $($User.SamAccountName) : $($_.Exception.Message)" -Level ERROR
            $Script:Errors++
        }
    }
}
else {
    Write-Log "  OU=Utilisateurs introuvable - etape ignoree" -Level WARNING
}

Write-Host ""
Write-Log "Etape 1 terminee - Utilisateurs supprimes : $Script:DeletedUsers" -Level SUCCESS
Write-Host ""

# -----------------------------------------------------------------------
# ETAPE 2 : SUPPRESSION DES ORDINATEURS
# -----------------------------------------------------------------------

Write-Log "--- ETAPE 2 : Suppression des ordinateurs ---" -Level INFO
Write-Host ""

$PCBase = "OU=$OuPCs,$SiteDN"
$PCExists = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$PCBase'" `
    -Credential $ADCredential -EA SilentlyContinue

if ($PCExists) {
    $Computers = Get-ADComputer -Filter * -SearchBase $PCBase `
        -Credential $ADCredential -EA SilentlyContinue

    Write-Log "  Ordinateurs trouves : $($Computers.Count)" -Level INFO

    foreach ($PC in $Computers) {
        try {
            if ($WhatIf) {
                Write-Log "  [SIM] Suppression PC : $($PC.Name)" -Level INFO
                $Script:DeletedComputers++; continue
            }
            Remove-ADComputer -Identity $PC.DistinguishedName `
                -Credential $ADCredential -Confirm:$false -ErrorAction Stop
            Write-Log "  - $($PC.Name)" -Level SUCCESS
            $Script:DeletedComputers++
        }
        catch {
            Write-Log "  ERREUR $($PC.Name) : $($_.Exception.Message)" -Level ERROR
            $Script:Errors++
        }
    }
}
else {
    Write-Log "  OU=Ordinateurs introuvable - etape ignoree" -Level WARNING
}

Write-Host ""
Write-Log "Etape 2 terminee - Ordinateurs supprimes : $Script:DeletedComputers" -Level SUCCESS
Write-Host ""

# -----------------------------------------------------------------------
# ETAPE 3 : SUPPRESSION DES GROUPES
# -----------------------------------------------------------------------

Write-Log "--- ETAPE 3 : Suppression des groupes ---" -Level INFO
Write-Host ""

$GrpBase = "OU=Groupes,$SiteDN"
$GrpExists = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$GrpBase'" `
    -Credential $ADCredential -EA SilentlyContinue

if ($GrpExists) {
    $Groups = Get-ADGroup -Filter * -SearchBase $GrpBase `
        -Credential $ADCredential -EA SilentlyContinue

    Write-Log "  Groupes trouves : $($Groups.Count)" -Level INFO

    foreach ($Group in $Groups) {
        try {
            if ($WhatIf) {
                Write-Log "  [SIM] Suppression groupe : $($Group.Name)" -Level INFO
                $Script:DeletedGroups++; continue
            }
            Remove-ADGroup -Identity $Group.DistinguishedName `
                -Credential $ADCredential -Confirm:$false -ErrorAction Stop
            Write-Log "  - $($Group.Name)" -Level SUCCESS
            $Script:DeletedGroups++
        }
        catch {
            Write-Log "  ERREUR $($Group.Name) : $($_.Exception.Message)" -Level ERROR
            $Script:Errors++
        }
    }
}
else {
    Write-Log "  OU=Groupes introuvable - etape ignoree" -Level WARNING
}

Write-Host ""
Write-Log "Etape 3 terminee - Groupes supprimes : $Script:DeletedGroups" -Level SUCCESS
Write-Host ""

# -----------------------------------------------------------------------
# ETAPE 4 : SUPPRESSION DE L'ARBORESCENCE DES OUs
# -----------------------------------------------------------------------

Write-Log "--- ETAPE 4 : Suppression de l arborescence OU=$RootOU ---" -Level INFO
Write-Host ""

if ($WhatIf) {
    $AllOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $RootDN `
        -Credential $ADCredential -EA SilentlyContinue
    Write-Log "  [SIM] $($AllOUs.Count + 1) OUs seraient supprimees (dont OU=$RootOU)" -Level INFO
    $Script:DeletedOUs += $AllOUs.Count + 1
}
else {
    # Desactiver la protection sur toutes les OUs en une passe avant suppression
    Write-Log "  Desactivation de la protection sur toutes les OUs..." -Level INFO
    Get-ADOrganizationalUnit -Filter * -SearchBase $RootDN `
        -Credential $ADCredential -EA SilentlyContinue |
        ForEach-Object {
            Set-ADOrganizationalUnit -Identity $_.DistinguishedName `
                -ProtectedFromAccidentalDeletion $false `
                -Credential $ADCredential -EA SilentlyContinue
        }
    # Desactiver aussi sur la racine
    Set-ADOrganizationalUnit -Identity $RootDN `
        -ProtectedFromAccidentalDeletion $false `
        -Credential $ADCredential -EA SilentlyContinue

    # Suppression recursive de la racine (emporte tout le contenu restant)
    try {
        Remove-ADOrganizationalUnit -Identity $RootDN `
            -Credential $ADCredential -Confirm:$false -Recursive -ErrorAction Stop
        Write-Log "  - OU=$RootOU et tout son contenu supprimee" -Level SUCCESS
        $Script:DeletedOUs++
    }
    catch {
        Write-Log "  ERREUR suppression OU=$RootOU : $($_.Exception.Message)" -Level ERROR
        Write-Log "  Tentative de suppression en profondeur..." -Level WARNING
        Remove-OURecursive -OUDN $RootDN
    }
}

Write-Host ""
Write-Log "Etape 4 terminee - OUs supprimees : $Script:DeletedOUs" -Level SUCCESS
Write-Host ""

# ============================================================================
# RECAPITULATIF
# ============================================================================

Write-Log "========================================" -Level INFO
Write-Log "RECAPITULATIF NETTOYAGE"                  -Level INFO
Write-Log "  Utilisateurs   : $Script:DeletedUsers"     -Level SUCCESS
Write-Log "  Ordinateurs    : $Script:DeletedComputers"  -Level SUCCESS
Write-Log "  Groupes        : $Script:DeletedGroups"     -Level SUCCESS
Write-Log "  OUs            : $Script:DeletedOUs"        -Level SUCCESS
Write-Log "  Erreurs        : $Script:Errors"            -Level $(if($Script:Errors -gt 0){'ERROR'}else{'INFO'})
Write-Log "========================================" -Level INFO

if ($WhatIf) {
    Write-Host ""
    Write-Host "Simulation terminee - aucun objet supprime." -ForegroundColor Cyan
    Write-Host "Relancez sans -WhatIf pour effectuer la suppression reelle." -ForegroundColor Cyan
}
else {
    Write-Host ""
    Write-Host "Nettoyage termine. Verifiez la console AD pour confirmer." -ForegroundColor Green
}

Write-Log "FIN - Nettoyage AD" -Level INFO
