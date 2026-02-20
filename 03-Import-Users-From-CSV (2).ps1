# ============================================================================
# Script      : 03-Import-Users-From-CSV.ps1
# Description : Import des utilisateurs et ordinateurs depuis le CSV BillU
# Prerequis   : 00-Config.ps1 dans le meme dossier + scripts 01 et 02 executes
# ============================================================================

<#
.SYNOPSIS
    Importe les utilisateurs BillU depuis le CSV avec le compte $ADAdminUser.

.DESCRIPTION
    Toutes les operations AD utilisent $ADCredential (defini dans 00-Config.ps1).

    Phases :
      1. Creation des comptes utilisateurs
      2. Affectation aux groupes de departement + GG_ALL_Employees
      3. Configuration des relations manager
      4. Enregistrement des ordinateurs dans OU=Ordinateurs,OU=Paris,...

.PARAMETER CSVFile
    Chemin du fichier CSV (defaut : .\BillUTableau.csv)

.PARAMETER DefaultPassword
    Mot de passe initial (defaut : BillU2025!Temp)

.PARAMETER AddToGroups
    Affecter les utilisateurs aux groupes de departement (defaut : $true)

.PARAMETER ImportOrdinateurs
    Enregistrer les ordinateurs dans OU=Ordinateurs (defaut : $true)

.PARAMETER ImportExterne
    Importer aussi les employes des societes externes (defaut : $false)

.PARAMETER LogFile
    Chemin du fichier de log (defaut : $LogBaseDir\Users-Import.log)

.PARAMETER WhatIf
    Mode simulation - aucun objet AD cree ou modifie

.EXAMPLE
    .\03-Import-Users-From-CSV.ps1
    .\03-Import-Users-From-CSV.ps1 -WhatIf
    .\03-Import-Users-From-CSV.ps1 -ImportExterne -ImportOrdinateurs:$false
#>

[CmdletBinding()]
param(
    [string]$CSVFile           = ".\BillUTableau.csv",
    [string]$DefaultPassword   = "BillU2025!Temp",
    [bool]$AddToGroups         = $true,
    [bool]$ImportOrdinateurs   = $true,
    [switch]$ImportExterne,
    [string]$LogFile           = "",
    [switch]$WhatIf
)

# ============================================================================
# CHARGEMENT CONFIG
# ============================================================================

$ConfigFile = Join-Path $PSScriptRoot "00-Config.ps1"
if (-not (Test-Path $ConfigFile)) { Write-Error "00-Config.ps1 introuvable : $ConfigFile"; exit 1 }
. $ConfigFile

if (-not $LogFile) { $LogFile = Join-Path $LogBaseDir "Users-Import.log" }

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

$DomainDN       = $DomainInfo.DistinguishedName
$DomainName     = $DomainInfo.DNSRoot
$EmailDomain    = if ($DomainEmailSuffix) { $DomainEmailSuffix } else { $DomainName }
$SecurePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force

$RootDN    = "OU=$RootOU,$DomainDN"
$CountryDN = "OU=$CountryOU,$RootDN"
$SiteDN    = "OU=$SiteOU,$CountryDN"

# ============================================================================
# FONCTIONS UTILITAIRES
# Declarees avant tout appel (Normalize-Text utilisee a la construction des index)
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

function Remove-Accents {
    param([string]$Text)
    $Text = $Text -replace '[eéèêë]','e' -replace '[aàâä]','a' -replace '[oôö]','o'
    $Text = $Text -replace '[uùûü]','u'  -replace '[ç]','c'    -replace '[ïî]','i'
    $Text = $Text -replace '[ÿ]','y'
    $Text = $Text -replace "[''`"´]",'' -replace '[^\x20-\x7E]',''
    return $Text.ToLower().Trim()
}

function Normalize-Text {
    param([string]$Text)
    $Text = $Text -replace '[éèêë]','e' -replace '[àâä]','a' -replace '[ôö]','o'
    $Text = $Text -replace '[ùûü]','u'  -replace '[ç]','c'   -replace '[ïî]','i'
    return $Text.ToLower().Trim()
}

function Clean-CSVValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Trim() -eq '-') { return "" }
    return $Value.Trim()
}

function Build-LoginBase {
    # Construit la base du login : 3 premieres lettres du prenom + '.' + nom tronque
    # Le tout fait au maximum 20 caracteres (contrainte SAMAccountName)
    param([string]$Prenom, [string]$Nom)

    $CleanPrenom = (Remove-Accents $Prenom) -replace '[^a-z0-9]',''
    $CleanNom    = (Remove-Accents $Nom)    -replace '[^a-z0-9]',''

    # 3 premieres lettres du prenom (ou moins si le prenom est plus court)
    $PrenomPart = if ($CleanPrenom.Length -ge 3) { $CleanPrenom.Substring(0, 3) } else { $CleanPrenom }

    # Budget pour le nom = 20 - longueur(PrenomPart) - 1 (pour le point)
    $MaxNomLength = 20 - $PrenomPart.Length - 1
    $NomPart = if ($CleanNom.Length -gt $MaxNomLength) {
        $CleanNom.Substring(0, $MaxNomLength)
    } else { $CleanNom }

    return "$PrenomPart.$NomPart"
}

function Get-UniqueLogin {
    param([string]$Prenom, [string]$Nom)
    $Base  = Build-LoginBase -Prenom $Prenom -Nom $Nom
    $Login = $Base; $i = 2
    while (Get-ADUser -Filter "SamAccountName -eq '$Login'" `
            -Credential $ADCredential -ErrorAction SilentlyContinue) {
        # En cas de doublon : tronquer la base pour inserer le suffixe numerique
        # et rester dans les 20 caracteres (ex: "jea.dupont2")
        $Suffix     = "$i"
        $MaxBaseLen = 20 - $Suffix.Length
        $TruncBase  = if ($Base.Length -gt $MaxBaseLen) { $Base.Substring(0, $MaxBaseLen) } else { $Base }
        $Login = "$TruncBase$Suffix"
        $i++
    }
    return $Login
}

function Resolve-UserOU {
    param([string]$DeptKey, [string]$SvcKey)
    $Dept   = $DeptIndex[$DeptKey]
    $DeptOU = "OU=$($Dept.OUName),OU=Utilisateurs,$SiteDN"
    if ($SvcKey -and $ServiceIndex[$DeptKey].ContainsKey($SvcKey)) {
        return "OU=$($ServiceIndex[$DeptKey][$SvcKey]),$DeptOU"
    }
    return $DeptOU
}

# ============================================================================
# INDEX DE RESOLUTION RAPIDE
# ============================================================================

$DeptIndex    = @{}
$ServiceIndex = @{}
$DeptGroupMap = @{}

foreach ($Dept in $Departements) {
    $dk = Normalize-Text $Dept.CSVName
    $DeptIndex[$dk]    = $Dept
    $DeptGroupMap[$dk] = "GG_$($Dept.GroupCode)_Users"
    $ServiceIndex[$dk] = @{}
    foreach ($Svc in $Dept.Services) {
        $ServiceIndex[$dk][(Normalize-Text $Svc.CSVName)] = $Svc.OUName
    }
}

# ============================================================================
# FONCTION CREATION UTILISATEUR
# ============================================================================

function New-UserFromCSV {
    param([PSCustomObject]$Row)

    $Prenom    = Clean-CSVValue $Row.Prenom
    $Nom       = Clean-CSVValue $Row.Nom
    $CSVDept   = Clean-CSVValue $Row.Departement
    $CSVSvc    = Clean-CSVValue $Row.Service
    $Fonction  = Clean-CSVValue $Row.Fonction
    $TelFixe   = Clean-CSVValue $Row.'Telephone fixe'
    $TelPort   = Clean-CSVValue $Row.'Telephone portable'
    $NomPC     = Clean-CSVValue $Row.'Nom de PC'
    $MarquePC  = Clean-CSVValue $Row.'Marque PC'
    $MgrPrenom = Clean-CSVValue $Row.'Manager-Prenom'
    $MgrNom    = Clean-CSVValue $Row.'Manager-Nom'

    if (-not $Prenom -or -not $Nom) {
        Write-Log "  ERREUR ligne ignoree : Prenom ou Nom manquant" -Level ERROR
        return $false
    }

    $DeptKey = Normalize-Text $CSVDept
    $SvcKey  = Normalize-Text $CSVSvc

    if (-not $DeptIndex.ContainsKey($DeptKey)) {
        Write-Log "  ERREUR departement inconnu : '$CSVDept' -> $Prenom $Nom ignore" -Level ERROR
        return $false
    }

    $Dept     = $DeptIndex[$DeptKey]
    $TargetOU = Resolve-UserOU -DeptKey $DeptKey -SvcKey $SvcKey

    if (-not $WhatIf) {
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TargetOU'" `
                -Credential $ADCredential -EA SilentlyContinue)) {
            Write-Log "  ERREUR OU introuvable : $TargetOU -> $Prenom $Nom ignore" -Level ERROR
            return $false
        }
    }

    $Login = if ($WhatIf) {
        Build-LoginBase -Prenom $Prenom -Nom $Nom
    } else {
        Get-UniqueLogin -Prenom $Prenom -Nom $Nom
    }

    $DisplayName = "$Prenom $Nom"
    $UPN         = "$Login@$DomainName"
    $Email       = "$Login@$EmailDomain"

    if (-not $WhatIf -and (Get-ADUser -Filter "SamAccountName -eq '$Login'" `
            -Credential $ADCredential -EA SilentlyContinue)) {
        Write-Log "  SKIP $Login - compte existant" -Level WARNING
        return $null
    }

    $SvcLabel = if ($SvcKey -and $ServiceIndex[$DeptKey].ContainsKey($SvcKey)) {
        " > $($ServiceIndex[$DeptKey][$SvcKey])"
    } else { "" }
    $OULabel = "$($Dept.OUName)$SvcLabel"

    if ($WhatIf) {
        Write-Log "  [SIM] $Login ($DisplayName) | $OULabel" -Level INFO
        return @{ Login=$Login; DisplayName=$DisplayName; DeptKey=$DeptKey; SvcKey=$SvcKey
                  MgrPrenom=$MgrPrenom; MgrNom=$MgrNom; NomPC=$NomPC; MarquePC=$MarquePC; OULabel=$OULabel }
    }

    $UserParams = @{
        Name                  = $DisplayName
        GivenName             = $Prenom
        Surname               = $Nom
        SamAccountName        = $Login
        UserPrincipalName     = $UPN
        EmailAddress          = $Email
        DisplayName           = $DisplayName
        Path                  = $TargetOU
        AccountPassword       = $SecurePassword
        Enabled               = $true
        ChangePasswordAtLogon = $true
        PasswordNeverExpires  = $false
        CannotChangePassword  = $false
        Credential            = $ADCredential
    }

    if ($Fonction) { $UserParams['Title']       = $Fonction    }
    if ($CSVDept)  { $UserParams['Department']  = $Dept.OUName }
    if ($CSVSvc)   { $UserParams['Description'] = $CSVSvc      }
    if ($TelFixe)  { $UserParams['OfficePhone'] = $TelFixe     }
    if ($TelPort)  { $UserParams['MobilePhone'] = $TelPort     }

    try {
        New-ADUser @UserParams -PassThru | Out-Null
        Write-Log "  + $Login ($DisplayName) | $OULabel" -Level SUCCESS
        return @{ Login=$Login; DisplayName=$DisplayName; DeptKey=$DeptKey; SvcKey=$SvcKey
                  MgrPrenom=$MgrPrenom; MgrNom=$MgrNom; NomPC=$NomPC; MarquePC=$MarquePC; OULabel=$OULabel }
    }
    catch {
        Write-Log "  ERREUR creation $Login : $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

# ============================================================================
# SCRIPT PRINCIPAL
# ============================================================================

Write-Log "========================================" -Level INFO
Write-Log "DEBUT - Import utilisateurs [$OrgName]" -Level INFO
Write-Log "Compte   : $ADAdminUser"                -Level INFO
Write-Log "Site     : $SiteDN"                     -Level INFO
Write-Log "CSV      : $CSVFile"                    -Level INFO
if ($WhatIf) { Write-Log "!!! MODE SIMULATION !!!" -Level WARNING }
Write-Log "========================================" -Level INFO
Write-Host ""

if (-not (Test-Path $CSVFile)) {
    Write-Log "ERREUR fichier CSV introuvable : $CSVFile" -Level ERROR; exit 1
}
try   { $AllRows = Import-Csv -Path $CSVFile -Delimiter $CSVDelimiter -Encoding UTF8 }
catch { Write-Log "ERREUR lecture CSV : $($_.Exception.Message)" -Level ERROR; exit 1 }

$BillURows   = $AllRows | Where-Object { (Clean-CSVValue $_.'Societe') -eq $SocietePrincipale }
$ExterneRows = $AllRows | Where-Object { (Clean-CSVValue $_.'Societe') -ne $SocietePrincipale }
$ToImport    = if ($ImportExterne) { $AllRows } else { $BillURows }

Write-Log "Lignes CSV totales  : $($AllRows.Count)"   -Level INFO
Write-Log "  Internes $OrgName : $($BillURows.Count)" -Level INFO
Write-Log "  Externes          : $($ExterneRows.Count)$(if(-not $ImportExterne){' (ignores)'})" -Level INFO
Write-Log "  A importer        : $($ToImport.Count)"  -Level INFO
Write-Host ""

$Script:Created = 0; $Script:Skipped = 0; $Script:ErrorUsers = 0
$Script:AddedToGroups = 0; $Script:ComputersCreated = 0
$CreatedUsers = @()

# --- PHASE 1 : Comptes ---
Write-Log "--- PHASE 1 : Creation des comptes ---" -Level INFO
Write-Host ""

foreach ($Row in $ToImport) {
    $Result = New-UserFromCSV -Row $Row
    if ($Result -is [hashtable]) { $CreatedUsers += [PSCustomObject]$Result; $Script:Created++ }
    elseif ($null -eq $Result)   { $Script:Skipped++ }
    else                         { $Script:ErrorUsers++ }
}

Write-Host ""
Write-Log "Phase 1 terminee - Crees : $Script:Created | Skips : $Script:Skipped | Erreurs : $Script:ErrorUsers" -Level SUCCESS
Write-Host ""

# --- PHASE 2 : Groupes ---
if ($AddToGroups -and -not $WhatIf) {
    Write-Log "--- PHASE 2 : Affectation aux groupes ---" -Level INFO
    Write-Host ""

    foreach ($User in $CreatedUsers) {
        $GName = $DeptGroupMap[$User.DeptKey]
        if (-not $GName) { continue }
        if (-not (Get-ADGroup -Filter "Name -eq '$GName'" -Credential $ADCredential -EA SilentlyContinue)) {
            Write-Log "  WARN groupe introuvable : $GName" -Level WARNING; continue
        }
        try {
            Add-ADGroupMember -Identity $GName -Members $User.Login `
                -Credential $ADCredential -ErrorAction Stop
            Write-Log "  + $($User.Login) -> $GName" -Level SUCCESS
            $Script:AddedToGroups++
        }
        catch { Write-Log "  ERREUR $($User.Login) -> $GName : $($_.Exception.Message)" -Level ERROR }
    }

    Write-Host ""
    if (Get-ADGroup -Filter "Name -eq 'GG_ALL_Employees'" -Credential $ADCredential -EA SilentlyContinue) {
        foreach ($User in $CreatedUsers) {
            Add-ADGroupMember -Identity "GG_ALL_Employees" -Members $User.Login `
                -Credential $ADCredential -EA SilentlyContinue
        }
        Write-Log "$($CreatedUsers.Count) utilisateurs -> GG_ALL_Employees" -Level SUCCESS
    }

    Write-Host ""
    Write-Log "Phase 2 terminee - Ajouts groupes : $Script:AddedToGroups" -Level SUCCESS
    Write-Host ""
}

# --- PHASE 3 : Managers ---
if (-not $WhatIf) {
    Write-Log "--- PHASE 3 : Configuration des managers ---" -Level INFO
    Write-Host ""
    $ManagersSet = 0

    foreach ($User in $CreatedUsers) {
        if (-not $User.MgrPrenom -or -not $User.MgrNom) { continue }
        $MgrLogin = Build-LoginBase -Prenom $User.MgrPrenom -Nom $User.MgrNom
        $Mgr = Get-ADUser -Filter "SamAccountName -eq '$MgrLogin'" `
                -Credential $ADCredential -EA SilentlyContinue
        if ($Mgr) {
            try {
                Set-ADUser -Identity $User.Login -Manager $Mgr.DistinguishedName `
                    -Credential $ADCredential -ErrorAction Stop
                Write-Log "  + $($User.Login) -> manager : $MgrLogin" -Level SUCCESS
                $ManagersSet++
            }
            catch { Write-Log "  ERREUR manager $($User.Login) : $($_.Exception.Message)" -Level ERROR }
        }
        else { Write-Log "  WARN manager introuvable : $MgrLogin" -Level WARNING }
    }

    Write-Host ""
    Write-Log "Phase 3 terminee - Managers definis : $ManagersSet" -Level SUCCESS
    Write-Host ""
}

# --- PHASE 4 : Ordinateurs ---
if ($ImportOrdinateurs -and -not $WhatIf) {
    Write-Log "--- PHASE 4 : Enregistrement des ordinateurs ---" -Level INFO
    Write-Host ""

    $ComputerOU = "OU=$OuPCs,$SiteDN"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ComputerOU'" `
            -Credential $ADCredential -EA SilentlyContinue)) {
        Write-Log "ERREUR OU Ordinateurs introuvable : $ComputerOU" -Level ERROR
    }
    else {
        foreach ($User in $CreatedUsers) {
            if (-not $User.NomPC) { continue }
            if (Get-ADComputer -Filter "Name -eq '$($User.NomPC)'" `
                    -Credential $ADCredential -EA SilentlyContinue) {
                Write-Log "  (existe)  $($User.NomPC)" -Level WARNING; continue
            }
            $Desc = "$($User.DisplayName) - $($User.OULabel)$(if($User.MarquePC){" - $($User.MarquePC)"})"
            try {
                New-ADComputer -Name $User.NomPC -Path $ComputerOU -Description $Desc `
                    -ManagedBy $User.Login -Enabled $true `
                    -Credential $ADCredential -ErrorAction Stop
                Write-Log "  + $($User.NomPC) -> $($User.Login)" -Level SUCCESS
                $Script:ComputersCreated++
            }
            catch { Write-Log "  ERREUR $($User.NomPC) : $($_.Exception.Message)" -Level ERROR }
        }
    }

    Write-Host ""
    Write-Log "Phase 4 terminee - Ordinateurs enregistres : $Script:ComputersCreated" -Level SUCCESS
    Write-Host ""
}

# ============================================================================
# RECAPITULATIF
# ============================================================================

Write-Log "========================================" -Level INFO
Write-Log "RECAPITULATIF FINAL"                      -Level INFO
Write-Log "  Comptes crees      : $Script:Created"         -Level SUCCESS
Write-Log "  Skips (existants)  : $Script:Skipped"         -Level WARNING
Write-Log "  Erreurs            : $Script:ErrorUsers"      -Level ERROR
Write-Log "  Ajouts groupes     : $Script:AddedToGroups"   -Level INFO
Write-Log "  Ordinateurs crees  : $Script:ComputersCreated" -Level INFO
Write-Log "========================================" -Level INFO

if (-not $WhatIf -and $Script:Created -gt 0) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $ExportUsers = Join-Path $LogBaseDir "Export-Users-$stamp.csv"
    Get-ADUser -Filter * -SearchBase "OU=Utilisateurs,$SiteDN" -Credential $ADCredential `
        -Properties Department,Description,Title,EmailAddress,OfficePhone,MobilePhone,Manager |
        Select-Object @{N='Login';E={$_.SamAccountName}}, @{N='Nom complet';E={$_.Name}},
                      Department, @{N='Service';E={$_.Description}}, Title,
                      EmailAddress, OfficePhone, MobilePhone,
                      @{N='Manager';E={(Get-ADUser $_.Manager -Credential $ADCredential -EA SilentlyContinue).SamAccountName}},
                      DistinguishedName, Enabled |
        Export-Csv -Path $ExportUsers -NoTypeInformation -Encoding UTF8
    Write-Log "Export utilisateurs : $ExportUsers" -Level SUCCESS
}

Write-Log "FIN - Import utilisateurs" -Level INFO
