# ============================================================================
# Script      : 03-Import-Users-From-CSV.ps1
# Description : Import des utilisateurs et ordinateurs depuis le CSV BillU
# Prerequis   : 00-Config.ps1 dans le meme dossier + scripts 01 et 02 executes
# ============================================================================

<#
.SYNOPSIS
    Importe les utilisateurs BillU depuis le CSV (separateur ";").

.DESCRIPTION
    Format CSV attendu (separateur = ";") :
      Civilite;Prenom;Nom;Societe;Site;Departement;Service;Fonction;
      Manager-Prenom;Manager-Nom;Nom de PC;Marque PC;Date de naissance;
      Telephone fixe;Telephone portable

    Placement des utilisateurs dans l'OU AD :
      -> Avec service :
             OU=<Svc.OUName>,OU=<Dept.OUName>,OU=Utilisateurs,OU=BillU,...
      -> Sans service (Direction, Recrutement) :
             OU=<Dept.OUName>,OU=Utilisateurs,OU=BillU,...

    Les valeurs "-" dans le CSV sont traitees comme vides.
    Les logins sont generes en ASCII pur : prenom.nom
    Les employes de societes externes sont ignores par defaut (-ImportExterne pour les inclure).

    Phases :
      1. Creation des comptes utilisateurs
      2. Affectation aux groupes de departement + GG_ALL_Employees
      3. Configuration des relations manager
      4. Enregistrement des ordinateurs dans OU=Ordinateurs,OU=BillU,...

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
    .\03-Import-Users-From-CSV.ps1 -CSVFile "C:\Data\export.csv" -DefaultPassword "P@ss2025!"
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

$DomainDN       = (Get-ADDomain).DistinguishedName
$DomainName     = (Get-ADDomain).DNSRoot
$EmailDomain    = if ($DomainEmailSuffix) { $DomainEmailSuffix } else { $DomainName }
$SecurePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force

# DN de l'OU racine BillU - tous les chemins s'appuient dessus
$RootDN = "OU=$RootOU,$DomainDN"

# Index de resolution rapide (construit une seule fois au demarrage)
$DeptIndex    = @{}   # cle normalise -> hashtable Dept complet
$ServiceIndex = @{}   # cle dept      -> { cle service -> OUName service }
$DeptGroupMap = @{}   # cle dept      -> nom du groupe GG_..._Users

foreach ($Dept in $Departements) {
    $dk = Normalize-Text $Dept.CSVName
    $DeptIndex[$dk]    = $Dept
    $DeptGroupMap[$dk] = "GG_$($Dept.GroupCode)_Users"
    $ServiceIndex[$dk] = @{}
    foreach ($Svc in $Dept.Services) {
        $sk = Normalize-Text $Svc.CSVName
        $ServiceIndex[$dk][$sk] = $Svc.OUName
    }
}

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

function Remove-Accents {
    # Retourne une chaine ASCII pure minuscules - utilise pour les logins AD
    param([string]$Text)
    $Text = $Text -replace '[eéèêë]','e' -replace '[aàâä]','a' -replace '[oôö]','o'
    $Text = $Text -replace '[uùûü]','u'  -replace '[ç]','c'    -replace '[ïî]','i'
    $Text = $Text -replace '[ÿ]','y'
    $Text = $Text -replace "[''`"´]",'' -replace '[^\x20-\x7E]',''
    return $Text.ToLower().Trim()
}

function Normalize-Text {
    # Normalise pour comparaison CSV <-> config (ne sert PAS a generer des noms AD)
    param([string]$Text)
    $Text = $Text -replace '[éèêë]','e' -replace '[àâä]','a' -replace '[ôö]','o'
    $Text = $Text -replace '[ùûü]','u'  -replace '[ç]','c'   -replace '[ïî]','i'
    return $Text.ToLower().Trim()
}

function Clean-CSVValue {
    # Retourne une chaine vide si la valeur est "-", nulle ou vide
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Trim() -eq '-') { return "" }
    return $Value.Trim()
}

function Get-UniqueLogin {
    # Genere un login unique prenom.nom en ASCII avec suffixe numerique si doublon
    param([string]$Prenom, [string]$Nom)
    $Base  = "$(Remove-Accents $Prenom).$(Remove-Accents $Nom)" -replace '[^a-z0-9.]',''
    $Login = $Base; $i = 2
    while (Get-ADUser -Filter "SamAccountName -eq '$Login'" -ErrorAction SilentlyContinue) {
        $Login = "$Base$i"; $i++
    }
    return $Login
}

function Resolve-UserOU {
    # Retourne le DN de l'OU cible sous OU=Utilisateurs,OU=BillU,...
    # Priorite : OU service > OU departement
    param([string]$DeptKey, [string]$SvcKey)

    $Dept   = $DeptIndex[$DeptKey]
    $DeptOU = "OU=$($Dept.OUName),OU=Utilisateurs,$RootDN"

    if ($SvcKey -and $ServiceIndex[$DeptKey].ContainsKey($SvcKey)) {
        $SvcOUName = $ServiceIndex[$DeptKey][$SvcKey]
        return "OU=$SvcOUName,$DeptOU"
    }
    return $DeptOU
}

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
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TargetOU'" -EA SilentlyContinue)) {
            Write-Log "  ERREUR OU introuvable : $TargetOU -> $Prenom $Nom ignore" -Level ERROR
            return $false
        }
    }

    $Login = if ($WhatIf) {
        "$(Remove-Accents $Prenom).$(Remove-Accents $Nom)" -replace '[^a-z0-9.]',''
    } else {
        Get-UniqueLogin -Prenom $Prenom -Nom $Nom
    }

    $UPN         = "$Login@$DomainName"
    $DisplayName = "$Prenom $Nom"
    $Email       = "$Login@$EmailDomain"

    if (-not $WhatIf -and (Get-ADUser -Filter "SamAccountName -eq '$Login'" -EA SilentlyContinue)) {
        Write-Log "  SKIP $Login - compte existant" -Level WARNING
        return $null
    }

    # Label de log : Dept > Service ou Dept seul
    $SvcOUName = if ($SvcKey -and $ServiceIndex[$DeptKey].ContainsKey($SvcKey)) {
        $ServiceIndex[$DeptKey][$SvcKey]
    } else { "" }
    $OULabel = if ($SvcOUName) { "$($Dept.OUName) > $SvcOUName" } else { $Dept.OUName }

    if ($WhatIf) {
        Write-Log "  [SIM] $Login ($DisplayName) | $OULabel" -Level INFO
        return @{
            Login      = $Login; DisplayName = $DisplayName
            DeptKey    = $DeptKey; SvcKey    = $SvcKey
            MgrPrenom  = $MgrPrenom; MgrNom  = $MgrNom
            NomPC      = $NomPC; MarquePC    = $MarquePC
            OULabel    = $OULabel
        }
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
    }

    if ($Fonction)  { $UserParams['Title']       = $Fonction      }
    if ($CSVDept)   { $UserParams['Department']  = $Dept.OUName   }
    if ($CSVSvc)    { $UserParams['Description'] = $CSVSvc        }
    if ($TelFixe)   { $UserParams['OfficePhone'] = $TelFixe       }
    if ($TelPort)   { $UserParams['MobilePhone'] = $TelPort       }

    try {
        New-ADUser @UserParams -PassThru | Out-Null
        Write-Log "  + $Login ($DisplayName) | $OULabel" -Level SUCCESS
        return @{
            Login      = $Login; DisplayName = $DisplayName
            DeptKey    = $DeptKey; SvcKey    = $SvcKey
            MgrPrenom  = $MgrPrenom; MgrNom  = $MgrNom
            NomPC      = $NomPC; MarquePC    = $MarquePC
            OULabel    = $OULabel
        }
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
Write-Log "Racine   : OU=$RootOU,$DomainDN"        -Level INFO
Write-Log "CSV      : $CSVFile"                    -Level INFO
Write-Log "Groupes  : $AddToGroups"                -Level INFO
Write-Log "PCs      : $ImportOrdinateurs"          -Level INFO
Write-Log "Externes : $ImportExterne"              -Level INFO
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
Write-Log "  Externes          : $($ExterneRows.Count)$(if (-not $ImportExterne){' (ignores)'})" -Level INFO
Write-Log "  A importer        : $($ToImport.Count)"  -Level INFO
Write-Host ""

$Script:Created = 0; $Script:Skipped = 0; $Script:ErrorUsers = 0
$Script:AddedToGroups = 0; $Script:ComputersCreated = 0
$CreatedUsers = @()

# ============================================================================
# PHASE 1 : CREATION DES COMPTES
# ============================================================================

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

# ============================================================================
# PHASE 2 : AFFECTATION AUX GROUPES
# ============================================================================

if ($AddToGroups -and -not $WhatIf) {
    Write-Log "--- PHASE 2 : Affectation aux groupes ---" -Level INFO
    Write-Host ""

    foreach ($User in $CreatedUsers) {
        $GName = $DeptGroupMap[$User.DeptKey]
        if (-not $GName) {
            Write-Log "  WARN pas de groupe pour '$($User.DeptKey)'" -Level WARNING; continue
        }
        if (-not (Get-ADGroup -Filter "Name -eq '$GName'" -EA SilentlyContinue)) {
            Write-Log "  WARN groupe introuvable : $GName  (script 02 execute ?)" -Level WARNING; continue
        }
        try {
            Add-ADGroupMember -Identity $GName -Members $User.Login -ErrorAction Stop
            Write-Log "  + $($User.Login) -> $GName" -Level SUCCESS
            $Script:AddedToGroups++
        }
        catch { Write-Log "  ERREUR $($User.Login) -> $GName : $($_.Exception.Message)" -Level ERROR }
    }

    Write-Host ""
    if (Get-ADGroup -Filter "Name -eq 'GG_ALL_Employees'" -EA SilentlyContinue) {
        foreach ($User in $CreatedUsers) {
            Add-ADGroupMember -Identity "GG_ALL_Employees" -Members $User.Login -EA SilentlyContinue
        }
        Write-Log "$($CreatedUsers.Count) utilisateurs -> GG_ALL_Employees" -Level SUCCESS
    }
    else { Write-Log "WARN GG_ALL_Employees introuvable  (script 02 execute ?)" -Level WARNING }

    Write-Host ""
    Write-Log "Phase 2 terminee - Ajouts groupes : $Script:AddedToGroups" -Level SUCCESS
    Write-Host ""
}

# ============================================================================
# PHASE 3 : CONFIGURATION DES MANAGERS
# ============================================================================

if (-not $WhatIf) {
    Write-Log "--- PHASE 3 : Configuration des managers ---" -Level INFO
    Write-Host ""

    $ManagersSet = 0

    foreach ($User in $CreatedUsers) {
        if (-not $User.MgrPrenom -or -not $User.MgrNom) { continue }
        $MgrLogin = "$(Remove-Accents $User.MgrPrenom).$(Remove-Accents $User.MgrNom)" -replace '[^a-z0-9.]',''
        $Mgr = Get-ADUser -Filter "SamAccountName -eq '$MgrLogin'" -EA SilentlyContinue

        if ($Mgr) {
            try {
                Set-ADUser -Identity $User.Login -Manager $Mgr.DistinguishedName -ErrorAction Stop
                Write-Log "  + $($User.Login) -> manager : $MgrLogin" -Level SUCCESS
                $ManagersSet++
            }
            catch { Write-Log "  ERREUR manager $($User.Login) : $($_.Exception.Message)" -Level ERROR }
        }
        else { Write-Log "  WARN manager introuvable : $MgrLogin (pour $($User.Login))" -Level WARNING }
    }

    Write-Host ""
    Write-Log "Phase 3 terminee - Managers definis : $ManagersSet" -Level SUCCESS
    Write-Host ""
}

# ============================================================================
# PHASE 4 : ENREGISTREMENT DES ORDINATEURS
# ============================================================================

if ($ImportOrdinateurs -and -not $WhatIf) {
    Write-Log "--- PHASE 4 : Enregistrement des ordinateurs ---" -Level INFO
    Write-Host ""

    $ComputerOU = "OU=$OuPCs,$RootDN"

    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ComputerOU'" -EA SilentlyContinue)) {
        Write-Log "ERREUR OU Ordinateurs introuvable : $ComputerOU  (script 01 execute ?)" -Level ERROR
    }
    else {
        foreach ($User in $CreatedUsers) {
            $NomPC    = $User.NomPC
            $MarquePC = $User.MarquePC
            if (-not $NomPC) { continue }

            if (Get-ADComputer -Filter "Name -eq '$NomPC'" -EA SilentlyContinue) {
                Write-Log "  (existe)  $NomPC" -Level WARNING; continue
            }

            $Desc = "$($User.DisplayName) - $($User.OULabel)$(if($MarquePC){" - $MarquePC"})"

            try {
                New-ADComputer -Name $NomPC -Path $ComputerOU -Description $Desc `
                    -ManagedBy $User.Login -Enabled $true -ErrorAction Stop
                Write-Log "  + $NomPC $(if($MarquePC){"($MarquePC) "})-> $($User.Login)" -Level SUCCESS
                $Script:ComputersCreated++
            }
            catch { Write-Log "  ERREUR $NomPC : $($_.Exception.Message)" -Level ERROR }
        }
    }

    Write-Host ""
    Write-Log "Phase 4 terminee - Ordinateurs enregistres : $Script:ComputersCreated" -Level SUCCESS
    Write-Host ""
}

# ============================================================================
# RECAPITULATIF FINAL
# ============================================================================

Write-Log "========================================" -Level INFO
Write-Log "RECAPITULATIF FINAL"                      -Level INFO
Write-Log "  A importer         : $($ToImport.Count)"     -Level INFO
Write-Log "  Comptes crees      : $Script:Created"         -Level SUCCESS
Write-Log "  Skips (existants)  : $Script:Skipped"         -Level WARNING
Write-Log "  Erreurs            : $Script:ErrorUsers"      -Level ERROR
if ($AddToGroups -and -not $WhatIf) {
    Write-Log "  Ajouts groupes     : $Script:AddedToGroups" -Level INFO
}
if ($ImportOrdinateurs -and -not $WhatIf) {
    Write-Log "  Ordinateurs crees  : $Script:ComputersCreated" -Level INFO
}
Write-Log "========================================" -Level INFO
Write-Host ""

if (-not $WhatIf -and $Script:Created -gt 0) {
    Write-Log "--- Repartition par departement / service ---" -Level INFO
    Write-Host ""

    foreach ($Dept in $Departements) {
        $DeptOUDN = "OU=$($Dept.OUName),OU=Utilisateurs,$RootDN"
        if ($Dept.Services.Count -eq 0) {
            $n = (Get-ADUser -Filter * -SearchBase $DeptOUDN -SearchScope OneLevel -EA SilentlyContinue).Count
            Write-Host "  $($Dept.OUName) (direct) : $n" -ForegroundColor White
        }
        else {
            foreach ($Svc in $Dept.Services) {
                $SvcOUDN = "OU=$($Svc.OUName),$DeptOUDN"
                $n = (Get-ADUser -Filter * -SearchBase $SvcOUDN -EA SilentlyContinue).Count
                Write-Host "  $($Dept.OUName) > $($Svc.OUName) : $n" -ForegroundColor White
            }
        }
    }
    Write-Host ""

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    $ExportUsers = Join-Path $LogBaseDir "Export-Users-$stamp.csv"
    Get-ADUser -Filter * -SearchBase "OU=Utilisateurs,$RootDN" `
        -Properties Department, Description, Title, EmailAddress, OfficePhone, MobilePhone, Manager |
        Select-Object @{N='Login';E={$_.SamAccountName}},
                      @{N='Nom complet';E={$_.Name}},
                      Department,
                      @{N='Service';E={$_.Description}},
                      Title, EmailAddress, OfficePhone, MobilePhone,
                      @{N='Manager';E={(Get-ADUser $_.Manager -EA SilentlyContinue).SamAccountName}},
                      DistinguishedName, Enabled |
        Export-Csv -Path $ExportUsers -NoTypeInformation -Encoding UTF8
    Write-Log "Export utilisateurs : $ExportUsers" -Level SUCCESS

    if ($ImportOrdinateurs -and $Script:ComputersCreated -gt 0) {
        $ExportPCs = Join-Path $LogBaseDir "Export-PCs-$stamp.csv"
        Get-ADComputer -Filter * -SearchBase "OU=$OuPCs,$RootDN" -Properties Description, ManagedBy |
            Select-Object Name, Description,
                          @{N='ManagedBy';E={(Get-ADUser $_.ManagedBy -EA SilentlyContinue).SamAccountName}} |
            Export-Csv -Path $ExportPCs -NoTypeInformation -Encoding UTF8
        Write-Log "Export ordinateurs  : $ExportPCs" -Level SUCCESS
    }
    Write-Host ""
}

Write-Log "FIN - Import utilisateurs" -Level INFO
