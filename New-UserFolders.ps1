# Requires -RunAsAdministrator
###########################################################
# New-UserFolders-Debug.ps1
# BillU - Groupe 1 - Sprint 4
###########################################################

$ErrorActionPreference = 'Stop' # Crucial pour que chaque erreur soit capturée immédiatement

$baseDir      = 'E:\Partages\Utilisateurs'
$ouPath       = 'OU=Utilisateurs,OU=Paris,OU=France,OU=BillU,DC=billu,DC=local'
$logFile      = 'C:\Windows\Logs\BillU\NewUserFolders.log'
$adminGroup   = 'BUILTIN\Administrators'
$systemAcc    = 'NT AUTHORITY\SYSTEM'
$targetAdGroup = 'GROUPE_ADMIN'

# --- Initialisation du Log ---
if (-not (Test-Path (Split-Path $logFile))) {
    New-Item -Path (Split-Path $logFile) -ItemType Directory -Force | Out-Null
}

function Write-Log($msg, $lvl = 'INFO') {
    $line = "[$(Get-Date -f 'HH:mm:ss')] [$lvl] $msg"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Host $line
}

# --- ÉTAPE 0 : Vérification du Groupe AD ---
try {
    $currentStep = "Vérification de l'existence du groupe AD ($targetAdGroup)"
    $adGroupObj = Get-ADGroup -Identity $targetAdGroup -ErrorAction Stop
    Write-Log "Groupe AD '$targetAdGroup' trouvé (SID: $($adGroupObj.SID))" 'OK'
} catch {
    Write-Log "ERREUR CRITIQUE [$currentStep] : $($_.Exception.Message)" 'ERROR'
    exit 1
}

# --- ÉTAPE 1 : Récupération des utilisateurs ---
try {
    $currentStep = "Lecture de l'OU dans l'Active Directory"
    $users = Get-ADUser -Filter * -SearchBase $ouPath -Properties SamAccountName, Enabled, SID |
             Where-Object { $_.Enabled -eq $true }
    Write-Log "Début du traitement pour $($users.Count) utilisateurs." 'INFO'
} catch {
    Write-Log "ERREUR CRITIQUE [$currentStep] : $($_.Exception.Message)" 'ERROR'
    exit 1
}

# --- BOUCLE PRINCIPALE ---
foreach ($user in $users) {
    $login  = $user.SamAccountName
    $folder = Join-Path $baseDir $login
    
    try {
        # --- ÉTAPE 2 : Création du dossier ---
        $currentStep = "Création physique du dossier ($folder)"
        if (-not (Test-Path $folder)) {
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
            Write-Log "Dossier créé pour $login" 'OK'
        }

        # --- ÉTAPE 3 : Préparation de l'ACL ---
        $currentStep = "Initialisation de l'ACL (Get-Acl / Heritage)"
        $acl = Get-Acl -Path $folder
        $acl.SetAccessRuleProtection($true, $false) # Casse l'héritage
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null # Purge

        # --- ÉTAPE 4 : Ajout SYSTEM ---
        $currentStep = "Attribution des droits : SYSTEM"
        $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $systemAcc, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleSystem)

        # --- ÉTAPE 5 : Ajout ADMINS LOCAUX ---
        $currentStep = "Attribution des droits : Administrateurs Locaux"
        $ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adminGroup, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleAdmin)

        # --- ÉTAPE 6 : Ajout GROUPE AD ADMIN ---
        $currentStep = "Attribution des droits : Groupe AD ($targetAdGroup)"
        $ruleAdAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adGroupObj.SID, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleAdAdmin)

        # --- ÉTAPE 7 : Ajout UTILISATEUR CIBLE ---
        $currentStep = "Attribution des droits : Utilisateur ($login)"
        $ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $user.SID, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleUser)

        # --- ÉTAPE 8 : Application finale de l'ACL ---
        $currentStep = "Écriture finale de l'ACL sur le disque (Set-Acl)"
        Set-Acl -Path $folder -AclObject $acl
        
        Write-Log "Succès total pour $login" 'SUCCESS'

    } catch {
        # Ici, le log te dira exactement quelle étape a échoué via $currentStep
        Write-Log "ÉCHEC pour l'utilisateur $login | Étape : [$currentStep] | Message : $($_.Exception.Message)" 'ERROR'
        continue # Passe à l'utilisateur suivant même si celui-ci a échoué
    }
}

Write-Log "=== Fin du script de maintenance ==="
