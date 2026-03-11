# Requires -RunAsAdministrator
###########################################################
# New-UserFolders.ps1
# BillU - Groupe 1 - Sprint 4
# But : Créer un dossier individuel pour chaque user AD
#       et configurer les permissions NTFS (SYSTEM, Admins, User)
###########################################################

$ErrorActionPreference = 'Stop' # On passe en 'Stop' pour que le catch attrape tout proprement

$baseDir      = 'E:\Partages\Utilisateurs'
$ouPath       = 'OU=Utilisateurs,OU=Paris,OU=France,OU=BillU,DC=billu,DC=local'
$logFile      = 'C:\Windows\Logs\BillU\NewUserFolders.log'
$adminGroup   = 'BUILTIN\Administrators'
$systemAcc    = 'NT AUTHORITY\SYSTEM'
$targetAdGroup = 'GROUPE_ADMIN' # Nom du groupe dans l'AD

# --- Initialisation du Log ---
if (-not (Test-Path (Split-Path $logFile))) {
    New-Item -Path (Split-Path $logFile) -ItemType Directory -Force | Out-Null
}

function Write-Log($msg, $lvl = 'INFO') {
    $line = "[$(Get-Date -f 'HH:mm:ss')] [$lvl] $msg"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Host $line
}

# --- Vérification du Groupe AD ---
try {
    $adGroupObj = Get-ADGroup -Identity $targetAdGroup -ErrorAction Stop
    Write-Log "Groupe AD identifié : $($adGroupObj.DistinguishedName)" 'OK'
} catch {
    Write-Log "ERREUR FATALE : Le groupe AD '$targetAdGroup' est introuvable. Vérifiez l'orthographe." 'ERROR'
    exit 1
}

# --- Récupération des utilisateurs ---
try {
    $users = Get-ADUser -Filter * -SearchBase $ouPath -Properties SamAccountName, Enabled, SID |
             Where-Object { $_.Enabled -eq $true }
    Write-Log "=== Début traitement pour $($users.Count) utilisateurs ==="
} catch {
    Write-Log "Impossible de lire l'OU : $ouPath" 'ERROR'
    exit 1
}

# --- Boucle de création ---
foreach ($user in $users) {
    $login  = $user.SamAccountName
    $folder = Join-Path $baseDir $login

    # 1. Création du dossier
    if (-not (Test-Path $folder)) {
        try {
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
            Write-Log "Dossier créé : $folder" 'OK'
        } catch {
            Write-Log "Échec création dossier $folder : $($_.Exception.Message)" 'ERROR'
            continue
        }
    }

    # 2. Configuration des permissions
    try {
        $acl = Get-Acl -Path $folder
        $acl.SetAccessRuleProtection($true, $false) # Désactive l'héritage
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null # Nettoyage

        # Fonction interne pour simplifier l'ajout de règles
        $AddRule = {
            param($Identity, $AclObj)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $Identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $AclObj.AddAccessRule($rule)
        }

        # Application des 4 piliers de sécurité
        Write-Log "Application des permissions pour $login..." 'DEBUG'
        
        # SYSTEM
        &$AddRule $systemAcc $acl
        
        # Administrateurs Locaux
        &$AddRule $adminGroup $acl
        
        # Groupe AD Administrateurs (via SID pour éviter l'erreur de traduction)
        &$AddRule $adGroupObj.SID $acl
        
        # L'utilisateur lui-même (via SID)
        &$AddRule $user.SID $acl

        # Enregistrement final des droits
        Set-Acl -Path $folder -AclObject $acl
        Write-Log "Permissions NTFS configurées avec succès pour $login" 'OK'

    } catch {
        Write-Log "ERREUR NTFS sur $login : $($_.Exception.Message)" 'ERROR'
    }
}

Write-Log "=== Fin du script ==="
