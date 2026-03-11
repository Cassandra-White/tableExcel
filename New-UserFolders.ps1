# Requires -RunAsAdministrator
###########################################################
# New-UserFolders-UltraPrecise.ps1
# But : Identifier précisément quel ajout de droit échoue
###########################################################

$ErrorActionPreference = 'Stop'

$baseDir      = 'E:\Partages\Utilisateurs'
$ouPath       = 'OU=Utilisateurs,OU=Paris,OU=France,OU=BillU,DC=billu,DC=local'
$logFile      = 'C:\Windows\Logs\BillU\NewUserFolders_Debug.log'
$adminGroup   = 'BUILTIN\Administrators'
$systemAcc    = 'NT AUTHORITY\SYSTEM'
$targetAdGroup = 'GROUPE_ADMIN'

# --- Initialisation Log ---
if (-not (Test-Path (Split-Path $logFile))) {
    New-Item -Path (Split-Path $logFile) -ItemType Directory -Force | Out-Null
}

function Write-Log($msg, $lvl = 'INFO') {
    $line = "[$(Get-Date -f 'HH:mm:ss')] [$lvl] $msg"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Host $line
}

# --- ÉTAPE PRÉLIMINAIRE : Vérification Groupe AD ---
try {
    $adGroupObj = Get-ADGroup -Identity $targetAdGroup
    $adGroupSID = $adGroupObj.SID
    Write-Log "Groupe AD '$targetAdGroup' résolu avec succès." 'OK'
} catch {
    Write-Log "ERREUR : Impossible de trouver le groupe AD '$targetAdGroup' : $($_.Exception.Message)" 'ERROR'
    exit 1
}

# --- Récupération des utilisateurs ---
$users = Get-ADUser -Filter * -SearchBase $ouPath -Properties SamAccountName, SID, Enabled | Where-Object {$_.Enabled -eq $true}

foreach ($user in $users) {
    $login = $user.SamAccountName
    $folder = Join-Path $baseDir $login
    
    Write-Log "--- Traitement de l'utilisateur : $login ---" 'INFO'

    # 1. Création Dossier
    if (-not (Test-Path $folder)) {
        try { New-Item -Path $folder -ItemType Directory -Force | Out-Null } 
        catch { Write-Log "Erreur création dossier $folder" 'ERROR'; continue }
    }

    # 2. Préparation ACL
    try {
        $acl = Get-Acl $folder
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null
    } catch {
        Write-Log "Erreur lors de la purge des anciens droits sur $folder" 'ERROR'
        continue
    }

    # --- TEST PRÉCIS DE CHAQUE RÈGLE ---

    # TEST SYSTEM
    try {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemAcc, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Write-Log "   [OK] Permission SYSTEM ajoutée" 'DEBUG'
    } catch {
        Write-Log "   [!!!] BLOCAGE sur SYSTEM : $($_.Exception.Message)" 'ERROR'
    }

    # TEST ADMINS LOCAUX
    try {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminGroup, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Write-Log "   [OK] Permission Admins Locaux ajoutée" 'DEBUG'
    } catch {
        Write-Log "   [!!!] BLOCAGE sur ADMINS LOCAUX : $($_.Exception.Message)" 'ERROR'
    }

    # TEST GROUPE AD (GROUPE_ADMIN)
    try {
        # On utilise le SID récupéré au début
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($adGroupSID, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Write-Log "   [OK] Permission Groupe AD ($targetAdGroup) ajoutée" 'DEBUG'
    } catch {
        Write-Log "   [!!!] BLOCAGE sur GROUPE AD ($targetAdGroup) : $($_.Exception.Message)" 'ERROR'
    }

    # TEST UTILISATEUR CIBLE
    try {
        # On utilise le SID de l'objet $user
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($user.SID, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Write-Log "   [OK] Permission Utilisateur ($login) ajoutée" 'DEBUG'
    } catch {
        Write-Log "   [!!!] BLOCAGE sur UTILISATEUR ($login) : $($_.Exception.Message)" 'ERROR'
    }

    # 3. Application finale
    try {
        Set-Acl -Path $folder -AclObject $acl
        Write-Log "Succès final pour $login" 'OK'
    } catch {
        Write-Log "Erreur critique Set-Acl final pour $login : $($_.Exception.Message)" 'ERROR'
    }
}
