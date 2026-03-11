# Requires -RunAsAdministrator
###########################################################
#  New-UserFolders.ps1
#  BillU - Groupe 1 - Sprint 4
#  But : creer un dossier individuel (I:) pour chaque user AD
#        et configurer les permissions NTFS correctement
###########################################################

$ErrorActionPreference = 'Continue'

$baseDir   = 'D:\Partages\Utilisateurs'
$ouPath    = 'OU=Utilisateurs,OU=Paris,OU=France,OU=BillU,DC=billu,DC=local'
$logFile   = 'C:\Windows\Logs\BillU\NewUserFolders.log'
$adminGroup = 'BUILTIN\Administrators'
$systemAcc  = 'NT AUTHORITY\SYSTEM'
$adAdminGroup = 'BILLU\GROUPE_ADMIN'

if (-not (Test-Path (Split-Path $logFile))) {
    New-Item -Path (Split-Path $logFile) -ItemType Directory -Force | Out-Null
}

function Write-Log($msg, $lvl = 'INFO') {
    $line = "[$(Get-Date -f 'HH:mm:ss')] [$lvl] $msg"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Host $line
}

# Recupere tous les utilisateurs de l'OU
$users = Get-ADUser -Filter * -SearchBase $ouPath `
    -Properties SamAccountName, Enabled |
    Where-Object { $_.Enabled -eq $true }

Write-Log "=== Debut creation dossiers pour $($users.Count) utilisateurs ==="

foreach ($user in $users) {
    $login   = $user.SamAccountName
    $folder  = Join-Path $baseDir $login

    # Creer le dossier s'il n'existe pas
    if (-not (Test-Path $folder)) {
        try {
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
            Write-Log "Dossier cree : $folder" 'OK'
        } catch {
            Write-Log "Echec creation $folder : $_" 'ERROR'
            continue
        }
    } else {
        Write-Log "Dossier deja present : $folder" 'WARN'
    }

    # Configurer les permissions NTFS
    try {
        # Charge l'ACL actuelle du dossier
        $acl = Get-Acl -Path $folder

        # Desactiver l'heritage et supprimer les permissions heritees
        $acl.SetAccessRuleProtection($true, $false)

        # Supprimer toutes les entrees existantes (repartir de zero)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null

        # Ajouter SYSTEM avec Controle total
        $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $systemAcc, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleSystem)

        # Ajouter les Admins avec Controle total
        $ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adminGroup, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleAdmin)

        # Ajouter l'utilisateur avec Controle total sur son propre dossier
        $domainUser = "BILLU\$login"
        $ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $domainUser, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleUser)

        # Ajouter le groupe GROUPE_ADMIN de l'AD avec Controle total
      $ruleAdAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
          $adAdminGroup, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
      $acl.AddAccessRule($ruleAdAdmin)

        # Appliquer l'ACL au dossier
        Set-Acl -Path $folder -AclObject $acl
        Write-Log "Permissions NTFS configurees pour $login" 'OK'
    } catch {
        Write-Log "Erreur permissions $login : $_" 'ERROR'
    }
}

Write-Log "=== Fin - Traitement termine ==="
exit 0
