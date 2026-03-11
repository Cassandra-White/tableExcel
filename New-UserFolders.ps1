# Requires -RunAsAdministrator
###########################################################
#  New-UserFolders.ps1
#  BillU - Groupe 1 - Sprint 4
#  But : creer un dossier individuel (I:) pour chaque user AD
#        et configurer les permissions NTFS correctement
###########################################################

$ErrorActionPreference = 'Continue'

$baseDir   = 'E:\Partages\Utilisateurs'
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
        $acl = Get-Acl -Path $folder
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null

        # 1. SYSTEM
        $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $systemAcc, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleSystem)

        # 2. Admins Locaux
        $ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adminGroup, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleAdmin)

        # 3. Ton groupe AD (On utilise le SID pour être sûr)
        $adGroupObj = Get-ADGroup -Identity "GROUPE_ADMIN"
        $ruleAdAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adGroupObj.SID, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleAdAdmin)

        # 4. L'utilisateur (On utilise son SID pour éviter l'erreur de traduction)
        $ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $user.SID, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleUser)

        Set-Acl -Path $folder -AclObject $acl
        Write-Log "Permissions NTFS OK pour $login" 'OK'
    } catch {
        Write-Log "Erreur permissions $login : $($_.Exception.Message)" 'ERROR'
    } catch {
        Write-Log "Erreur permissions $login : $_" 'ERROR'
    }
}

Write-Log "=== Fin - Traitement termine ==="
exit 0
