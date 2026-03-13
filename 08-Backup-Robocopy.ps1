#Requires -RunAsAdministrator
# 08-Backup-Robocopy.ps1 -- BillU Sprint 5
# Sauvegarde incrementielle de D:\Partages vers E:\Backup
# Planifie chaque nuit a 02h00 par la tache BillU-Backup

$source  = "D:\Partages"
$dest    = "E:\Backup\Partages"
$logDir  = "E:\Backup\Logs"
$logFile = "$logDir\backup-$(Get-Date -Format 'yyyyMMdd-HHmm').log"
$retain  = 30   # Jours de retention des logs

# Creer les dossiers de destination si absents
New-Item $dest   -ItemType Directory -Force | Out-Null
New-Item $logDir -ItemType Directory -Force | Out-Null

Write-Host "=== Sauvegarde BillU -- $(Get-Date -Format 'dd/MM/yyyy HH:mm') ==="
Write-Host "  Source      : $source"
Write-Host "  Destination : $dest"
Write-Host "  Log         : $logFile"

# Lancement de Robocopy
# /MIR   = miroir complet (supprime a dest ce qui n est plus a la source)
# /R:2   = 2 tentatives par fichier en cas d echec
# /W:5   = 5 secondes d attente entre les tentatives
# /NP    = ne pas afficher le % progression (allege le log)
# /LOG   = ecrire le resultat dans le fichier de log
$proc = Start-Process -FilePath "robocopy.exe" `
    -ArgumentList "`"$source`" `"$dest`" /MIR /R:2 /W:5 /NP /LOG:`"$logFile`"" `
    -Wait -PassThru -NoNewWindow

$code = $proc.ExitCode

if ($code -le 3) {
    Write-Host "[OK] Robocopy termine -- code $code (succes)"
    Add-Content $logFile "[OK] Sauvegarde terminee -- $(Get-Date)"
} else {
    Write-Host "[ERREUR] Robocopy code $code -- voir le log : $logFile"
    Add-Content $logFile "[ERREUR] Code $code -- $(Get-Date)"
}

# Supprimer les logs de plus de 30 jours (rotation)
Get-ChildItem $logDir -Filter "*.log" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$retain) } |
    Remove-Item -Force
Write-Host "Rotation logs terminee (suppression apres $retain jours)"
