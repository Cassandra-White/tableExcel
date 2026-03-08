# 1. Récupération des postes
$postes = Get-ADComputer -Filter * -SearchBase "DC=billu,DC=local" | Select-Object -ExpandProperty Name

# 2. Préparation des listes pour le rapport
$success = @()
$failed = @()

Write-Host "Début du déploiement sur $($postes.Count) postes..." -ForegroundColor Cyan

# 3. Exécution avec gestion d'erreurs
foreach ($pc in $postes) {
    try {
        # Test si le PC répond au ping avant de tenter la commande
        if (Test-Connection -ComputerName $pc -Count 1 -Quiet) {
            Invoke-Command -ComputerName $pc -FilePath "\\billu.local\NETLOGON\Disable-Telemetry.ps1" -ErrorAction Stop
            $success += $pc
            Write-Host "[OK] $pc" -ForegroundColor Green
        } else {
            throw "Hors ligne (Ping échoué)"
        }
    } catch {
        $failed += [PSCustomObject]@{ Poste = $pc; Erreur = $_.Exception.Message }
        Write-Host "[ERREUR] $pc : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 4. Résumé final
Write-Host "`n--- RÉSUMÉ DU DÉPLOIEMENT ---" -ForegroundColor Yellow
Write-Host "Succès : $($success.Count)" -ForegroundColor Green
Write-Host "Échecs : $($failed.Count)" -ForegroundColor Red

# Optionnel : Exporter les échecs dans un fichier pour corriger plus tard
if ($failed.Count -gt 0) {
    $failed | Export-Csv -Path "C:\Users\Administrateur\Documents\Echecs_Telemetry.csv" -NoTypeInformation -Encoding utf8
    Write-Host "La liste des erreurs a été enregistrée dans Documents\Echecs_Telemetry.csv"
}
