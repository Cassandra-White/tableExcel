# Récupère tous les postes Windows de l'OU Postes
$postes = Get-ADComputer -Filter * `
    -SearchBase "DC=billu,DC=local" |
    Select-Object -ExpandProperty Name

# Exécute le script sur chacun en parallèle
Invoke-Command -ComputerName $postes `
    -FilePath "\\billu.local\NETLOGON\scripts\Disable-Telemetry.ps1" `
    -ThrottleLimit 10   # Max 10 connexions simultanées

Write-Host "Script déployé sur $($postes.Count) postes" -ForegroundColor Green
