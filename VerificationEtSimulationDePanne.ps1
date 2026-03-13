# Simuler la panne d un disque (le mettre en etat "Retired")
$pd = Get-PhysicalDisk | Where-Object { $_.CanPool -eq $false } | Select-Object -First 1
Write-Host "Simulation panne sur : $($pd.FriendlyName)"
Set-PhysicalDisk -UniqueId $pd.UniqueId -Usage Retired

# D: reste accessible malgre la "panne" -- verifier
Get-VirtualDisk "Data-Mirror"  # HealthStatus = Warning (un seul disque)
dir D:\                         # doit fonctionner normalement
Write-Host "D: toujours accessible malgre la panne -- RAID 1 fonctionne !"

# Reconnecter le disque (simuler le remplacement)
# Dans Proxmox : pas besoin de rien changer, on remet juste le disque en "Auto"
Set-PhysicalDisk -UniqueId $pd.UniqueId -Usage AutoSelect

# Suivre la reconstruction (dure quelques secondes en lab)
Get-StorageJob
Start-Sleep 10
Get-VirtualDisk "Data-Mirror"   # HealthStatus = Healthy apres reconstruction
