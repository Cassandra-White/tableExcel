# Etat du pool et du disque virtuel
Get-StoragePool -FriendlyName "BillU-Data" |
    Format-List FriendlyName, HealthStatus, OperationalStatus, Size

Get-VirtualDisk -FriendlyName "Data-Mirror" |
    Format-List FriendlyName, ResiliencySettingName, HealthStatus, OperationalStatus

Get-PhysicalDisk | Where-Object { $_.CanPool -eq $false } |
    Format-Table FriendlyName, HealthStatus, OperationalStatus, Size

# Etat du volume D:
Get-Volume -DriveLetter D | Format-Table DriveLetter, HealthStatus, FileSystem, SizeRemaining

# ---- Simulation de panne ----
# Retirer un disque physique du pool (test)
# ATTENTION : a executer en lab uniquement
$pd = Get-PhysicalDisk | Where-Object { $_.CanPool -eq $false } | Select-Object -First 1
Set-PhysicalDisk -UniqueId $pd.UniqueId -Usage Retired

# D: reste accessible malgre la "panne"
Get-VirtualDisk -FriendlyName "Data-Mirror"    # HealthStatus = Warning (un seul disque)
dir D:\Partages                                 # Doit fonctionner

# ---- Reconstruction apres remplacement ----
# Apres avoir ajoute le nouveau disque dans Proxmox et redemarrage DC1
$newDisk = Get-PhysicalDisk | Where-Object { $_.CanPool -eq $true } | Select-Object -First 1
Add-PhysicalDisk -StoragePoolFriendlyName "BillU-Data" -PhysicalDisks $newDisk
# La reconstruction demarre automatiquement
Get-StorageJob   # Suivre la reconstruction
