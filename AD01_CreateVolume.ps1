01-Init-Disques.ps1 -- Storage Spaces + volume D: -- DC1
PS Admin -- DC1
#Requires -RunAsAdministrator
# 01-Init-Disques.ps1 -- BillU Sprint 5
# Cree un pool Storage Spaces sur sdb + sdc et monte le volume D:
# Les 2 disques doivent etre vierges (non initialises)

$ErrorActionPreference = 'Stop'

# Lister les disques bruts disponibles (RAW = non initialises)
$disques = Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' }
Write-Host "Disques bruts detectes : $($disques.Count)"
$disques | Select-Object Number, Size, FriendlyName | Format-Table

if ($disques.Count -lt 2) {
    Write-Error "Il faut au moins 2 disques bruts (ajouter sdb et sdc dans Proxmox)"
    exit 1
}

# Creer le pool Storage Spaces
$subsystem = Get-StorageSubSystem -FriendlyName "*Windows*"
$pool = New-StoragePool `
    -FriendlyName "BillU-Data" `
    -StorageSubSystemFriendlyName $subsystem.FriendlyName `
    -PhysicalDisks $disques

Write-Host "[OK] Pool 'BillU-Data' cree : $([math]::Round($pool.Size/1GB, 0)) GB"

# Creer le disque virtuel en miroir (RAID 1)
# -ResiliencySettingName Mirror : copie sur les 2 disques physiques
# -ProvisioningType Fixed       : espace alloue immediatement
$vdisk = New-VirtualDisk `
    -StoragePoolFriendlyName "BillU-Data" `
    -FriendlyName "Data-Mirror" `
    -UseMaximumSize `
    -ResiliencySettingName "Mirror" `
    -ProvisioningType Fixed

Write-Host "[OK] Disque virtuel 'Data-Mirror' cree (RAID 1 miroir)"

# Initialiser, partitionner et formater en D:
$disk = Get-VirtualDisk -FriendlyName "Data-Mirror" | Get-Disk
Initialize-Disk -Number $disk.Number -PartitionStyle GPT
$part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter D
Format-Volume -DriveLetter D -FileSystem NTFS `
    -NewFileSystemLabel "BillU-Data" -Confirm:$false

Write-Host "[OK] Volume D: monte -- $(Get-Volume -DriveLetter D | Select-Object -ExpandProperty SizeRemaining | ForEach-Object {[math]::Round($_/1GB,0)}) GB disponibles"

# Verifier
Get-StoragePool -FriendlyName "BillU-Data" | Format-List FriendlyName, HealthStatus, Size
Get-VirtualDisk | Format-Table FriendlyName, ResiliencySettingName, OperationalStatus
Get-Volume -DriveLetter D | Format-Table DriveLetter, FileSystem, SizeRemaining, HealthStatus
