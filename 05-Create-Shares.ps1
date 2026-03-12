#Requires -RunAsAdministrator
# 05-Create-Shares.ps1 -- BillU Sprint 5
# Cree les 3 partages SMB sur DC1
# Les permissions NTFS (granulaires) sont deja configurees -- les permissions SMB
# sont volontairement larges (Authenticated Users Read/Write) pour laisser les NTFS
# faire le vrai filtrage. C est la bonne pratique Windows.

$ErrorActionPreference = 'Continue'

$shares = @(
    @{ Name = "Homes";        Path = "D:\Partages\Homes";        Desc = "Dossiers individuels I:"; Full = "BILLU\GG_DSI_Admins" },
    @{ Name = "Services";     Path = "D:\Partages\Services";     Desc = "Dossiers de service J:";  Full = "BILLU\GG_DSI_Admins" },
    @{ Name = "Departements"; Path = "D:\Partages\Departements"; Desc = "Dossiers de dept K:";     Full = "BILLU\GG_DSI_Admins" }
)

foreach ($s in $shares) {
    # Supprimer si existe deja (idempotent)
    Remove-SmbShare -Name $s.Name -Force -ErrorAction SilentlyContinue

    New-SmbShare -Name $s.Name -Path $s.Path -Description $s.Desc `
        -FullAccess $s.Full `
        -ChangeAccess "Authenticated Users" `
        -ReadAccess  "BUILTIN\Users" `
        -FolderEnumerationMode AccessBased | Out-Null
    # AccessBased : les users ne voient que les sous-dossiers auxquels ils ont acces

    Write-Host "[OK] \\DC1\$($s.Name)  ->  $($s.Path)"
}

Write-Host ""
Write-Host "=== Partages actifs ==="
Get-SmbShare | Where-Object { $_.Name -in @("Homes","Services","Departements") } |
    Format-Table Name, Path, Description
