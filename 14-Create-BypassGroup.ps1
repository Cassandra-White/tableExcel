#Requires -RunAsAdministrator
# 14-Create-BypassGroup.ps1 -- BillU Sprint 5
# Cree GRP-Bypass-Horaires et y ajoute les groupes d admins
# Les membres de ce groupe ne seront PAS soumis aux restrictions horaires

$ouFonct = "OU=Groupes-Fonctionnels,OU=Groupes,OU=Paris,OU=France,OU=BillU,DC=billu,DC=local"
$grpName = "GRP-Bypass-Horaires"

# Creer le groupe si absent
if (-not (Get-ADGroup -Filter "Name -eq '$grpName'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $grpName `
        -GroupScope Global `
        -GroupCategory Security `
        -Path $ouFonct `
        -Description "Membres exempts des restrictions horaires (admins)"
    Write-Host "[OK] Groupe $grpName cree dans OU=Groupes-Fonctionnels"
} else {
    Write-Host "[OK] Groupe $grpName existe deja"
}

# Ajouter les groupes d admins dans le bypass
# (GG_DSI_Admins et GG_DIRECTION_Admins n ont pas de restrictions)
$groupsToAdd = @("GG_DSI_Admins", "GG_DIRECTION_Admins")
foreach ($g in $groupsToAdd) {
    try {
        Add-ADGroupMember -Identity $grpName -Members $g -ErrorAction Stop
        Write-Host "[OK] $g --> $grpName (bypass)"
    } catch {
        Write-Host "[INFO] $g : deja membre ou groupe absent"
    }
}

# Afficher les membres du groupe bypass
Write-Host ""
Write-Host "=== Membres de $grpName ==="
Get-ADGroupMember $grpName | Format-Table Name, ObjectClass
