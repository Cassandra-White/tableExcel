# 1. Chemin du fichier CSV
$csvPath = "C:\Chemin\Vers\Ton\Fichier.csv"
$domain = "DC=entreprise,DC=local" # A ADAPTER à ton nom de domaine
$baseOU = "OU=BillU,DC=entreprise,DC=local" # A ADAPTER

# 2. Importer les données
$users = Import-Csv -Path $csvPath -Delimiter ',' -Encoding UTF8

# 3. Créer l'OU de base "BillU" si elle n'existe pas
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'BillU'")) {
    New-ADOrganizationalUnit -Name "BillU" -Path $domain
}

# 4. Boucler sur chaque ligne du CSV pour créer les OU et les Utilisateurs
foreach ($row in $users) {
    
    # Création de l'arborescence des OU (Département > Service)
    $deptOUName = $row.Departement
    $serviceOUName = $row.Service
    
    # Vérifier/Créer OU Département
    $deptOUPath = "OU=$deptOUName,$baseOU"
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$deptOUName'")) {
        New-ADOrganizationalUnit -Name $deptOUName -Path $baseOU
    }
    
    # Vérifier/Créer OU Service
    $serviceOUPath = "OU=$serviceOUName,$deptOUPath"
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$serviceOUName'")) {
        New-ADOrganizationalUnit -Name $serviceOUName -Path $deptOUPath
    }

    # Création de l'utilisateur
    $username = "$($row.Prenom).$($row.Nom)"
    $upn = "$username@entreprise.local" # A ADAPTER
    
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$username'")) {
        New-ADUser -Name "$($row.Prenom) $($row.Nom)" `
                   -GivenName $row.Prenom `
                   -Surname $row.Nom `
                   -SamAccountName $username `
                   -UserPrincipalName $upn `
                   -Path $serviceOUPath `
                   -Enabled $true `
                   -ChangePasswordAtLogon $true
        Write-Host "Utilisateur $username créé dans $serviceOUPath" -ForegroundColor Green
    }
}
