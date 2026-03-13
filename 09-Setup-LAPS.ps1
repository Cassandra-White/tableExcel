#Requires -RunAsAdministrator
# IMPORTANT : etre membre du groupe "Schema Admins" pour etendre le schema
# Administrateur du domaine l est par defaut

Import-Module AdmPwd.PS -ErrorAction Stop

$ouPC = "OU=Ordinateurs,OU=Paris,OU=France,OU=BillU,DC=billu,DC=local"

# Etape 1 : Etendre le schema AD (ajouter les 2 attributs LAPS)
# A faire UNE SEULE FOIS -- inoffensif de le relancer
Write-Host "Extension du schema AD..."
Update-AdmPwdADSchema
Write-Host "[OK] Schema etendu (attributs ms-Mcs-AdmPwd ajoutes)"

# Etape 2 : Les PC doivent pouvoir ecrire leur propre MDP dans l AD
# (chaque PC met a jour son mot de passe en ecrivant dans l attribut qui le concerne)
Write-Host "Permission self-write sur OU=Ordinateurs..."
Set-AdmPwdComputerSelfPermission -Identity $ouPC
Write-Host "[OK] Les PC peuvent ecrire leur MDP dans l AD"

# Etape 3 : Seul GG_DSI_Admins peut LIRE les mots de passe
Write-Host "Permission de lecture : GG_DSI_Admins..."
Set-AdmPwdReadPasswordPermission -Identity $ouPC -AllowedPrincipals "GG_DSI_Admins"
Write-Host "[OK] Lecture des MDP reservee a GG_DSI_Admins"

# Verifier les permissions
Find-AdmPwdExtendedRights -Identity $ouPC | Format-Table ExtendedRightHolder, Task
