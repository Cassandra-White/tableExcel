# Lire le MDP d un PC specifique
Import-Module AdmPwd.PS
Get-AdmPwdPassword -ComputerName "PC-ALICE-01" | Format-List

# Lister tous les PCs de OU=Ordinateurs et leurs MDP
Get-ADComputer -Filter * `
    -SearchBase "OU=Ordinateurs,OU=Paris,OU=France,OU=BillU,DC=billu,DC=local" |
    ForEach-Object {
        $r = Get-AdmPwdPassword -ComputerName $_.Name
        [PSCustomObject]@{
            PC          = $_.Name
            MotDePasse  = $r.Password
            Expiration  = $r.ExpirationTimestamp
        }
    } | Format-Table -AutoSize

# Forcer le renouvellement du MDP d un PC
Reset-AdmPwdPassword -ComputerName "PC-ALICE-01"
Write-Host "MDP reinitialise -- changement effectif au prochain redemarrage du client"
