# Creer le sous-dossier LAPS dans NETLOGON
$nlLAPS = "C:\Windows\SYSVOL\sysvol\billu.local\scripts\LAPS"
New-Item $nlLAPS -ItemType Directory -Force | Out-Null

# Copier le MSI
Copy-Item "C:\Temp\LAPS.x64.msi" "$nlLAPS\LAPS.x64.msi" -Force
Write-Host "[OK] MSI copie dans \\DC1\NETLOGON\LAPS\"

# Copier aussi les templates ADMX dans le Central Store (pour GPMC)
$centralStore = "C:\Windows\SYSVOL\sysvol\billu.local\Policies\PolicyDefinitions"
New-Item "$centralStore\fr-FR" -ItemType Directory -Force | Out-Null
Copy-Item "C:\Windows\PolicyDefinitions\AdmPwd.admx"          "$centralStore\" -Force
Copy-Item "C:\Windows\PolicyDefinitions\fr-FR\AdmPwd.adml"    "$centralStore\fr-FR\" -Force
Write-Host "[OK] Templates ADMX LAPS dans le Central Store GPMC"
