#Requires -RunAsAdministrator
# Telecharger LAPS.x64.msi directement sur DC1 (necessite acces Internet)
# L URL de telechargement Microsoft change -- utiliser la page officielle
# pour recuperer l URL directe, ou utiliser winget si disponible

New-Item "C:\Temp" -ItemType Directory -Force -ErrorAction SilentlyContinue

# Via winget (Windows Package Manager -- disponible sur WS2022)
winget search LAPS

# Via Invoke-WebRequest (remplacer l URL par l URL directe du fichier MSI)
$url = "https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi"
Invoke-WebRequest -Uri $url -OutFile "C:\Temp\LAPS.x64.msi" -UseBasicParsing
Write-Host "[OK] LAPS.x64.msi telecharge"
Get-Item "C:\Temp\LAPS.x64.msi" | Select-Object Name, Length, LastWriteTime
