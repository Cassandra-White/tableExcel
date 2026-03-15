Copy-Item ".\Map-Drives-BillU.ps1" "C:\Windows\SYSVOL\sysvol\billu.local\scripts\" -Force

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "BillU-Shortcut" -EA SilentlyContinue


$g = Get-GPO -Name "BillU-Bureau"
$guid = $g.Id.ToString("B")
$xml = "C:\Windows\SYSVOL\sysvol\billu.local\Policies\$guid\User\Preferences\Files\Files.xml"
Test-Path $xml   # doit retourner True
Get-Content $xml # doit afficher le XML avec le chemin du bat


# Vérifier où sont liées les 2 GPOs
Get-GPO -Name "BillU-Bureau"        | Select-Object DisplayName, GpoStatus
Get-GPO -Name "BillU-LecteursReseau"| Select-Object DisplayName, GpoStatus

# Voir les liens de chaque GPO
Get-GPOReport -Name "BillU-Bureau"         -ReportType Xml | Select-String "LinksTo"
Get-GPOReport -Name "BillU-LecteursReseau" -ReportType Xml | Select-String "LinksTo"







# Voir la valeur Run configurée dans BillU-LecteursReseau
Get-GPRegistryValue -Name "BillU-LecteursReseau" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
    -ValueName "BillU-MapDrives" | Select-Object Value



# Corriger avec le bon chemin (sans \scripts\)
Set-GPRegistryValue -Name "BillU-LecteursReseau" `
    -Key   "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
    -ValueName "BillU-MapDrives" `
    -Type  String `
    -Value "powershell.exe -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"\\billu.local\NETLOGON\Map-Drives-BillU.ps1`""








# Sur DC1 -- corriger le chemin dans Files.xml

$g    = Get-GPO -Name "BillU-Bureau"
$guid = $g.Id.ToString("B")
$xml  = "C:\Windows\SYSVOL\sysvol\billu.local\Policies\$guid\User\Preferences\Files\Files.xml"

# Verifier le contenu actuel
Get-Content $xml | Select-String "fromPath"



# Remplacer le chemin dans le XML
(Get-Content $xml) -replace 'fromPath="[^"]*"', 'fromPath="\\billu.local\NETLOGON\Reconnecter-Lecteurs.bat"' |
    Set-Content $xml -Encoding UTF8

# Verifier la correction
Get-Content $xml | Select-String "fromPath"

# Incrementer la version GPO pour forcer reapplication
$gptIni  = "C:\Windows\SYSVOL\sysvol\billu.local\Policies\$guid\GPT.INI"
$content = Get-Content $gptIni
$content = $content | ForEach-Object {
    if ($_ -match '^Version=(\d+)') { "Version=$([int]$matches[1] + 1)" } else { $_ }
}
$content | Set-Content $gptIni
Write-Host "GPT.INI mis a jour"
```

Puis sur le client :
```
gpupdate /force
