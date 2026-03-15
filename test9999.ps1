Copy-Item ".\Map-Drives-BillU.ps1" "C:\Windows\SYSVOL\sysvol\billu.local\scripts\" -Force

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "BillU-Shortcut" -EA SilentlyContinue


$g = Get-GPO -Name "BillU-Bureau"
$guid = $g.Id.ToString("B")
$xml = "C:\Windows\SYSVOL\sysvol\billu.local\Policies\$guid\User\Preferences\Files\Files.xml"
Test-Path $xml   # doit retourner True
Get-Content $xml # doit afficher le XML avec le chemin du bat
