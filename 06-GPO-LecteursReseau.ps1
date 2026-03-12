#Requires -RunAsAdministrator
$gpoName = "BillU-LecteursReseau"
$target  = "OU=Paris,OU=France,OU=BillU,DC=billu,DC=local"
$nl      = "C:\Windows\SYSVOL\sysvol\billu.local\scripts"
$script  = "Map-Drives-BillU.ps1"

New-Item $nl -ItemType Directory -Force -EA SilentlyContinue | Out-Null
Copy-Item ".\$script" "$nl\$script" -Force

# Creer et lier la GPO
if (-not (Get-GPO -Name $gpoName -EA SilentlyContinue)) {
    New-GPO -Name $gpoName -Comment "Mappage I: J: K: sur DC1" | Out-Null
}
try { New-GPLink -Name $gpoName -Target $target | Out-Null } catch {}

# Configurer le script de logon
$gpoId  = (Get-GPO -Name $gpoName).Id.ToString()
$logDir = "C:\Windows\SYSVOL\sysvol\billu.local\Policies\{$gpoId}\User\Scripts\Logon"
New-Item $logDir -ItemType Directory -Force | Out-Null
Copy-Item "$nl\$script" "$logDir\$script" -Force

Set-Content "$logDir\scripts.ini" @"
[Logon]
0CmdLine=PowerShell.exe
0Parameters=-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File "$script"
"@ -Encoding Unicode

Write-Host "[OK] GPO $gpoName creee -- client : gpupdate /force"
