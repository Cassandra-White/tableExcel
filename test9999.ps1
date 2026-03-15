Copy-Item ".\Map-Drives-BillU.ps1" "C:\Windows\SYSVOL\sysvol\billu.local\scripts\" -Force

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "BillU-Shortcut" -EA SilentlyContinue
