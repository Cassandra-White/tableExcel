#Requires -RunAsAdministrator
# 06-GPO-LecteursReseau.ps1 -- BillU Sprint 5
# Configure :
#   - GPO BillU-LecteursReseau  : logon script PS (mappage I J K)
#   - GPO BillU-Bureau          : copie Reconnecter-Lecteurs.bat sur le bureau (GPO Preferences)

. ".\00-Config.ps1"

$DomInfo  = Get-ADDomain -Credential $ADCredential
$dns      = $DomInfo.DNSRoot          # billu.local
$OuCible  = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$($DomInfo.DistinguishedName)"
$netlogon = "C:\Windows\SYSVOL\sysvol\$dns\scripts"
$unc      = "\\$dns\NETLOGON\scripts"

Write-Host "=== GPO Lecteurs + Bureau -- BillU Sprint 5 ==="
Write-Host ""

# ---- 1. Copier les fichiers dans NETLOGON --------------------
Write-Host "--- 1. Depot dans NETLOGON ---"
New-Item $netlogon -ItemType Directory -Force | Out-Null

foreach ($f in @("Map-Drives-BillU.ps1","Reconnecter-Lecteurs.bat")) {
    if (Test-Path ".\$f") {
        Copy-Item ".\$f" "$netlogon\$f" -Force
        Write-Host "  [OK] $f --> $netlogon"
    } else {
        Write-Host "  [ERR] $f introuvable dans le dossier courant"
    }
}
Write-Host ""

# ---- 2. GPO logon script -------------------------------------
Write-Host "--- 2. GPO BillU-LecteursReseau (logon script) ---"
$gpo1 = "BillU-LecteursReseau"

if (-not (Get-GPO -Name $gpo1 -EA SilentlyContinue)) {
    New-GPO -Name $gpo1 | Out-Null
    Write-Host "  [NEW] $gpo1 creee"
} else {
    Write-Host "  [OK]  $gpo1 existe"
}
try { New-GPLink -Name $gpo1 -Target $OuCible -EA SilentlyContinue | Out-Null } catch {}

# Cle Run : lance le script PS au logon avec ExecutionPolicy Bypass
$cmd = "powershell.exe -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$unc\Map-Drives-BillU.ps1`""
Set-GPRegistryValue -Name $gpo1 `
    -Key   "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
    -ValueName "BillU-MapDrives" `
    -Type  String `
    -Value $cmd | Out-Null
Write-Host "  [OK]  Run configure : $cmd"
Write-Host ""

# ---- 3. GPO Bureau : copie du .bat via GPO Preferences XML ---
Write-Host "--- 3. GPO BillU-Bureau (raccourci bat sur le bureau) ---"
$gpo2 = "BillU-Bureau"

if (-not (Get-GPO -Name $gpo2 -EA SilentlyContinue)) {
    New-GPO -Name $gpo2 | Out-Null
    Write-Host "  [NEW] $gpo2 creee"
} else {
    Write-Host "  [OK]  $gpo2 existe"
}
try { New-GPLink -Name $gpo2 -Target $OuCible -EA SilentlyContinue | Out-Null } catch {}

# Recuperer le GUID de la GPO pour construire le chemin SYSVOL
$gpo2Obj  = Get-GPO -Name $gpo2
$gpo2Guid = $gpo2Obj.Id.ToString("B")   # {xxxxxxxx-xxxx-...}

# Chemin du XML GPO Preferences (User > Preferences > Files)
$prefDir = "C:\Windows\SYSVOL\sysvol\$dns\Policies\$gpo2Guid\User\Preferences\Files"
New-Item $prefDir -ItemType Directory -Force | Out-Null

# XML GPO Preference : copie \\DC1\NETLOGON\scripts\Reconnecter-Lecteurs.bat
# vers %USERPROFILE%\Desktop\Reconnecter-Lecteurs.bat
# action="C" = Create (cree si absent, ne recopie pas si deja la)
# clsid et autres GUIDs sont fixes pour le type "Files" dans les GPO Preferences
$xml = @"
<?xml version="1.0" encoding="UTF-8"?>
<Files clsid="{215B2E53-57CE-475c-80FD-5ADB9B3A1834}">
  <File clsid="{50be44c8-567a-4ed1-b1d0-9234fe1f38af}"
        name="Reconnecter-Lecteurs.bat"
        status="Reconnecter-Lecteurs.bat"
        image="2"
        changed="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        uid="{$(New-Guid)}">
    <Properties action="C"
                fromPath="$unc\Reconnecter-Lecteurs.bat"
                targetPath="%USERPROFILE%\Desktop\Reconnecter-Lecteurs.bat"
                readOnly="0"
                archive="1"
                hidden="0" />
  </File>
</Files>
"@

$xmlPath = "$prefDir\Files.xml"
$xml | Set-Content $xmlPath -Encoding UTF8
Write-Host "  [OK]  GPO Preferences Files.xml cree : $xmlPath"

# Mettre a jour la version de la GPO pour forcer la reapplication
# (incrementer le numero de version dans gpt.ini)
$gptIni = "C:\Windows\SYSVOL\sysvol\$dns\Policies\$gpo2Guid\GPT.INI"
if (Test-Path $gptIni) {
    $content = Get-Content $gptIni
    $content = $content | ForEach-Object {
        if ($_ -match '^Version=(\d+)') {
            $v = [int]$matches[1] + 1
            "Version=$v"
        } else { $_ }
    }
    $content | Set-Content $gptIni
    Write-Host "  [OK]  GPT.INI version incrementee"
}
Write-Host ""

# ---- 4. Forcer gpupdate --------------------------------------
Write-Host "--- 4. Appliquer sur les clients ---"
Write-Host "   Option A -- sur chaque client manuellement :"
Write-Host "     gpupdate /force"
Write-Host "     Puis deconnecter / reconnecter l utilisateur"
Write-Host ""
Write-Host "   Option B -- depuis DC1 pour tous les PC de l OU :"
Write-Host "     Get-ADComputer -Filter * -SearchBase '$OuCible' |"
Write-Host "     ForEach-Object { Invoke-GPUpdate -Computer `$_.Name -Force -EA 0 }"
Write-Host ""
Write-Host "=== Termine -- le bat sera sur le bureau au prochain logon ==="
