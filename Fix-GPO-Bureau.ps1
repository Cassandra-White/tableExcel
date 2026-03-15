#Requires -RunAsAdministrator
# Fix-GPO-Bureau.ps1 -- supprime l ancienne cle Run BillU-Shortcut
# et deploie le bat sur le bureau via GPO Preferences

. ".\00-Config.ps1"

$DomInfo  = Get-ADDomain -Credential $ADCredential
$dns      = $DomInfo.DNSRoot
$OuCible  = "OU=$SiteOU,OU=$CountryOU,OU=$RootOU,$($DomInfo.DistinguishedName)"
$netlogon = "C:\Windows\SYSVOL\sysvol\$dns\scripts"
$unc      = "\\$dns\NETLOGON\scripts"

Write-Host "=== Fix GPO Bureau -- billu.local ==="
Write-Host ""

# ---- 1. Supprimer l ancienne cle Run BillU-Shortcut ----------
Write-Host "--- 1. Suppression ancienne cle BillU-Shortcut ---"
$gpo2 = "BillU-Bureau"

if (Get-GPO -Name $gpo2 -EA SilentlyContinue) {
    try {
        Remove-GPRegistryValue -Name $gpo2 `
            -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
            -ValueName "BillU-Shortcut" -EA Stop
        Write-Host "  [OK] Cle BillU-Shortcut supprimee de $gpo2"
    } catch {
        Write-Host "  [INFO] Cle BillU-Shortcut deja absente ou deja supprimee"
    }
} else {
    New-GPO -Name $gpo2 | Out-Null
    Write-Host "  [NEW] GPO $gpo2 creee"
}
try { New-GPLink -Name $gpo2 -Target $OuCible -EA SilentlyContinue | Out-Null } catch {}
Write-Host ""

# ---- 2. Copier le bat dans NETLOGON --------------------------
Write-Host "--- 2. Depot Reconnecter-Lecteurs.bat dans NETLOGON ---"
if (Test-Path ".\Reconnecter-Lecteurs.bat") {
    Copy-Item ".\Reconnecter-Lecteurs.bat" "$netlogon\Reconnecter-Lecteurs.bat" -Force
    Write-Host "  [OK] Copie --> $netlogon\Reconnecter-Lecteurs.bat"
} else {
    Write-Host "  [ERR] Reconnecter-Lecteurs.bat introuvable dans le dossier courant"
    Write-Host "        Placer le fichier bat dans le meme dossier que ce script"
    exit 1
}
Write-Host ""

# ---- 3. GPO Preferences : copier le bat sur le bureau --------
Write-Host "--- 3. GPO Preferences Files -- copie sur bureau ---"

$gpo2Obj  = Get-GPO -Name $gpo2
$gpo2Guid = $gpo2Obj.Id.ToString("B")
$prefDir  = "C:\Windows\SYSVOL\sysvol\$dns\Policies\$gpo2Guid\User\Preferences\Files"
New-Item $prefDir -ItemType Directory -Force | Out-Null

$uid = [System.Guid]::NewGuid().ToString("B").ToUpper()
$now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$xml = @"
<?xml version="1.0" encoding="UTF-8"?>
<Files clsid="{215B2E53-57CE-475c-80FD-5ADB9B3A1834}">
  <File clsid="{50be44c8-567a-4ed1-b1d0-9234fe1f38af}"
        name="Reconnecter-Lecteurs.bat"
        status="Reconnecter-Lecteurs.bat"
        image="2"
        changed="$now"
        uid="$uid">
    <Properties action="C"
                fromPath="$unc\Reconnecter-Lecteurs.bat"
                targetPath="%USERPROFILE%\Desktop\Reconnecter-Lecteurs.bat"
                readOnly="0"
                archive="1"
                hidden="0" />
  </File>
</Files>
"@

$xml | Set-Content "$prefDir\Files.xml" -Encoding UTF8
Write-Host "  [OK] Files.xml cree : $prefDir\Files.xml"

# Incrementer la version GPO pour forcer reapplication
$gptIni = "C:\Windows\SYSVOL\sysvol\$dns\Policies\$gpo2Guid\GPT.INI"
if (Test-Path $gptIni) {
    $lines   = Get-Content $gptIni
    $newLines = $lines | ForEach-Object {
        if ($_ -match '^Version=(\d+)') { "Version=$([int]$matches[1] + 1)" }
        else { $_ }
    }
    $newLines | Set-Content $gptIni
    Write-Host "  [OK] GPT.INI version incrementee"
}
Write-Host ""

# ---- 4. Appliquer sur les clients ----------------------------
Write-Host "--- 4. Application ---"
Write-Host "  Sur le client : gpupdate /force"
Write-Host "  Puis deconnecter / reconnecter l utilisateur"
Write-Host "  Le bat apparaitra sur le bureau au prochain logon"
Write-Host ""
Write-Host "=== Fix termine ==="
