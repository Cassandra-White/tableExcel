@echo off
title Reconnexion lecteurs BillU

:: pushd permet a CMD de travailler depuis un chemin UNC
pushd %~dp0

echo.
echo  =========================================
echo   BillU -- Reconnexion des lecteurs reseau
echo  =========================================
echo.

:: Forcer la suppression des anciens mappages (erreur 85 = deja utilise)
echo  Suppression des anciens mappages...
net use I: /delete /y >nul 2>&1
net use J: /delete /y >nul 2>&1
net use K: /delete /y >nul 2>&1

:: Attendre 1 seconde que Windows libere les lettres
timeout /t 1 /nobreak >nul

echo  Remappage en cours...
echo.

:: Lancer le script PS depuis NETLOGON
powershell.exe -ExecutionPolicy Bypass -WindowStyle Normal -File "\\DC1\NETLOGON\scripts\Map-Drives-BillU.ps1"

echo.
echo  =========================================
echo   Verification :
echo  =========================================
if exist I:\ (echo   [OK]  I: - Dossier personnel) else (echo   [!!!] I: non connecte)
if exist J:\ (echo   [OK]  J: - Dossier de service) else (echo   [!!!] J: non connecte)
if exist K:\ (echo   [OK]  K: - Dossier de departement) else (echo   [!!!] K: non connecte)
echo.

popd
pause
