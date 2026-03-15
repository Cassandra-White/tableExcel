@echo off
title Reconnexion des lecteurs reseau BillU
echo.
echo  =========================================
echo   BillU -- Reconnexion des lecteurs reseau
echo  =========================================
echo.
echo  Patientez...
echo.

powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "\\DC1\NETLOGON\scripts\Map-Drives-BillU.ps1"

echo.
echo  Verification :
echo.
if exist I:\ (echo   [OK]  I: - Dossier personnel) else (echo   [!!!] I: non connecte)
if exist J:\ (echo   [OK]  J: - Dossier de service) else (echo   [!!!] J: non connecte)
if exist K:\ (echo   [OK]  K: - Dossier de departement) else (echo   [!!!] K: non connecte)
echo.
echo  Appuyez sur une touche pour fermer...
pause > nul
