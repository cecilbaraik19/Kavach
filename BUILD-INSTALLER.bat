@echo off
title Kavach Antivirus - Build Installer
cd /d "%~dp0"
echo.
echo  ==============================================
echo    Kavach Antivirus - build the installer
echo    Developed by Cecil Baraik
echo  ==============================================
echo.

where dotnet >nul 2>nul
if errorlevel 1 (
    echo  [X] The .NET SDK was not found. Install Visual Studio with ".NET desktop development".
    pause
    exit /b 1
)

set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"

if not defined ISCC (
    echo  [1/3] Inno Setup 6 is not installed. Installing it now with winget...
    echo        ^(Windows may ask for permission - click Yes^)
    winget install --id JRSoftware.InnoSetup -e --accept-package-agreements --accept-source-agreements
    echo.
) else (
    echo  [1/3] Inno Setup 6 found.
)

echo  [2/3] Building Kavach and creating the installer. This takes 1-3 minutes...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1"
if errorlevel 1 (
    echo.
    echo  [X] Build failed. Take a screenshot of this window and send it to Claude.
    pause
    exit /b 1
)

echo.
if exist "%~dp0installer\Output\KavachSetup-*.exe" (
    echo  [3/3] Done! Installer created:
    dir /b "%~dp0installer\Output\KavachSetup-*.exe"
    explorer "%~dp0installer\Output"
) else (
    echo  [!] Program built, but the installer was not created. Send a screenshot of this window to Claude.
)
echo.
pause
