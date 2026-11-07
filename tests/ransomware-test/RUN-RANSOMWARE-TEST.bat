@echo off
title Kavach ransomware test
echo This is a SAFE fake-ransomware test for Kavach.
echo It writes junk into Documents\Kavach-Ransom-Test and touches Kavach's bait file.
echo.
copy /y "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" "%TEMP%\KavachRansomTest.exe" >nul
"%TEMP%\KavachRansomTest.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0ransom-sim.ps1"
echo.
echo The test program has ended. Check Kavach for the alert.
pause
