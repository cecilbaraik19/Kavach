@echo off
title Kavach - commit and push to GitHub
cd /d "%~dp0"

rem Find git.exe (on PATH, Git for Windows, or the copy inside Visual Studio)
set "GIT=git"
where git >nul 2>nul && goto :havegit
for %%P in ("%ProgramFiles%\Git\cmd\git.exe" "%ProgramFiles(x86)%\Git\cmd\git.exe") do if exist %%P (set "GIT=%%~P" & goto :havegit)
for /d %%V in ("%ProgramFiles%\Microsoft Visual Studio\*") do for /d %%E in ("%%V\*") do if exist "%%E\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd\git.exe" (set "GIT=%%E\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd\git.exe" & goto :havegit)
echo [X] Could not find git.exe. Send a screenshot of this window to Claude.
pause
exit /b 1

:havegit
for /f "tokens=3 delims=<>" %%V in ('findstr /c:"<Version>" Directory.Build.props') do set "VERSION=%%V"
echo Using: %GIT%
echo Kavach version %VERSION%
echo.
echo [1/3] Getting the latest state from GitHub...
"%GIT%" fetch origin || goto :fail
"%GIT%" status --short
echo.
echo [2/3] Saving all changes as a NEW commit (never "amend")...
"%GIT%" add --renormalize . || goto :fail
"%GIT%" add -A || goto :fail
"%GIT%" diff --cached --quiet && echo Nothing new to commit. && goto :push
if exist commit-message.txt ("%GIT%" commit -F commit-message.txt || goto :fail) else ("%GIT%" commit -m "Kavach v%VERSION%" || goto :fail)
del commit-message.txt 2>nul

:push
echo [3/3] Uploading to GitHub...
"%GIT%" push origin master || goto :fail
echo.
"%GIT%" log --oneline -3
echo.
echo  [OK] Done! Your changes are on GitHub.
pause
exit /b 0

:fail
echo.
echo  [X] Something went wrong. Take a screenshot of this window and send it to Claude.
pause
exit /b 1
