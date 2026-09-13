@echo off
setlocal
cd /d "%~dp0"

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell.exe"

"%PS_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
set "exitCode=%ERRORLEVEL%"
echo.
if not "%exitCode%"=="0" echo START FAILED. Exit code: %exitCode%
if "%exitCode%"=="0" echo SERVICE STARTED OR ALREADY RUNNING.
echo.
pause
endlocal & exit /b %exitCode%
