@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
title Codex Account Tool

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell.exe"

"%PS_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" -Foreground
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
  echo.
  echo Startup failed. Exit code: %EXIT_CODE%
  pause
)
endlocal & exit /b %EXIT_CODE%
