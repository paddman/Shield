@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0CONNECTION.txt" (
  start "" notepad.exe "%~dp0CONNECTION.txt"
  exit /b 0
)
if exist "%ProgramData%\NTShield\Server\CONNECTION.txt" (
  start "" notepad.exe "%ProgramData%\NTShield\Server\CONNECTION.txt"
  exit /b 0
)
echo CONNECTION.txt not found. Central may not have finished registering.
echo Install folder: %~dp0
echo.
echo Try: Start-Service NTShieldCentral
pause
