@echo off
REM tls-peek launcher (double-click). Capture and cleanup run as ADMINISTRATOR.
echo   1  Pick program to monitor
echo   2  Start capture
echo   3  Cleanup (only if the capture window was closed without Ctrl+C)
choice /c 123 /n /m "Choose 1-3: "
if errorlevel 3 (set "script=mitm-cleanup.ps1") else if errorlevel 2 (set "script=mitm-capture.ps1") else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0mitm-capture.ps1" -Pick
  pause
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','\"%~dp0%script%\"'"
