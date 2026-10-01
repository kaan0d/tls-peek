@echo off
REM tls-peek launcher (double-click). Runs as ADMINISTRATOR.
echo   1  Start capture (opens the UI in your browser)
echo   2  Cleanup (only if the capture window was closed without Ctrl+C)
choice /c 12 /n /m "Choose 1-2: "
if errorlevel 2 (set "script=mitm-cleanup.ps1") else (set "script=mitm-capture.ps1")
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','\"%~dp0%script%\"'"
