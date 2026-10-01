@echo off
REM tls-peek launcher (double-click). Installs Python and mitmproxy on first run.
echo   1  Start capture (asks for admin, opens the UI in your browser)
echo   2  Open a saved session
echo   3  Cleanup (only after a crash)
choice /c 123 /n /m "Choose 1-3: "
if errorlevel 3 (set "action=cleanup") else if errorlevel 2 (set "action=open") else (set "action=capture")
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap.ps1" %action% --own-console
