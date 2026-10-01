@echo off
REM tls-peek: opens the start page in your browser. Installs Python and the packages on first run.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap.ps1" --own-console
