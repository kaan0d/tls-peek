@echo off
REM Starts the mitmproxy capture as ADMINISTRATOR (double-click).
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','\"%~dp0mitm-capture.ps1\"'"
