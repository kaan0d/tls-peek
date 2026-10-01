@echo off
REM Runs the cleanup as ADMINISTRATOR (double-click).
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','\"%~dp0mitm-cleanup.ps1\"'"
