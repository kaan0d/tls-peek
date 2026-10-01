# ============================================================================
#  mitm-cleanup.ps1
#  Cleanup for security/hygiene when done:
#   - removes the mitmproxy certificate from trusted roots
#   - turns off the system proxy setting (if any)
#  Run via START-cleanup.cmd (as administrator).
# ============================================================================
Write-Host "Removing mitmproxy certificate from trusted roots..." -ForegroundColor Cyan
try { certutil -delstore Root mitmproxy | Out-Null; Write-Host "  -> removed (if present)." } catch { Write-Host "  -> not found / already gone." }

Write-Host "Turning off system proxy setting (to be safe)..." -ForegroundColor Cyan
$k = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
try { Set-ItemProperty $k ProxyEnable 0 -ErrorAction Stop; Write-Host "  -> ProxyEnable=0" } catch {}

Write-Host "`nCleanup done." -ForegroundColor Green
Read-Host "Press Enter to close"
