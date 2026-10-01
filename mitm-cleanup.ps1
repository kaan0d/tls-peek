# ============================================================================
#  mitm-cleanup.ps1
#  Cleanup for security/hygiene when done:
#   - stops a leftover mitmweb/mitmdump
#   - removes the mitmproxy certificate from trusted roots
#   - deletes this folder's CA private key (.mitmproxy)
#  mitm-capture.ps1 runs this itself on exit. Run it by hand (tlspeek.cmd >
#  Cleanup) only if the capture window was closed or killed.
# ============================================================================
param([switch]$Quiet)

Get-Process mitmweb, mitmdump -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "Removing mitmproxy certificate from trusted roots..." -ForegroundColor Cyan
$n = 0
while ($n -lt 10) { certutil -delstore Root mitmproxy | Out-Null; if ($LASTEXITCODE -ne 0) { break }; $n++ }
Write-Host "  -> removed $n certificate(s)."

$confdir = Join-Path $PSScriptRoot ".mitmproxy"
if (Test-Path $confdir) {
  Remove-Item $confdir -Recurse -Force
  Write-Host "  -> deleted CA key folder $confdir"
}

Write-Host "Cleanup done." -ForegroundColor Green
if (-not $Quiet) { Read-Host "Press Enter to close" }
