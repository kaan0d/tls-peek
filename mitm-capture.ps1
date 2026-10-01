# ============================================================================
#  mitm-capture.ps1
#  Captures a program's HTTPS requests (mitmproxy "local" mode, WinDivert).
#  Opens the tls-peek web UI, where you pick the program and host filter
#  (saved to settings.json). Start it from tlspeek.cmd (opens as administrator).
#
#  Each session gets a fresh CA in .\.mitmproxy. On exit (Ctrl+C) the session
#  is exported to captures\*.har (redacted), and the CA is untrusted and
#  deleted.
# ============================================================================
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$confdir = Join-Path $root ".mitmproxy"

function Find-Exe($name) {
  $p = Get-ChildItem "$env:APPDATA\Python\Python*\Scripts\$name" -ErrorAction SilentlyContinue |
       Select-Object -First 1
  if ($p) { return $p.FullName }
  $c = Get-Command $name -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  return $null
}

$settings = Get-Content (Join-Path $root "settings.json") -Raw -Encoding UTF8 | ConvertFrom-Json
$port = if ($settings.ui_port) { $settings.ui_port } else { 8081 }

# --- Admin check (REQUIRED for local mode WinDivert) ---
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) {
  Write-Host "This script requires ADMINISTRATOR. Please run via tlspeek.cmd." -ForegroundColor Yellow
  Read-Host "Press Enter to exit"; exit 1
}

$mitmdump = Find-Exe "mitmdump.exe"
if (-not $mitmdump) {
  # Skips the Microsoft Store "python" stub, which exists but cannot run code.
  $py = "py", "python" | Where-Object {
    try { (Get-Command $_ -ErrorAction Stop) -and ((& $_ -c "print(1)" 2>$null) -eq "1") } catch { $false }
  } | Select-Object -First 1
  if (-not $py) {
    Write-Host "Python not found. Install it first:  winget install Python.Python.3.13" -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
  }
  Write-Host "mitmdump not found. Installing mitmproxy (one time)..." -ForegroundColor Cyan
  & $py -m pip install --user --upgrade mitmproxy
  $scripts = & $py -c "import os, sysconfig; print(sysconfig.get_path('scripts', os.name + '_user'))"
  $mitmdump = Join-Path $scripts "mitmdump.exe"
  if (-not (Test-Path $mitmdump)) { $mitmdump = Find-Exe "mitmdump.exe" }
  if (-not $mitmdump) {
    Write-Host "Install failed. Try by hand:  $py -m pip install --user mitmproxy" -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
  }
}

# --- Fresh CA for this session: generate (no port needed) + trust ---
$empty = [IO.Path]::GetTempFileName()
& $mitmdump -q -n -r $empty --set "confdir=$confdir"
Remove-Item $empty
$cer = Join-Path $confdir "mitmproxy-ca-cert.cer"
if (-not (Test-Path $cer)) {
  Write-Host "Certificate could not be generated." -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1
}
certutil -addstore -f Root "$cer" | Out-Null

# --- Start capture ---
$captures = Join-Path $root "captures"
New-Item -ItemType Directory -Force $captures | Out-Null
$session = Join-Path $captures ("session-{0:yyyyMMdd-HHmmss}" -f (Get-Date))
$ui = "http://127.0.0.1:$port"

Write-Host ""
Write-Host "Capture running. Pick the program in the UI." -ForegroundColor Green
Write-Host "  Interface : $ui"
Write-Host "  Saving to : $session.mitm"
Write-Host "  To stop   : Ctrl+C in this window (do not just close it)"
Write-Host ""
Write-Host "Note: If nothing appears, CLOSE and reopen the monitored program, then do the action." -ForegroundColor DarkGray
try {
  & $mitmdump -q --mode "local:tlspeek-no-program.exe" --set "confdir=$confdir" `
    --save-stream-file "$session.mitm" -s (Join-Path $root "tlspeek.py") --set "ui_port=$port"
} finally {
  if ((Test-Path "$session.mitm") -and (Get-Item "$session.mitm").Length -gt 0) {
    Write-Host "Exporting redacted HAR: $session.har" -ForegroundColor Cyan
    & $mitmdump -q -n -r "$session.mitm" --set "confdir=$confdir" -s (Join-Path $root "tlspeek.py") `
      --set redact=true --set "hardump=$session.har"
    Write-Host "Reopen the full (unredacted) session later:  mitmweb -r `"$session.mitm`"" -ForegroundColor DarkGray
  }
  & (Join-Path $root "mitm-cleanup.ps1") -Quiet
}
