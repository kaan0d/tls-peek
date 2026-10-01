# ============================================================================
#  mitm-capture.ps1
#  Captures a program's HTTPS requests (mitmproxy "local" mode, WinDivert).
#  Settings are read from  settings.json  in the same folder -- no command line
#  needed. To change which program is monitored, just edit settings.json >
#  "program".
#
#  TO START:  double-click  START-capture.cmd  (opens as administrator).
# ============================================================================
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

function Find-Exe($name) {
  $p = Get-ChildItem "$env:APPDATA\Python\Python*\Scripts\$name" -ErrorAction SilentlyContinue |
       Select-Object -First 1
  if ($p) { return $p.FullName }
  $c = Get-Command $name -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  return $null
}

# --- Read settings ---
$settingsPath = Join-Path $root "settings.json"
if (-not (Test-Path $settingsPath)) {
  Write-Host "settings.json not found: $settingsPath" -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1
}
$settings = Get-Content $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
$program = $settings.program
$hostFilter = $settings.host_filter
$port = if ($settings.ui_port) { $settings.ui_port } else { 8081 }
if (-not $program) { Write-Host "'program' is empty in settings.json." -ForegroundColor Red; Read-Host "Enter"; exit 1 }

# --- Admin check (REQUIRED for local mode WinDivert) ---
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) {
  Write-Host "This script requires ADMINISTRATOR. Please run via START-capture.cmd." -ForegroundColor Yellow
  Read-Host "Press Enter to exit"; exit 1
}

$mitmweb  = Find-Exe "mitmweb.exe"
$mitmdump = Find-Exe "mitmdump.exe"
if (-not $mitmweb) {
  Write-Host "mitmweb not found. To install:  python -m pip install --user mitmproxy" -ForegroundColor Red
  Read-Host "Press Enter to exit"; exit 1
}

# --- If no certificate yet: generate + install to trusted root ---
$cer = Join-Path $HOME ".mitmproxy\mitmproxy-ca-cert.cer"
if (-not (Test-Path $cer)) {
  Write-Host "Generating certificate (first run)..." -ForegroundColor Cyan
  $gen = Start-Process $mitmdump -ArgumentList "-p 8080 --listen-host 127.0.0.1" -PassThru -WindowStyle Hidden
  $n = 0; while (-not (Test-Path $cer) -and $n -lt 15) { Start-Sleep 1; $n++ }
  try { $gen | Stop-Process -Force } catch {}
}
if (Test-Path $cer) {
  Write-Host "Installing certificate to trusted root..." -ForegroundColor Cyan
  certutil -addstore -f Root "$cer" | Out-Null
} else {
  Write-Host "WARNING: Certificate could not be generated. HTTPS may not be decrypted." -ForegroundColor Yellow
}

# --- Start capture ---
$extra = @("--web-port", "$port", "--web-host", "127.0.0.1")
if ($hostFilter -and $hostFilter.Trim() -ne "") { $extra += @("--allow-hosts", $hostFilter) }

Write-Host ""
Write-Host "Capture starting." -ForegroundColor Green
Write-Host "  Program     : $program"
Write-Host "  Host filter : $(if($hostFilter){$hostFilter}else{'(all)'})"
Write-Host "  Interface   : http://127.0.0.1:$port"
Write-Host "  To stop     : Ctrl+C in this window"
Write-Host ""
Write-Host "Note: If nothing appears, CLOSE and reopen the monitored program, then do the action." -ForegroundColor DarkGray
Write-Host ""

& $mitmweb --mode "local:$program" @extra
