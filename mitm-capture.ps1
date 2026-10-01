# ============================================================================
#  mitm-capture.ps1
#  Captures a program's HTTPS requests (mitmproxy "local" mode, WinDivert).
#  Settings are read from  settings.json  in the same folder. Start it from
#  tlspeek.cmd (opens as administrator).
#
#  -Pick : choose the program from a list of running processes, save it to
#          settings.json and exit.
#
#  Each session gets a fresh CA in .\.mitmproxy. On exit (Ctrl+C) the session
#  is exported to captures\*.har (redacted), and the CA is untrusted and
#  deleted.
# ============================================================================
param([switch]$Pick)
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

# --- Read settings ---
$settingsPath = Join-Path $root "settings.json"
if (-not (Test-Path $settingsPath)) {
  Write-Host "settings.json not found: $settingsPath" -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1
}
$settings = Get-Content $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json

# --- Pick program from running processes ---
if ($Pick -or -not $settings.program) {
  $chosen = Get-Process | Where-Object { $_.MainWindowTitle -or $_.Path } |
            Sort-Object ProcessName -Unique |
            Select-Object @{n="Program";e={"$($_.ProcessName).exe"}}, @{n="Window";e={$_.MainWindowTitle}}, Path |
            Out-GridView -Title "Pick the program to monitor, then click OK" -OutputMode Single
  if (-not $chosen) { Write-Host "Nothing picked." -ForegroundColor Yellow; if ($Pick) { exit 0 } else { exit 1 } }
  $settings.program = $chosen.Program
  $settings | ConvertTo-Json | Set-Content $settingsPath -Encoding UTF8
  Write-Host "Saved program = $($chosen.Program) to settings.json" -ForegroundColor Green
  if ($Pick) { exit 0 }
}

$program = $settings.program
$port = if ($settings.ui_port) { $settings.ui_port } else { 8081 }
# Plain domain -> regex. A value that already contains "\" is used as a regex as-is.
$hostFilter = "$($settings.host_filter)".Trim()
if ($hostFilter -and $hostFilter -notmatch '\\') { $hostFilter = [regex]::Escape($hostFilter) }

# --- Admin check (REQUIRED for local mode WinDivert) ---
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) {
  Write-Host "This script requires ADMINISTRATOR. Please run via tlspeek.cmd." -ForegroundColor Yellow
  Read-Host "Press Enter to exit"; exit 1
}

$mitmweb  = Find-Exe "mitmweb.exe"
$mitmdump = Find-Exe "mitmdump.exe"
if (-not $mitmweb) {
  Write-Host "mitmweb not found. To install:  python -m pip install --user mitmproxy" -ForegroundColor Red
  Read-Host "Press Enter to exit"; exit 1
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
$session = Join-Path $captures ("{0}-{1:yyyyMMdd-HHmmss}" -f ($program -replace '\.exe$', ''), (Get-Date))

$extra = @("--web-port", "$port", "--web-host", "127.0.0.1",
           "--set", "confdir=$confdir", "--save-stream-file", "$session.mitm",
           "-s", (Join-Path $root "tlspeek.py"))
if ($hostFilter) { $extra += @("--allow-hosts", $hostFilter) }

Write-Host ""
Write-Host "Capture starting." -ForegroundColor Green
Write-Host "  Program     : $program"
Write-Host "  Host filter : $(if($hostFilter){$hostFilter}else{'(all)'})"
Write-Host "  Interface   : http://127.0.0.1:$port"
Write-Host "  Saving to   : $session.mitm"
Write-Host "  To stop     : Ctrl+C in this window (do not just close it)"
Write-Host ""
Write-Host "Note: If nothing appears, CLOSE and reopen the monitored program, then do the action." -ForegroundColor DarkGray
Write-Host ""

try {
  & $mitmweb --mode "local:$program" @extra
} finally {
  if ((Test-Path "$session.mitm") -and (Get-Item "$session.mitm").Length -gt 0) {
    Write-Host "Exporting redacted HAR: $session.har" -ForegroundColor Cyan
    & $mitmdump -q -n -r "$session.mitm" --set "confdir=$confdir" -s (Join-Path $root "tlspeek.py") `
      --set redact=true --set "hardump=$session.har"
    Write-Host "Reopen the full (unredacted) session later:  mitmweb -r `"$session.mitm`"" -ForegroundColor DarkGray
  }
  & (Join-Path $root "mitm-cleanup.ps1") -Quiet
}
