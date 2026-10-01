# ============================================================================
#  bootstrap.ps1
#  Makes sure Python and mitmproxy are installed (installs them on first run),
#  then runs tlspeek.py with the given arguments (capture / open / cleanup).
#  Called by tlspeek.cmd. Does not need administrator rights.
# ============================================================================
param([Parameter(ValueFromRemainingArguments)] $rest)
$ErrorActionPreference = "Stop"

# Skips the Microsoft Store "python" stub, which exists but cannot run code.
function Find-Python {
  "py", "python" | Where-Object {
    try { (Get-Command $_ -ErrorAction Stop) -and ((& $_ -c "print(1)" 2>$null) -eq "1") } catch { $false }
  } | Select-Object -First 1
}

function Stop-WithError($msg) {
  Write-Host $msg -ForegroundColor Red
  Read-Host "Press Enter to exit"; exit 1
}

$py = Find-Python
if (-not $py) {
  Write-Host "Python not found. Installing Python 3.13 for this user (one time)..." -ForegroundColor Cyan
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install -e --id Python.Python.3.13 --scope user --silent `
      --accept-package-agreements --accept-source-agreements
  } else {
    # ponytail: fixed version and x64 build (runs on ARM64 too); bump the version when it ages
    $installer = Join-Path $env:TEMP "python-3.13.15-amd64.exe"
    Invoke-WebRequest "https://www.python.org/ftp/python/3.13.15/python-3.13.15-amd64.exe" -OutFile $installer -UseBasicParsing
    Start-Process $installer -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_launcher=1" -Wait
    Remove-Item $installer
  }
  # The installer changed PATH in the registry; this window still has the old one.
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
  $py = Find-Python
  if (-not $py) { Stop-WithError "Python install failed. Install it by hand from https://www.python.org/downloads/" }
}

$hasMitm = try { & $py -c "import mitmproxy" 2>$null; $LASTEXITCODE -eq 0 } catch { $false }
if (-not $hasMitm) {
  Write-Host "Installing mitmproxy (one time)..." -ForegroundColor Cyan
  & $py -m pip install --user --upgrade mitmproxy
  if ($LASTEXITCODE -ne 0) { Stop-WithError "mitmproxy install failed. Try by hand:  $py -m pip install --user mitmproxy" }
}

& $py (Join-Path $PSScriptRoot "tlspeek.py") @rest
if ($LASTEXITCODE -ne 0) { Read-Host "Press Enter to exit" }
