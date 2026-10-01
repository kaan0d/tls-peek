# tls-peek

See the HTTPS requests (URL, headers, tokens, bodies) one Windows desktop
program sends, in a local web UI. Built on mitmproxy `local` mode (WinDivert),
so it works on programs that ignore the system proxy. Capture needs
administrator rights.

> For authorized work on systems you own or administer. Captures contain
> credentials and personal data: keep them private and delete them when done.

## Features
- **Per-program capture:** pick a running app (or type an `.exe` name); only its traffic is intercepted.
- **Live switching:** program and host filter change without a restart and are saved to `settings.json`.
- **Pause/Resume:** while paused, new connections pass through untouched and nothing is recorded.
- **Request view:** pending requests, status/type/host filters, search in URLs or bodies, pretty JSON.
- **WebSocket:** sent and received messages per connection.
- **Edit and resend:** change method, URL, headers or body and send again; the result shows as a new row.
- **Copy as:** URL, cURL, PowerShell or Python `requests`.
- **Sessions:** every capture streams to `captures\session-<time>.mitm`; open it later in the same UI.
- **Redacted HAR:** from the UI or on exit; credential headers, query, form and JSON fields are masked.
- **CA hygiene:** fresh CA per session, untrusted and deleted on Ctrl+C, on window close and at the next start.

## Setup
Nothing to install by hand. `tlspeek.cmd` installs Python 3.13 (winget, or the
python.org installer) and mitmproxy (`pip install --user`) on first run.

Or build a single `tlspeek.exe` that needs neither:
```
pip install mitmproxy pyinstaller
pyinstaller --onefile --name tlspeek --add-data "ui.html;." --add-data "addon.py;." tlspeek.py
```
The exe lands in `dist\`. Put `settings.json` next to it (optional).

## Usage
Double-click `tlspeek.cmd` (or `tlspeek.exe`) and accept the UAC prompt. The UI opens in your browser.

1. Click **Program** and pick the app (tick **Background** for tray apps).
2. Optionally set a host filter such as `api.example.com` and press **Apply**.
3. Close and reopen the monitored program, then do the action. WinDivert only sees new connections.
4. Press **Ctrl+C** in the capture window to stop. It writes `captures\*.har` (redacted) and removes the CA.

```
tlspeek.cmd                          menu: capture / open saved session / cleanup
tlspeek.exe [capture]                start a capture
tlspeek.exe open [FILE.mitm]         view a saved session (or drop the file on the exe)
tlspeek.exe cleanup                  untrust and delete the CA after a crash
python tlspeek.py ...                same commands without the exe
```

`settings.json`: `program`, `host_filter` (plain domain; a value with `\` is a
regex), `ui_port` (default 8081), `keep_days` (old captures are deleted, 0 = keep all).

## Verification
```
python test_tlspeek.py
```
Checks field-name matching, that the redacted HAR has no secrets, and the UI
server: change tracking, pending state, body search, Host guard, live program
switching and edit-and-resend against a local echo server.

## Limits
- **Certificate not accepted:** pinned hosts cannot be decrypted. Apps started before the capture may also refuse the new CA until restarted. The UI lists these hosts in one collapsible bar.
- **Bodies over 5 MB** are streamed through and not stored or shown.
- **The UI keeps the last 5000 requests.** The `.mitm` file keeps all of them.
- **Redaction is by field name** (auth, token, password, key, user, code, ...). Free-text
  personal data in bodies is not masked. Check the HAR before you share it.
- **WebSocket flows** can be viewed but not resent.

## Layout
```
tlspeek.cmd        launcher menu
bootstrap.ps1      installs Python and mitmproxy if missing, runs tlspeek.py
tlspeek.py         capture / open / cleanup, CA handling, HAR export
addon.py           mitmproxy addon: UI server, flow tracking, redaction, resend
ui.html            web UI
test_tlspeek.py    redaction and UI API check
settings.json      program, host filter, UI port, capture retention
```
