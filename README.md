# tls-peek

See the HTTPS requests (URL, headers, tokens, bodies) one Windows desktop
program sends, in a local web UI. Built on mitmproxy `local` mode (WinDivert),
so it works on programs that ignore the system proxy. Capture needs
administrator rights.

> For authorized work on systems you own or administer. Captures contain
> credentials and personal data: keep them private and delete them when done.

## Features
- **Per-program capture:** pick a running app (or type an `.exe` name); only its traffic is intercepted.
- **Live control:** switch program and host filter, pause/resume, stop, all from the UI or the tray icon.
- **Auto-stop:** closing the last UI tab stops the capture after 10 s (5 min without any tab as a fallback).
- **Request list:** pending requests, status/type/host/bookmark filters, URL or body search, sortable and resizable columns, waterfall timeline.
- **Request detail:** headers, query, pretty JSON, WebSocket messages, image and sandboxed HTML previews.
- **Decoders:** JWTs found in headers, URL or body; Base64; mitmproxy's views (protobuf, gRPC, msgpack, hex, ...).
- **Work with requests:** bookmarks and notes, edit and resend, compare two as a diff, copy as cURL/PowerShell/Python.
- **Stats:** totals, median and p95 time, status and type counts, per-host table for the requests shown.
- **Export:** HAR or Postman collection, for all, filtered or selected requests, credentials masked by default.
- **Sessions:** every capture streams to `captures\session-<time>.mitm`; open it later in the same UI.
- **CA hygiene:** fresh CA per session, untrusted and deleted on stop, on window close and at the next start.

## Setup
Nothing to install by hand. `tlspeek.cmd` installs Python 3.13 (winget, or the
python.org installer) and `mitmproxy pystray pillow` (`pip install --user`) on first run.

Or build a single `tlspeek.exe` that needs neither:
```
pip install mitmproxy pystray pillow pyinstaller
pyinstaller --onefile --name tlspeek --hidden-import pystray._win32 --add-data "ui.html;." --add-data "addon.py;." tlspeek.py
```
The exe lands in `dist\`. Put `settings.json` next to it (optional).

## Usage
Double-click `tlspeek.cmd` (or `tlspeek.exe`) and accept the UAC prompt. The UI opens in
your browser and a tray icon appears; the admin window hides behind it.

1. Click **Program** and pick the app (tick **Background** for tray apps).
2. Optionally set a host filter such as `api.example.com` and press **Apply**.
3. Close and reopen the monitored program, then do the action. WinDivert only sees new connections.
4. Press **Stop** (UI or tray), or just close the tab. The redacted HAR lands in `captures\` and the CA is removed.

Tick rows (Ctrl/Shift-click for several) to compare two or export a selection.

```
tlspeek.cmd                          menu: capture / open saved session / cleanup
tlspeek.exe [capture]                start a capture
tlspeek.exe open [FILE.mitm]         view a saved session (or drop the file on the exe)
tlspeek.exe cleanup                  untrust and delete the CA after a crash
python tlspeek.py ...                same commands without the exe
```

`settings.json`: `program`, `host_filter` (plain domain; a value with `\` is a regex),
`ui_port` (default 8081), `auto_stop_seconds` (default 300, 0 = never stop on its own),
`keep_days` (older captures are deleted, 0 = keep all).

## Verification
```
python test_tlspeek.py
```
Covers field-name matching and redacted HAR export, then runs the UI server and checks
change tracking, pending state, body search, the Host guard, live program switching,
pause, edit-and-resend against a local echo server, Stop and auto-stop, bookmarks and
notes surviving in the session file, decoders and sandboxed previews, HAR and Postman
export, and that tray polling does not keep an unattended capture alive.

## Limits
- **Certificate not accepted:** pinned hosts cannot be decrypted. Apps started before the capture may also refuse the new CA until restarted. The UI lists these hosts in one collapsible bar.
- **Auto-stop needs an open tab.** A tab the browser puts to sleep (Edge sleeping tabs) counts as closed after `auto_stop_seconds`.
- **Bodies over 5 MB** are streamed through and not stored or shown.
- **The UI keeps the last 5000 requests.** The `.mitm` file keeps all of them.
- **Redaction is by field name** (auth, token, password, key, user, code, ...). Free-text
  personal data in bodies is not masked. Check exports before you share them.
- **WebSocket flows** can be viewed but not resent.

## Layout
```
tlspeek.cmd        launcher menu
bootstrap.ps1      installs Python and the Python packages if missing, runs tlspeek.py
tlspeek.py         capture / open / cleanup, CA handling, tray icon, HAR on exit
addon.py           mitmproxy addon: UI server, flow tracking, redaction, decoders, export
ui.html            web UI
test_tlspeek.py    redaction and UI API checks
settings.json      program, host filter, UI port, auto-stop, capture retention
```
