# tls-peek

See the HTTPS requests (URL, headers, tokens, bodies) one Windows desktop
program sends, in a local web UI. Built on mitmproxy `local` mode (WinDivert),
so it works on programs that ignore the system proxy. Capture needs
administrator rights.

> For authorized work on systems you own or administer. Captures contain
> credentials and personal data: keep them private and delete them when done.

## Features
- **Start page:** start a capture, open, download or delete saved sessions, and remove a leftover certificate.
- **Per-program capture:** pick a running app (or type an `.exe` name); only its traffic is intercepted.
- **Live control:** switch program and host filter, pause/resume, stop, all from the UI or the tray icon.
- **Auto-stop:** closing the last UI tab stops the capture after 10 s (5 min without any tab as a fallback).
- **Request list:** pending requests, status/type/host/bookmark filters, URL or body search, sortable and resizable columns, waterfall timeline.
- **Request detail:** headers, query, pretty JSON, WebSocket messages, image and sandboxed HTML previews.
- **Decoders:** JWTs found in headers, URL or body; Base64; mitmproxy's views (protobuf, gRPC, msgpack, hex, ...).
- **Intercept:** hold requests and/or responses matching a URL and method, edit them, then continue or drop; the program gets the edited version. Clicking Intercept again turns it off and sends held traffic on unchanged.
- **Rewrite rules:** set or remove a header, find and replace in URL or body, or answer with a fixed response, automatically and without holding. **New rule…** on a request starts one for its URL with the captured response. Rules are saved for the next capture.
- **Work with requests:** bookmarks and notes, edit and resend, compare two as a diff, copy as cURL/PowerShell/Python.
- **Stats:** totals, median and p95 time, status and type counts, per-host table for the requests shown.
- **Export:** HAR or Postman collection, for all, filtered or selected requests, credentials masked by default.
- **Sessions:** every capture streams to `captures\session-<time>.mitm`; open it later in the same UI.
- **CA hygiene:** fresh CA per session, untrusted and deleted on stop, on window close and at the next start.

## Setup
Download `tlspeek.exe` from [Releases](https://github.com/kaan0d/tls-peek/releases/latest) and run it: no Python needed.

From source: `tlspeek.cmd` installs Python 3.13 (winget, or the
python.org installer) and `mitmproxy pystray pillow` (`pip install --user`) on first run.

Or build the exe yourself:
```
pip install mitmproxy pystray pillow pyinstaller
pyinstaller --onefile --name tlspeek --icon app/icon.ico --hidden-import pystray._win32 --add-data "ui;ui" --add-data "app/addon.py;." app/tlspeek.py
```
The exe lands in `dist\`.

## Usage
Double-click `tlspeek.cmd` (or `tlspeek.exe`). The start page opens in your browser.

1. Click **Start capture** and accept the UAC prompt. A tray icon appears.
2. The UI asks which program to capture: pick it from the list (tick **Background** for tray apps) or press **Use again** for the last one. **Program** switches later.
3. Optionally set a host filter such as `api.example.com` and press **Apply**.
4. Close and reopen the monitored program, then do the action. WinDivert only sees new connections.
5. Press **Stop** (UI or tray). The redacted HAR lands in `captures\`, the CA is removed and the tab returns to the start page.

Closing the start page with nothing running ends tls-peek.

Tick rows (Ctrl/Shift-click for several) to compare two or export a selection.

```
tlspeek.cmd  /  tlspeek.exe          start page
tlspeek.exe capture                  start a capture right away
tlspeek.exe open [FILE.mitm]         view a saved session (or drop the file on the exe)
tlspeek.exe cleanup                  untrust and delete the CA after a crash
python app\tlspeek.py ...            same commands without the exe
```

`settings.json` (created next to `tlspeek.cmd` or the exe, not in git): `program` (last used), `host_filter` (plain domain; a value with `\` is a regex),
`ui_port` (default 8081), `auto_stop_seconds` (default 300, 0 = never stop on its own),
`keep_days` (older captures are deleted, 0 = keep all).

## Verification
```
python app\test_tlspeek.py
```
Covers field-name matching and redacted HAR export, then runs the UI server and checks
change tracking, pending state, body search, the Host guard, live program switching,
pause, edit-and-resend against a local echo server, Stop and auto-stop, bookmarks and
notes surviving in the session file, decoders and sandboxed previews, HAR and Postman
export, that tray polling does not keep an unattended capture alive, that a capture stops
with its starter, the start page (sessions, path checks, open and close, exit), and intercept
on real proxied calls: the caller waits, gets an edited request and a faked response, drops, and release-all,
and rewrite rules (replace, header, fixed response) on the same calls.

## Limits
- **Certificate not accepted:** pinned hosts cannot be decrypted. Apps started before the capture may also refuse the new CA until restarted. The UI lists these hosts in one collapsible bar.
- **Auto-stop needs an open tab.** A tab the browser puts to sleep (Edge sleeping tabs) counts as closed after `auto_stop_seconds`.
- **Bodies over 5 MB** are streamed through and not stored or shown.
- **The UI keeps the last 5000 requests.** The `.mitm` file keeps all of them.
- **Redaction is by field name** (auth, token, password, key, user, code, ...), plus JWTs and
  bearer tokens anywhere. Other free-text personal data is not masked. Check exports before you share them.
- **WebSocket flows** can be viewed but not resent, intercepted or rewritten.
- **Held traffic makes the program wait.** Some programs give up after their own timeout; release quickly. Binary or very large bodies are sent on unchanged.

## Layout
```
tlspeek.cmd            launcher
settings.json          created on first use: last program, host filter, UI port, auto-stop, retention
app\
  bootstrap.ps1        installs Python and the Python packages if missing, runs tlspeek.py
  tlspeek.py           command line: capture / open / cleanup, CA handling, HAR on exit
  home.py              start page server
  win.py               flags, ports, UAC relaunch, console window, tray icon
  addon.py             mitmproxy addon: UI server, flow tracking, intercept, decoders
  export.py            credential masking, HAR and Postman export
  web.py               request handler base for both local servers
  test_tlspeek.py      redaction and UI API checks
ui\
  home.html            start page
  index.html           capture UI, with style.css and one ES module per panel
  base.css             colours shared by both pages
```
