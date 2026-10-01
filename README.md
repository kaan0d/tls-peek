# tls-peek

See the HTTPS requests (URL, headers, tokens, bodies) one Windows desktop
program sends, using mitmproxy `local` mode (WinDivert). Works on programs that
ignore the system proxy. Needs administrator rights.

> For authorized work on systems you own or administer. Captures contain
> credentials and personal data: keep them private and delete them when done.

## Features
- **Own web UI:** pick the program, set the host filter and inspect traffic at http://127.0.0.1:8081.
- **Live switching:** program and host filter change without a restart and are saved to `settings.json`.
- **Request view:** search, status colors, headers, query, pretty JSON bodies, copy URL or cURL.
- **Fresh CA per session:** generated in `.mitmproxy\`, untrusted and deleted on exit.
- **Saved sessions:** every capture streams to `captures\session-<time>.mitm`.
- **Redacted HAR export:** from the UI button or on exit, with credential headers, query params, form and JSON fields masked.
- **Pinning warning:** the UI shows when the program rejects the certificate.

## Setup
Nothing to install by hand. On the first capture, a missing Python 3.13 is
installed with winget (or the python.org installer when winget is absent), then
mitmproxy with `pip install --user mitmproxy`.

## Usage
Double-click `tlspeek.cmd`, choose **1** and accept the UAC prompt. The UI opens in your browser.

1. Click **Program** and pick the app (tick **Background** for tray apps, or type an `.exe` name and press Enter).
2. Optionally enter a host filter such as `api.example.com` and press **Apply**. Empty means all traffic.
3. Close and reopen the monitored program, then do the action. WinDivert only sees new connections.
4. Press **Ctrl+C** in the capture window to stop. It writes `captures\*.har` (redacted) and removes the CA.

If the window was closed without Ctrl+C, run `tlspeek.cmd` and choose **2** (cleanup).
Reopen a full, unredacted session later: `mitmweb -r captures\<file>.mitm`.

A host filter containing `\` is used as a regex as-is.

## Verification
```
python test_tlspeek.py
```
Checks that the redacted HAR contains no secrets from the header, query, JSON
body and cookie. Then starts the UI server and checks the flows API, the Host
guard and live program switching.

## Limits
- **Certificate pinning:** pinned hosts cannot be decrypted. The UI warns per host.
- **Closing the window** instead of Ctrl+C skips the export and cleanup. Run option 2.
- **The UI keeps the last 5000 requests** and shows them once the response arrives. The `.mitm` file keeps all of them.
- **Redaction is by field name** (auth, token, pass, key, user, code, ...). Free-text
  personal data in bodies is not masked. Check the HAR before you share it.

## Layout
```
tlspeek.cmd        launcher menu (capture / cleanup)
mitm-capture.ps1   CA setup, runs mitmdump with the addon, export on exit
mitm-cleanup.ps1   untrust and delete CA, stop mitmproxy
tlspeek.py         mitmproxy addon: UI server, pinning warning, redaction
ui.html            web UI
test_tlspeek.py    redaction and UI API check
settings.json      program, host filter, UI port (written by the UI)
```
