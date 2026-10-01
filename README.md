# tls-peek

See the HTTPS requests (URL, headers, tokens, bodies) one Windows desktop
program sends, using mitmproxy `local` mode (WinDivert). Works on programs that
ignore the system proxy. Needs administrator rights.

> For authorized work on systems you own or administer. Captures contain
> credentials and personal data: keep them private and delete them when done.

## Features
- **Per-program capture:** only the picked `.exe` is intercepted, not the whole machine.
- **Program picker:** choose from running processes, no JSON editing needed.
- **Fresh CA per session:** generated in `.mitmproxy\`, untrusted and deleted on exit.
- **Saved sessions:** every capture streams to `captures\<program>-<time>.mitm`.
- **Redacted HAR export:** on exit, credential headers, query params, form and JSON fields are masked.
- **Pinning warning:** the console says when the program rejects the certificate.

## Setup
```
python -m pip install --user mitmproxy
```

## Usage
Double-click `tlspeek.cmd`:

| Key | Action |
|---|---|
| 1 | Pick the program to monitor (saved to `settings.json`) |
| 2 | Start capture (UAC prompt). The UI opens at http://127.0.0.1:8081 |
| 3 | Cleanup, only if the capture window was closed without Ctrl+C |

Then:
1. Close and reopen the monitored program. WinDivert only sees new connections.
2. Do the action in the program. Requests appear in the browser UI.
3. Press **Ctrl+C** in the capture window. It writes `captures\*.har`
   (redacted) and removes the CA.

Reopen a full, unredacted session later: `mitmweb -r captures\<file>.mitm`.

`settings.json`:
```json
{ "program": "MyApp.exe", "host_filter": "api.example.com", "ui_port": 8081 }
```
`host_filter` is optional (empty = all traffic). A value containing `\` is used as a regex.

## Verification
```
python test_tlspeek.py
```
Builds a flow with secrets in the header, query, JSON body and cookie. Then
checks that the redacted HAR contains none of them.

## Limits
- **Certificate pinning:** pinned hosts cannot be decrypted. The console warns per host.
- **Closing the window** instead of Ctrl+C skips the export and cleanup. Run option 3.
- **Redaction is by field name** (auth, token, pass, key, user, code, ...). Free-text
  personal data in bodies is not masked. Check the HAR before you share it.

## Layout
```
tlspeek.cmd        launcher menu
mitm-capture.ps1   picker + capture session
mitm-cleanup.ps1   untrust and delete CA, stop mitmproxy
tlspeek.py         mitmproxy addon: pinning warning, redaction
test_tlspeek.py    redaction check
settings.json      program, host filter, UI port
```
