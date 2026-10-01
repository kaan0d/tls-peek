# Capturing a Program's Requests with mitmproxy

To see the HTTPS requests (URL, headers, token, sent/received data) that a
desktop program sends to its server.

> For authorized work on systems you own or administer. Captured data
> (username, password, app code, personal/medical records) is **sensitive** —
> mask these fields before sharing.

---

## What it does
- Traffic is **TLS encrypted** → Wireshark cannot show the content.
- **mitmproxy** sits in the middle (with its own certificate), decrypts, and
  makes the request readable.
- Because the program does not use the Windows proxy, **`local` mode**
  (WinDivert) is used: it captures only the traffic of the **program** you pick.

---

## Choosing which program to monitor (NO command line)

Open `settings.json` and change only these:

```json
{
  "program": "MyApp.exe",
  "host_filter": "api\\.example\\.com",
  "ui_port": 8081
}
```

- **program** — name of the .exe to monitor. To watch something else, change
  this (e.g. `"OtherClient.exe"`). If you don't know the exact name, check
  Task Manager > Details.
- **host_filter** — OPTIONAL. Leave empty (`""`) to decrypt all of the
  program's traffic. To limit to a specific address, write it with `\\` before
  each dot (e.g. `"api\\.site\\.com"`).
- **ui_port** — port of the browser interface (default 8081).

---

## Usage (3 steps)

### 1) Start
Double-click **`START-capture.cmd`** → UAC appears, click "Yes" (administrator
required). A black window opens, installs the certificate, and opens the
interface in the browser: **http://127.0.0.1:8081**

### 2) Perform the action in the program
In the monitored program, click the relevant button / pull the data. Requests
appear in the interface.

> **If nothing appears:** **close and reopen** the monitored program, then do
> the action. WinDivert only captures newly opened connections.

### 3) Inspect
Click a request in the interface:
- **Request** → URL, query parameters, headers (token / username / password / app code).
- **Response** → data returned by the server (JSON etc.).
- Right-click → **Copy** → copy as cURL / URL.

### 4) Clean up when done
Double-click **`START-cleanup.cmd`** → removes the certificate from trusted roots.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **No requests appear** | Open the program after the script; close-open, retry the action. Make sure you are administrator. |
| Request **red / TLS error**, program says "cannot connect" | The program **pins** the certificate. This method won't work; use the data's source (API/IT). |
| `mitmweb not found` | `python -m pip install --user mitmproxy` |
| UAC/admin issue | `START-capture.cmd` already requests admin; click "Yes". |

---

## Files

| File | Role |
|---|---|
| `settings.json` | **Set the program to monitor here.** |
| `START-capture.cmd` | Double-click → starts capture as administrator |
| `START-cleanup.cmd` | Double-click → removes the certificate, cleans up |
| `mitm-capture.ps1` | Capture script (called by the .cmd) |
| `mitm-cleanup.ps1` | Cleanup script |
| `README.md` | This guide |

---

## Security
- The certificate only enables HTTPS decryption on this machine; remove it with
  `START-cleanup.cmd` when done.
- Captured credentials/personal data are sensitive — keep records safe, delete
  when no longer needed.
- Use only on your own organization's authorized systems, within your authority.
