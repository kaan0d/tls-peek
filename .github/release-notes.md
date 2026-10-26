## Downloads
- `tlspeek.exe`: single file, nothing to unpack.
- `tlspeek-windows.zip`: same program as a folder. Unzip it anywhere and run `tlspeek\tlspeek.exe`.
- `SHA256SUMS`: check with `certutil -hashfile <file> SHA256`.

## Antivirus warnings
tls-peek installs a temporary root certificate, loads the WinDivert driver and asks for administrator rights. Some antivirus products (for example Kaspersky `PDM:Trojan.Win32.Generic`) flag this behaviour on unsigned executables. The source is in this repository and CI builds both files.

The single exe unpacks itself to `%TEMP%` on every start, which is what these heuristics dislike most. If your antivirus flags it, use the zip instead: it does not unpack at start. If it still flags the zip, add an exclusion for the folder or report a false positive to your vendor.

