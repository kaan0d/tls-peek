"""tls-peek: capture one Windows program's HTTPS traffic and inspect it in a web UI.

  tlspeek.py                start page in the browser: start a capture, open saved sessions, clean up
  tlspeek.py capture        start a capture right away (asks for admin, opens the UI)
  tlspeek.py open [FILE]    view a saved .mitm session (file dialog without FILE)
  tlspeek.py cleanup        untrust and delete the CA (only needed after a crash)
  tlspeek.py report FILE    findings and endpoints of a saved session on the console; --json for a machine-readable
                            report, --fail-on high|medium|low|info for exit code 1 when a finding of that level exists

Dropping a .mitm file on tlspeek.exe opens it. Add --no-browser to skip opening the UI.
"""
import ctypes
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import addon
from addon import CAPTURES, CONFDIR
from home import run_home
from version import VERSION
from win import (ELEVATED, exited, fail, flag, free_port, is_admin, open_when_up, owns_console, port_free,
                 relaunch_as_admin, show_console, start_tray, stop_with_parent, tray_available)


def run_mitmdump(args):
    from mitmproxy.tools.main import mitmdump
    mitmdump(["-q", "-s", str(addon.HERE / "addon.py"), *args])


def auto_stop(settings):
    """mitmproxy args: stop once no UI tab is open (settings auto_stop_seconds, 0 = never)."""
    return ["--set", f"ui_auto_stop={int(settings.get('auto_stop_seconds', 300))}"]


def cleanup():
    """Untrusts every mitmproxy CA and deletes this folder's CA key; returns how many were removed."""
    removed = 0
    while removed < 10 and subprocess.run(["certutil", "-delstore", "Root", "mitmproxy"],
                                          capture_output=True).returncode == 0:
        removed += 1
    shutil.rmtree(CONFDIR, ignore_errors=True)
    print(f"Cleanup: removed {removed} trusted CA certificate(s), deleted {CONFDIR}.")
    return removed


def prune_captures(keep_days):
    if keep_days <= 0:
        return
    cutoff = time.time() - keep_days * 86400
    for p in CAPTURES.glob("session-*"):
        if p.stat().st_mtime < cutoff:
            p.unlink()
            print(f"Deleted old capture {p.name}")


def export_har(session):
    """Writes session.har from session.mitm with credentials masked."""
    from mitmproxy import http, io

    from export import make_har

    src = session.with_suffix(".mitm")
    if not src.exists() or src.stat().st_size == 0:
        return
    with open(src, "rb") as fo:
        # A flow saved again after a bookmark or note appears twice; the last copy wins.
        flows = {f.id: f for f in io.FlowReader(fo).stream() if isinstance(f, http.HTTPFlow)}
    har = make_har(list(flows.values()))
    out = session.with_suffix(".har")
    out.write_text(json.dumps(har, indent=2), "utf-8")
    # same format as SHA256SUMS: sha256sum -c works, and so does comparing with certutil -hashfile
    out.with_name(out.name + ".sha256").write_text(f"{hashlib.sha256(out.read_bytes()).hexdigest()} *{out.name}\n", "utf-8")
    print(f"Saved redacted HAR: {session.with_suffix('.har')}")


# Windows gives a closing console window about 5 seconds; enough to untrust the CA.
@ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
def on_console_close(event):
    if event in (2, 5, 6):  # CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT
        cleanup()
    return False


def home_args():
    """mitmproxy args: link the UI back to the start page it was opened from."""
    home = flag("--home-port")
    return ["--set", f"ui_home=http://127.0.0.1:{home}/"] if home else []


def capture():
    settings = addon.read_settings()
    port = int(flag("--port") or settings.get("ui_port") or 8081)
    if not port_free(port):
        fail(f"Port {port} is busy. Is tls-peek already running? Otherwise change ui_port in {addon.SETTINGS}.")

    if not is_admin():
        tray = tray_available()
        # With a tray icon the admin window hides itself; the tray can show it again.
        child = relaunch_as_admin("capture --hide-console" if tray else "capture")
        if not child:
            fail("Capture needs administrator rights (the UAC prompt was declined).")
        print("Capture is running as administrator. Closing this window stops it.")
        icon = None
        if open_when_up(port, alive=lambda: not exited(child)):
            if tray:
                if owns_console():
                    show_console(False)
                icon = start_tray(port)
        elif not exited(child):
            print(f"The UI did not come up. Check the administrator window, then open http://127.0.0.1:{port}")
        while not exited(child, 500):  # short waits keep Ctrl+C working
            pass
        if icon:
            icon.stop()
        return

    cleanup()  # a CA left behind by a crashed session
    prune_captures(int(settings.get("keep_days", 7)))
    from mitmproxy.certs import CertStore
    CertStore.from_store(CONFDIR, "mitmproxy", 2048)
    subprocess.run(["certutil", "-addstore", "-f", "Root", str(CONFDIR / "mitmproxy-ca-cert.cer")],
                   check=True, capture_output=True)
    ctypes.windll.kernel32.SetConsoleCtrlHandler(on_console_close, True)

    CAPTURES.mkdir(exist_ok=True)
    session = CAPTURES / time.strftime("session-%Y%m%d-%H%M%S")
    if not ELEVATED and not flag("--home-port"):  # started as admin directly: nobody else opens the browser or tray
        threading.Thread(target=open_when_up, args=(port,), daemon=True).start()
        if tray_available():
            start_tray(port)
    if "--hide-console" in sys.argv:
        show_console(False)
    print(f"Capturing. UI: http://127.0.0.1:{port}  Saving to: {session}.mitm")
    print("Stop with Ctrl+C. If nothing shows up, close and reopen the monitored program.\n")
    try:
        run_mitmdump([
            "--mode", f"local:{addon.NO_PROGRAM}", "--set", f"confdir={CONFDIR}", *auto_stop(settings),
            "--save-stream-file", f"{session}.mitm", "--set", f"ui_port={port}",
            "--set", "stream_large_bodies=5m", *home_args(),
        ])
    finally:
        export_har(session)
        cleanup()
    if ELEVATED and "--hide-console" not in sys.argv:
        time.sleep(1.5)  # long enough to see the summary before the window closes


def open_session(path):
    if not path:
        import tkinter
        from tkinter import filedialog
        tkinter.Tk().withdraw()
        path = filedialog.askopenfilename(initialdir=CAPTURES, filetypes=[("mitmproxy session", "*.mitm")])
        if not path:
            return
    port = int(flag("--port") or free_port())
    threading.Thread(target=open_when_up, args=(port,), daemon=True).start()
    print(f"Viewing {path} at http://127.0.0.1:{port}. Stop with Ctrl+C.")
    with tempfile.TemporaryDirectory() as confdir:  # keeps the throwaway CA out of the home folder
        run_mitmdump(["-n", "-r", str(path), "--set", "keepserving=true", "--set", f"confdir={confdir}",
                      *auto_stop(addon.read_settings()), *home_args(),
                      "--set", f"ui_port={port}", "--set", f"ui_file={path}"])


def report(path, fail_on=None):
    """Findings and endpoints of a .mitm file, as text or --json. Dismissed findings are listed but do not fail the run."""
    from mitmproxy import http, io

    import apimap
    import findings

    with open(path, "rb") as fo:
        flows = list({f.id: f for f in io.FlowReader(fo).stream() if isinstance(f, http.HTTPFlow)}.values())
    ids = {f.id: i for i, f in enumerate(flows)}
    muted = {tuple(m) for m in addon.read_settings().get("dismissed_findings", [])}
    found = [{**x, "dismissed": (x["check"], x["host"]) in muted} for x in findings.check(flows, ids)]
    if "--json" in sys.argv:
        print(json.dumps({"file": str(path), "requests": len(flows), "findings": found,
                          "endpoints": apimap.endpoints(flows, ids)}, indent=2))
    else:
        print(f"{path}: {len(flows)} requests, {len(found)} findings")
        for x in found:
            print(f"{x['severity']:<7}{x['host']}  {x['title']}" + (f" [{x['detail']}]" if x["detail"] else "")
                  + f"  ({x['count']} requests)" + ("  dismissed" if x["dismissed"] else ""))
    limit = findings.ORDER.get(fail_on or "")
    if fail_on and limit is None:
        fail(f"--fail-on must be one of {', '.join(findings.ORDER)}.")
    return 1 if limit is not None and any(findings.ORDER[x["severity"]] <= limit and not x["dismissed"] for x in found) else 0


def main():
    if "--version" in sys.argv:
        print(f"tls-peek {VERSION}")
        return
    stop_with_parent()
    flags_with_value = {"--parent", "--port", "--home-port", "--fail-on"}
    args = [a for i, a in enumerate(sys.argv[1:], 1) if not a.startswith("--") and sys.argv[i - 1] not in flags_with_value]
    cmd = args[0] if args else "home"
    if cmd.lower().endswith(".mitm"):
        open_session(cmd)
    elif cmd == "report" and len(args) > 1:
        sys.exit(report(args[1], flag("--fail-on")))
    elif cmd == "open":
        open_session(args[1] if len(args) > 1 else "")
    elif cmd == "home":
        run_home()
    elif cmd == "cleanup":
        if not is_admin():
            if not relaunch_as_admin("cleanup"):
                fail("Cleanup needs administrator rights.")
            return
        if "--hide-console" in sys.argv:
            show_console(False)
        removed = cleanup()
        if ELEVATED and "--hide-console" not in sys.argv:
            input("Press Enter to close")
        sys.exit(removed)  # the start page reports this number
    elif cmd == "capture":
        capture()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
