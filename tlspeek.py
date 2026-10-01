"""tls-peek: capture one Windows program's HTTPS traffic and inspect it in a web UI.

  tlspeek.py [capture]      start a capture (asks for admin, opens the UI)
  tlspeek.py open [FILE]    view a saved .mitm session (file dialog without FILE)
  tlspeek.py cleanup        untrust and delete the CA (only needed after a crash)

Dropping a .mitm file on tlspeek.exe opens it. Add --no-browser to skip opening the UI.
"""
import ctypes
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path

import addon

CONFDIR = addon.APP_DIR / ".mitmproxy"
CAPTURES = addon.APP_DIR / "captures"
ELEVATED = "--elevated" in sys.argv
NO_BROWSER = "--no-browser" in sys.argv


def fail(msg):
    print(msg)
    if ELEVATED:
        input("Press Enter to close")
    sys.exit(1)


def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin() != 0


def port_free(port):
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def open_when_up(port, timeout=120):
    """Opens the UI in the browser once the server answers."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            if not NO_BROWSER:
                webbrowser.open(f"http://127.0.0.1:{port}")
            return True
        except OSError:
            time.sleep(0.3)
    return False


def relaunch_as_admin(cmd):
    if getattr(sys, "frozen", False):
        params = f"{cmd} --elevated"
    else:
        params = f'"{Path(__file__).resolve()}" {cmd} --elevated'
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, str(addon.APP_DIR), 1)
    return rc > 32


def run_mitmdump(args):
    from mitmproxy.tools.main import mitmdump
    mitmdump(["-q", "-s", str(addon.HERE / "addon.py"), *args])


def auto_stop(settings):
    """mitmproxy args: stop once no UI tab is open (settings auto_stop_seconds, 0 = never)."""
    return ["--set", f"ui_auto_stop={int(settings.get('auto_stop_seconds', 300))}"]


def cleanup():
    removed = 0
    while removed < 10 and subprocess.run(["certutil", "-delstore", "Root", "mitmproxy"],
                                          capture_output=True).returncode == 0:
        removed += 1
    shutil.rmtree(CONFDIR, ignore_errors=True)
    print(f"Cleanup: removed {removed} trusted CA certificate(s), deleted {CONFDIR}.")


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

    src = session.with_suffix(".mitm")
    if not src.exists() or src.stat().st_size == 0:
        return
    with open(src, "rb") as fo:
        # A flow saved again after a bookmark or note appears twice; the last copy wins.
        flows = {f.id: f for f in io.FlowReader(fo).stream() if isinstance(f, http.HTTPFlow) and f.response}
    har = addon.make_har(list(flows.values()))
    session.with_suffix(".har").write_text(json.dumps(har, indent=2), "utf-8")
    print(f"Saved redacted HAR: {session.with_suffix('.har')}")


# Windows gives a closing console window about 5 seconds; enough to untrust the CA.
@ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
def on_console_close(event):
    if event in (2, 5, 6):  # CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT
        cleanup()
    return False


def capture():
    settings = addon.read_settings()
    port = int(settings.get("ui_port") or 8081)
    if not port_free(port):
        fail(f"Port {port} is busy. Is tls-peek already running? Otherwise change ui_port in settings.json.")

    if not is_admin():
        if not relaunch_as_admin("capture"):
            fail("Capture needs administrator rights (the UAC prompt was declined).")
        print("Capture started in the administrator window. Opening the UI...")
        if not open_when_up(port):
            print(f"The UI did not come up. Check the administrator window, then open http://127.0.0.1:{port}")
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
    if not ELEVATED:  # started as admin directly, so nobody else opens the browser
        threading.Thread(target=open_when_up, args=(port,), daemon=True).start()
    print(f"Capturing. UI: http://127.0.0.1:{port}  Saving to: {session}.mitm")
    print("Stop with Ctrl+C. If nothing shows up, close and reopen the monitored program.\n")
    try:
        run_mitmdump([
            "--mode", f"local:{addon.NO_PROGRAM}", "--set", f"confdir={CONFDIR}", *auto_stop(settings),
            "--save-stream-file", f"{session}.mitm", "--set", f"ui_port={port}",
            "--set", "stream_large_bodies=5m",
        ])
    finally:
        export_har(session)
        cleanup()
    if ELEVATED:
        time.sleep(3)  # long enough to read the summary before the window closes


def open_session(path):
    if not path:
        import tkinter
        from tkinter import filedialog
        tkinter.Tk().withdraw()
        path = filedialog.askopenfilename(initialdir=CAPTURES, filetypes=[("mitmproxy session", "*.mitm")])
        if not path:
            return
    port = free_port()
    threading.Thread(target=open_when_up, args=(port,), daemon=True).start()
    print(f"Viewing {path} at http://127.0.0.1:{port}. Stop with Ctrl+C.")
    with tempfile.TemporaryDirectory() as confdir:  # keeps the throwaway CA out of the home folder
        run_mitmdump(["-n", "-r", str(path), "--set", "keepserving=true", "--set", f"confdir={confdir}",
                      *auto_stop(addon.read_settings()),
                      "--set", f"ui_port={port}", "--set", f"ui_file={path}"])


def main():
    args = [a for a in sys.argv[1:] if a not in ("--elevated", "--no-browser")]
    cmd = args[0] if args else "capture"
    if cmd.lower().endswith(".mitm"):
        open_session(cmd)
    elif cmd == "open":
        open_session(args[1] if len(args) > 1 else "")
    elif cmd == "cleanup":
        if not is_admin():
            if not relaunch_as_admin("cleanup"):
                fail("Cleanup needs administrator rights.")
            return
        cleanup()
        if ELEVATED:
            input("Press Enter to close")
    elif cmd == "capture":
        capture()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
