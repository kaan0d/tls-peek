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
    show_console(True)  # it may have been hidden behind the tray icon
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


TRAY_HEADER = {"X-Tlspeek-Tray": "1"}  # tray polls must not count as an open UI tab (auto-stop)


def tray_available():
    try:
        import PIL  # noqa: F401
        import pystray  # noqa: F401
        return True
    except ImportError:
        return False


def show_console(show):
    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 5 if show else 0)  # SW_SHOW / SW_HIDE


def owns_console():
    """True when this console was opened just for tls-peek (double-clicked exe or tlspeek.cmd),
    not a terminal the user is working in, so it is fine to hide it."""
    if "--own-console" in sys.argv:
        return True
    procs = (ctypes.c_uint * 8)()
    return getattr(sys, "frozen", False) and ctypes.windll.kernel32.GetConsoleProcessList(procs, 8) <= 2


def tray_icon_image(paused):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((2, 2, 62, 62), 14, fill=(224, 168, 74) if paused else (47, 111, 223))
    d.ellipse((14, 12, 42, 40), outline="white", width=6)  # magnifier
    d.line((38, 36, 52, 50), fill="white", width=8)
    return img


def run_tray(port):
    """Tray icon for a running capture: open the UI, pause/resume, show the log window, stop.
    Returns when the capture is gone."""
    import json
    import urllib.request

    import pystray

    base = f"http://127.0.0.1:{port}"
    state = {"paused": False, "program": "", "console": False}

    def call(path, data=None):
        req = urllib.request.Request(base + path, headers=dict(TRAY_HEADER),
                                     data=None if data is None else json.dumps(data).encode())
        if data is not None:
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read())

    def toggle_pause(icon, item):
        state.update(call("/api/pause", {"paused": not state["paused"]}))
        refresh(icon)

    def toggle_console(icon, item):
        state["console"] = not state["console"]
        call("/api/console", {"show": state["console"]})

    def refresh(icon):
        if state.get("shown_paused") != state["paused"]:
            state["shown_paused"] = state["paused"]
            icon.icon = tray_icon_image(state["paused"])
        what = state["program"] or "no program picked"
        icon.title = f"tls-peek: {'paused' if state['paused'] else 'capturing'} {what}"[:127]
        icon.update_menu()

    icon = pystray.Icon("tls-peek", tray_icon_image(False), "tls-peek", pystray.Menu(
        pystray.MenuItem("Open tls-peek", lambda: webbrowser.open(base), default=True),
        pystray.MenuItem(lambda item: "Resume capture" if state["paused"] else "Pause capture", toggle_pause),
        pystray.MenuItem("Show log window", toggle_console, checked=lambda item: state["console"]),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Stop capture", lambda: call("/api/stop", {})),
    ))

    def watch():
        icon.visible = True
        misses = 0
        while misses < 3:  # the capture is gone once the server stops answering
            time.sleep(2)
            try:
                state.update(call("/api/state"))
                misses = 0
                refresh(icon)
            except OSError:
                misses += 1
        icon.stop()

    icon.run(setup=lambda i: threading.Thread(target=watch, daemon=True).start())



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
        tray = tray_available()
        # With a tray icon the admin window hides itself; the tray can show it again.
        if not relaunch_as_admin("capture --hide-console" if tray else "capture"):
            fail("Capture needs administrator rights (the UAC prompt was declined).")
        print("Capture started in the administrator window. Opening the UI...")
        if not open_when_up(port):
            print(f"The UI did not come up. Check the administrator window, then open http://127.0.0.1:{port}")
            return
        if tray:
            if owns_console():
                show_console(False)
            run_tray(port)
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
    if not ELEVATED:  # started as admin directly, so nobody else opens the browser or shows a tray icon
        threading.Thread(target=open_when_up, args=(port,), daemon=True).start()
        if tray_available():
            threading.Thread(target=run_tray, args=(port,), daemon=True).start()
    if "--hide-console" in sys.argv:
        show_console(False)
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
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
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
