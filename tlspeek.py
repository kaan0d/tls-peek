"""tls-peek: capture one Windows program's HTTPS traffic and inspect it in a web UI.

  tlspeek.py [capture]      start a capture (asks for admin, opens the UI)
  tlspeek.py open [FILE]    view a saved .mitm session (file dialog without FILE)
  tlspeek.py cleanup        untrust and delete the CA (only needed after a crash)

Dropping a .mitm file on tlspeek.exe opens it. Add --no-browser to skip opening the UI.
"""
import ctypes
import json
import os
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from ctypes import wintypes
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


def open_when_up(port, timeout=120, alive=lambda: True):
    """Opens the UI in the browser once the server answers."""
    end = time.time() + timeout
    while time.time() < end and alive():
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            if not NO_BROWSER:
                webbrowser.open(f"http://127.0.0.1:{port}")
            return True
        except OSError:
            time.sleep(0.3)
    return False


class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
SYNCHRONIZE = 0x00100000
INFINITE = 0xFFFFFFFF


def relaunch_as_admin(cmd):
    """Starts this program again as administrator (UAC prompt). Returns the new process handle,
    or None when the prompt was declined. The new process stops when this one exits."""
    args = f"{cmd} --elevated --parent {os.getpid()}"
    params = args if getattr(sys, "frozen", False) else f'"{Path(__file__).resolve()}" {args}'
    info = _ShellExecuteInfo(cbSize=ctypes.sizeof(_ShellExecuteInfo), fMask=0x40,  # SEE_MASK_NOCLOSEPROCESS
                             lpVerb="runas", lpFile=sys.executable, lpParameters=params,
                             lpDirectory=str(addon.APP_DIR), nShow=1)
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        return None
    return info.hProcess


def exited(handle, wait_ms=0):
    return kernel32.WaitForSingleObject(handle, wait_ms) == 0  # WAIT_OBJECT_0


def stop_with_parent():
    """Admin process: stop like Ctrl+C once the window that started us is gone (closed, killed),
    so a capture never keeps running on its own."""
    if "--parent" not in sys.argv:
        return
    handle = kernel32.OpenProcess(SYNCHRONIZE, False, int(sys.argv[sys.argv.index("--parent") + 1]))
    if not handle:
        return

    def wait():
        kernel32.WaitForSingleObject(handle, INFINITE)
        print("The tls-peek window that started this capture was closed; stopping.")
        signal.raise_signal(signal.SIGINT)

    threading.Thread(target=wait, daemon=True).start()


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


def start_tray(port):
    """Tray icon for a running capture: open the UI, pause/resume, show the log window, stop.
    Runs in its own thread; returns the icon (call .stop() to remove it)."""
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
        while True:
            try:
                state.update(call("/api/state"))
                refresh(icon)
            except OSError:
                pass
            time.sleep(2)

    threading.Thread(target=icon.run, kwargs={"setup": lambda i: threading.Thread(target=watch, daemon=True).start()},
                     daemon=True).start()
    return icon



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
    if not ELEVATED:  # started as admin directly, so nobody else opens the browser or shows a tray icon
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
            "--set", "stream_large_bodies=5m",
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
    port = free_port()
    threading.Thread(target=open_when_up, args=(port,), daemon=True).start()
    print(f"Viewing {path} at http://127.0.0.1:{port}. Stop with Ctrl+C.")
    with tempfile.TemporaryDirectory() as confdir:  # keeps the throwaway CA out of the home folder
        run_mitmdump(["-n", "-r", str(path), "--set", "keepserving=true", "--set", f"confdir={confdir}",
                      *auto_stop(addon.read_settings()),
                      "--set", f"ui_port={port}", "--set", f"ui_file={path}"])


def main():
    stop_with_parent()
    flags_with_value = {"--parent"}
    args = [a for i, a in enumerate(sys.argv[1:], 1) if not a.startswith("--") and sys.argv[i - 1] not in flags_with_value]
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
