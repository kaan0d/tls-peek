"""Windows and process plumbing shared by the command line and the start page:
command-line flags, ports, UAC relaunch, waiting on processes, the console window and the tray icon."""
import ctypes
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from ctypes import wintypes
from pathlib import Path

from addon import APP_DIR

SCRIPT = Path(__file__).with_name("tlspeek.py").resolve()  # what to relaunch when not frozen

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
    params = args if getattr(sys, "frozen", False) else f'"{SCRIPT}" {args}'
    info = _ShellExecuteInfo(cbSize=ctypes.sizeof(_ShellExecuteInfo), fMask=0x40,  # SEE_MASK_NOCLOSEPROCESS
                             lpVerb="runas", lpFile=sys.executable, lpParameters=params,
                             lpDirectory=str(APP_DIR), nShow=1)
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


# The tile and letter of the logo, 128 px. app/icon.ico and ui/icon.svg are the same drawing; the pupil is drawn on
# top so it can change colour. The small-size cut of the logo.
TRAY_TILE = (
    "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"
    "vw/8B6YljPRVmy/qAAAAAElFTkSuQmCC"
)
TRAY_PUPIL = (0.5449, 0.3121, 0.0672)  # x, y and radius as fractions of the tile


def tray_icon_image(paused, size=64):
    """The logo for the tray: mint pupil while capturing, amber while paused."""
    import base64
    import io
    from PIL import Image, ImageDraw
    img = Image.open(io.BytesIO(base64.b64decode(TRAY_TILE))).convert("RGBA")
    x, y, r = (v * img.width for v in TRAY_PUPIL)
    ImageDraw.Draw(img).ellipse((x - r, y - r, x + r, y + r), fill=(224, 168, 74) if paused else (53, 230, 171))
    return img.resize((size, size), Image.LANCZOS)


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


def flag(name, default=None):
    """Value of a --name VALUE command line flag."""
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def self_command(*args):
    """Command line that runs this program (script or frozen exe) with args."""
    base = [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, str(SCRIPT)]
    return base + [str(a) for a in args]


def ca_trusted():
    return subprocess.run(["certutil", "-store", "Root", "mitmproxy"], capture_output=True).returncode == 0


def is_up(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False
