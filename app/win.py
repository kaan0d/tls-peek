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


def tray_icon_image(paused, size=64):
    """ui/icon.svg is the same drawing (unpaused) for the browser tab, and app/icon.ico for the exe
    (python -c "from win import tray_icon_image as t; t(False, 256).save('icon.ico')" in app\\); change all together."""
    from PIL import Image, ImageDraw
    s = size / 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((2 * s, 2 * s, 62 * s, 62 * s), 14 * s, fill=(224, 168, 74) if paused else (47, 111, 223))
    d.ellipse((14 * s, 12 * s, 42 * s, 40 * s), outline="white", width=round(6 * s))  # magnifier
    d.line((38 * s, 36 * s, 52 * s, 50 * s), fill="white", width=round(8 * s))
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
