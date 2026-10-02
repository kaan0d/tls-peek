"""Start page: the non-admin process that launches captures, saved-session viewers and cleanup."""
import ctypes
import os
import subprocess
import threading
import time
import webbrowser
from ctypes import wintypes
from http.server import ThreadingHTTPServer

import addon
from addon import CAPTURES, CONFDIR
from web import LocalHandler
from win import (NO_BROWSER, ca_trusted, exited, fail, flag, free_port, is_up, owns_console, port_free,
                 relaunch_as_admin, self_command, show_console, start_tray, tray_available)


class Home:
    """State of the start page: at most one capture or saved-session viewer at a time."""

    def __init__(self, port):
        self.port = port
        self.child = None      # {"kind", "port", "alive": callable, "file"}
        self.icon = None
        self.message = ""      # last result shown on the page (cleanup, errors)
        self.started = time.time()
        self.wait_for_tab = 120  # seconds to wait for a first page view before giving up
        self.last_seen = None
        self.bye_at = None
        self.lock = threading.Lock()

    def child_alive(self):
        return self.child is not None and self.child["alive"]()

    def sessions(self):
        if not CAPTURES.exists():
            return []
        out = []
        for p in sorted(CAPTURES.glob("*.mitm"), key=lambda p: p.stat().st_mtime, reverse=True):
            st = p.stat()
            out.append({"name": p.name, "size": st.st_size, "time": st.st_mtime,
                        "har": p.with_suffix(".har").exists()})
        return out

    def status(self):
        child = None
        if self.child_alive():
            c = self.child
            child = {"kind": c["kind"], "port": c["port"], "file": c.get("file", ""), "up": is_up(c["port"])}
        return {"child": child, "sessions": self.sessions(), "ca_trusted": ca_trusted(),
                "ca_folder": CONFDIR.exists(), "message": self.message}

    def session_path(self, name):
        """A file in captures\\ by bare name; rejects anything that points elsewhere."""
        p = (CAPTURES / name).resolve()
        if p.parent != CAPTURES.resolve() or p.suffix not in (".mitm", ".har") or not p.exists():
            raise ValueError("no such session")
        return p

    def start_capture(self):
        with self.lock:
            if self.child_alive():
                raise ValueError("a capture or session view is already open")
            port = free_port()
            tray = tray_available()
            args = f"capture --port {port} --home-port {self.port}" + (" --hide-console" if tray else "")
            handle = relaunch_as_admin(args)
            if not handle:
                raise ValueError("Capture needs administrator permission; the prompt was declined.")
            self.child = {"kind": "capture", "port": port, "alive": lambda: not exited(handle)}
            self.icon = start_tray(port) if tray else None
            self.message = ""

    def open_session(self, name):
        with self.lock:
            if self.child_alive():
                raise ValueError("a capture or session view is already open")
            path = self.session_path(name)
            port = free_port()
            proc = subprocess.Popen(
                self_command("open", path, "--no-browser", "--port", port, "--home-port", self.port,
                             "--parent", os.getpid()),
                creationflags=subprocess.CREATE_NO_WINDOW)
            self.child = {"kind": "viewer", "port": port, "file": path.name, "alive": lambda: proc.poll() is None}
            self.message = ""

    def delete(self, name):
        path = self.session_path(name)
        for p in (path.with_suffix(".mitm"), path.with_suffix(".har")):
            p.unlink(missing_ok=True)

    def cleanup(self):
        with self.lock:
            if self.child_alive() and self.child["kind"] == "capture":
                raise ValueError("stop the running capture first")
            handle = relaunch_as_admin("cleanup --hide-console")
            if not handle:
                raise ValueError("Cleanup needs administrator permission; the prompt was declined.")
            exited(handle, 60_000)
            code = wintypes.DWORD()
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            n = code.value
            self.message = (f"Removed {n} capture certificate(s) and the CA folder." if n
                            else "No capture certificate was installed; the CA folder is removed.")

    def seen(self, bye=False):
        if bye:
            self.bye_at = time.time()
        else:
            self.last_seen = time.time()

    def should_exit(self):
        """No capture or viewer running and no start page open (closed, or never opened)."""
        if self.child_alive():
            return False
        now = time.time()
        if self.last_seen is None:
            return now - self.started > self.wait_for_tab
        closed = self.bye_at is not None and self.bye_at >= self.last_seen and now - self.bye_at > 10
        return closed or now - self.last_seen > int(addon.read_settings().get("auto_stop_seconds", 300) or 10 ** 9)

    def tick(self):
        """Called every second: tidy up after a child that ended."""
        if self.child is not None and not self.child_alive():
            self.child = None
            # Forget page visits from before the child ended (the tab left for the capture),
            # keep ones from the tab coming back. If it never comes back, end tls-peek soon.
            ended = time.time() - 2  # tick runs every second, so the end was at most ~1 s ago
            if self.last_seen is not None and self.last_seen < ended:
                self.last_seen = None
            if self.bye_at is not None and self.bye_at < ended:
                self.bye_at = None
            self.started, self.wait_for_tab = time.time(), 30
            if self.icon:
                self.icon.stop()
                self.icon = None


def make_home_handler(home):
    class Handler(LocalHandler):
        def do_GET(self):
            if not self.allowed():
                return
            home.seen()
            path, _, query = self.path.partition("?")
            if path == "/":
                self.send(200, (addon.HERE / "home.html").read_bytes(), "text/html; charset=utf-8")
            elif self.send_static(path):
                pass
            elif path == "/api/home":
                self.send(200, home.status())
            elif path == "/api/file":
                from urllib.parse import parse_qs
                try:
                    p = home.session_path(parse_qs(query).get("name", [""])[0])
                except ValueError as e:
                    return self.send(404, {"error": str(e)})
                self.send(200, p.read_bytes(), "application/octet-stream",
                          [("Content-Disposition", f'attachment; filename="{p.name}"')])
            else:
                self.send(404, {"error": "not found"})

        def do_POST(self):
            if not self.allowed():
                return
            try:
                body = self.json_body()
                if self.path == "/api/bye":
                    home.seen(bye=True)
                    return self.send(200, {})
                home.seen()
                if self.path == "/api/start-capture":
                    home.start_capture()
                elif self.path == "/api/open":
                    home.open_session(body["name"])
                elif self.path == "/api/delete":
                    home.delete(body["name"])
                elif self.path == "/api/cleanup":
                    home.cleanup()
                else:
                    return self.send(404, {"error": "not found"})
                self.send(200, home.status())
            except Exception as e:
                self.send(400, {"error": str(e)})

    return Handler


def run_home():
    port = int(flag("--port") or addon.read_settings().get("ui_port") or 8081)
    if not port_free(port):
        if is_up(port):  # probably tls-peek already running: just show it
            if not NO_BROWSER:
                webbrowser.open(f"http://127.0.0.1:{port}")
            return
        fail(f"Port {port} is busy. Change ui_port in settings.json.")
    home = Home(port)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_home_handler(home))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"tls-peek start page: http://127.0.0.1:{port}  (closing the page ends tls-peek)")
    if not NO_BROWSER:
        webbrowser.open(f"http://127.0.0.1:{port}")
    if owns_console():
        show_console(False)
    try:
        while not home.should_exit():
            home.tick()
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    home.tick()
    server.shutdown()
