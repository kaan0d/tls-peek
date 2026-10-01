"""mitmproxy addon for tls-peek.

Serves the web UI (ui.html) on 127.0.0.1 when ui_port > 0: pick the program,
set the host filter, inspect, search, filter and resend traffic. Warns when the
monitored program rejects the mitmproxy certificate (pinning).

With redact=true it masks credentials in every flow (used for HAR export).
"""
import asyncio
import json
import logging
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

from mitmproxy import contentviews, ctx, http
from OpenSSL import SSL
from mitmproxy.addons.savehar import SaveHar
from mitmproxy.utils import strutils

HERE = Path(__file__).parent
# settings.json and captures\ live next to tlspeek.exe when frozen, else next to this file.
APP_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else HERE
SETTINGS = APP_DIR / "settings.json"
MASK = "***"
MAX_FLOWS = 5000  # ponytail: oldest flows drop from the UI past this; the .mitm file keeps all
MAX_BODY = 200_000
MAX_WS_MESSAGES = 1000
NO_PROGRAM = "tlspeek-no-program.exe"  # local mode needs a target; this matches nothing
BYE_GRACE = 10  # seconds a closed tab has to come back (a refresh) before auto-stop

# Field names are split into words ("X-Api-Key" -> x, api, key; "accessToken" ->
# access, token). A field is masked when one of its words is in SECRET_WORDS.
SECRET_WORDS = {
    "auth", "authorization", "authentication", "bearer", "cookie", "cookies", "token", "jwt",
    "pass", "passwd", "password", "pwd", "passphrase", "secret", "key", "apikey", "session",
    "sessionid", "sid", "user", "username", "userid", "login", "code", "otp", "pin", "sig",
    "signature", "credential", "credentials", "csrf", "xsrf",
}
NOT_SECRET = {"user-agent"}
WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")


def is_secret(name):
    if name.lower() in NOT_SECRET:
        return False
    return any(w.lower() in SECRET_WORDS for w in WORD.findall(name))


def mask_json(obj):
    if isinstance(obj, dict):
        return {k: MASK if is_secret(k) else mask_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_json(v) for v in obj]
    return obj


def mask_message(msg):
    for name in list(msg.headers):
        if is_secret(name):
            msg.headers[name] = MASK
    ctype = msg.headers.get("content-type", "")
    if not msg.raw_content:
        return
    if "json" in ctype:
        try:
            msg.text = json.dumps(mask_json(json.loads(msg.text)))
        except ValueError:
            pass
    elif "x-www-form-urlencoded" in ctype:
        pairs = parse_qsl(msg.text, keep_blank_values=True)
        msg.text = urlencode([(k, MASK if is_secret(k) else v) for k, v in pairs])


def redact(flow):
    req = flow.request
    req.query = [(k, MASK if is_secret(k) else v) for k, v in req.query.items(multi=True)]
    mask_message(req)
    if flow.response:
        mask_message(flow.response)


def quiet_tls_crashes(record):
    """Drops mitmproxy's "has crashed!" tracebacks for connections that died mid-TLS.
    Only that one connection is lost; the capture keeps running."""
    exc = record.exc_info[1] if record.exc_info else None
    return not isinstance(exc, SSL.Error)


def make_har(flows, mask=True):
    """HAR of the given flows (copies are masked, the originals stay intact); notes become entry comments."""
    flows = [f.copy() for f in flows]
    if mask:
        for f in flows:
            redact(f)
    har = SaveHar().make_har(flows)
    for entry, f in zip(har["log"]["entries"], flows):
        if f.comment:
            entry["comment"] = f.comment
    return har


def read_settings():
    return json.loads(SETTINGS.read_text("utf-8-sig")) if SETTINGS.exists() else {}


def host_regex(text):
    """Plain domain -> regex. A value that already contains a backslash is a regex as-is."""
    return text if "\\" in text else re.escape(text)


def body_text(msg):
    """Decoded body, or None for binary. Streamed bodies are not stored."""
    if msg is None or not msg.raw_content:
        return ""
    content = msg.get_content(strict=False) or b""
    if strutils.is_mostly_bin(content[:2048]):
        return None
    return msg.get_text(strict=False)


class TlsPeek:
    def __init__(self):
        self.flows = []       # oldest first; ids are dropped + position
        self.dropped = 0
        self.ids = {}         # flow.id -> UI id
        self.seq = 0          # bumps on every change; the UI asks for changes since its last seq
        self.changed = {}     # flow.id -> seq of its last change
        self.rejected = {}    # host -> {"count", "last", "reason"} for failed client TLS handshakes
        self.paused = False
        self.server = None
        self.loop = None
        self.program = ""
        self.host_text = ""
        self.last_seen = None  # last UI request; None until a tab has connected
        self.bye_at = None     # when a tab last said it is closing
        self.watcher = None

    def load(self, loader):
        loader.add_option("redact", bool, False, "Mask credentials in flows (for HAR export).")
        loader.add_option("ui_port", int, 0, "Serve the tls-peek web UI on this port (0 = off).")
        loader.add_option("ui_file", str, "", "Session file shown read-only in the UI (open mode).")
        loader.add_option("ui_auto_stop", int, 0,
                          "Stop when no UI tab has been open for this many seconds (0 = never).")

    def running(self):
        self.loop = asyncio.get_running_loop()
        for h in logging.getLogger().handlers:
            h.addFilter(quiet_tls_crashes)
        if ctx.options.ui_port and not self.server:
            if not ctx.options.ui_file:
                settings = read_settings()
                self.apply(settings.get("program", ""), settings.get("host_filter", ""))
            self.server = ThreadingHTTPServer(("127.0.0.1", ctx.options.ui_port), make_handler(self))
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            if ctx.options.ui_auto_stop:
                self.watcher = asyncio.create_task(self.watch_ui())

    async def watch_ui(self):
        """Stops mitmproxy once every UI tab is gone: right after a tab closes (plus a
        grace period for refreshes), or when no tab has polled for ui_auto_stop seconds."""
        while True:
            await asyncio.sleep(2)
            if self.last_seen is None:
                continue
            now = time.time()
            closed = self.bye_at is not None and self.bye_at >= self.last_seen and now - self.bye_at > BYE_GRACE
            if closed or now - self.last_seen > ctx.options.ui_auto_stop:
                print("[tls-peek] No UI tab is open any more; stopping.")
                ctx.master.shutdown()
                return

    def seen(self, bye=False):
        if bye:
            self.bye_at = time.time()
        else:
            self.last_seen = time.time()

    def done(self):
        if self.server:
            self.server.shutdown()

    def tls_failed_client(self, data):
        # mitmproxy has already turned the OpenSSL error into one of these messages.
        err = data.conn.error or ""
        if "does not trust" in err:
            reason = "rejected"
        elif "disconnected during the handshake" in err:
            reason = "closed"
        else:
            return  # early closes and version mismatches are not about our certificate
        host = data.conn.sni or "unknown host"
        entry = self.rejected.setdefault(host, {"host": host, "count": 0, "reason": reason})
        entry["count"] += 1
        entry["last"] = time.time()
        if reason == "rejected":
            entry["reason"] = reason

    # --- flow tracking (event loop thread) ---

    def request(self, flow):
        self.touch(flow)

    def response(self, flow):
        if ctx.options.redact:
            redact(flow)
        self.touch(flow)

    def error(self, flow):
        self.touch(flow)

    def websocket_message(self, flow):
        self.touch(flow)

    def websocket_end(self, flow):
        self.touch(flow)

    def touch(self, flow, force=False):
        if not ctx.options.ui_port or (self.paused and not force and flow.id not in self.ids):
            return
        if flow.id in self.ids:
            # A saved session can hold a flow twice (re-saved after a note); keep the newest copy.
            i = self.ids[flow.id] - self.dropped
            if self.flows[i] is not flow:
                self.flows[i] = flow
        else:
            self.ids[flow.id] = self.dropped + len(self.flows)
            self.flows.append(flow)
            if len(self.flows) > MAX_FLOWS:
                old = self.flows.pop(0)
                self.dropped += 1
                self.ids.pop(old.id, None)
                self.changed.pop(old.id, None)
        self.seq += 1
        self.changed[flow.id] = self.seq

    def get(self, ui_id):
        i = ui_id - self.dropped
        return self.flows[i] if 0 <= i < len(self.flows) else None

    def summary(self, f):
        r = f.response
        if f.error:
            state = "error"
        elif r is None:
            state = "pending"
        else:
            state = "done"
        return {
            "id": self.ids[f.id],
            "time": f.request.timestamp_start,
            "method": f.request.method,
            "url": f.request.pretty_url,
            "host": f.request.pretty_host,
            "status": r.status_code if r else None,
            "state": state,
            "type": (r.headers.get("content-type", "") if r else "").split(";")[0],
            "size": len(r.raw_content or b"") if r else 0,
            "ms": round((r.timestamp_end - f.request.timestamp_start) * 1000) if r and r.timestamp_end else None,
            "error": f.error.msg if f.error else None,
            "ws": len(f.websocket.messages) if f.websocket else None,
            "replay": bool(f.is_replay),
            "marked": bool(f.marked),
            "note": f.comment,
        }

    # --- called from the UI thread ---

    def on_loop(self, fn):
        async def run():
            return fn()
        return asyncio.run_coroutine_threadsafe(run(), self.loop).result(timeout=10)

    def apply(self, program, host_filter):
        """Switch the captured program and host filter live. Runs on the event loop."""
        program = Path(program.strip()).name
        host_filter = host_filter.strip()
        ctx.options.update(
            mode=[f"local:{NO_PROGRAM if self.paused or not program else program}"],
            allow_hosts=[host_regex(host_filter)] if host_filter else [],
        )
        self.program, self.host_text = program, host_filter

    def set_paused(self, paused):
        """Paused: the program's new connections pass through untouched and nothing is recorded."""
        self.paused = paused
        if ctx.options.save_stream_file:
            ctx.options.update(save_stream_filter="!~all" if paused else "")
        self.apply(self.program, self.host_text)

    def state(self):
        return {
            "program": self.program,
            "host_filter": self.host_text,
            "file": Path(ctx.options.ui_file).name if ctx.options.ui_file else "",
            "paused": self.paused,
            "rejected": sorted(self.rejected.values(), key=lambda e: -e["last"]),
        }

    def configure_capture(self, program, host_filter):
        """Also saves the choice to settings.json."""
        self.on_loop(lambda: self.apply(program, host_filter))
        settings = read_settings()
        settings.update(program=self.program, host_filter=self.host_text)
        SETTINGS.write_text(json.dumps(settings, indent=2), "utf-8")

    def changes(self, since):
        flows = [f for f in list(self.flows) if self.changed.get(f.id, 0) > since]
        return {"seq": self.seq, "dropped": self.dropped, "flows": [self.summary(f) for f in flows]}

    def detail(self, f):
        def message(msg):
            if msg is None:
                return None
            body = body_text(msg)
            if msg.raw_content is None:
                body = "<body streamed, not stored>"
            elif body is None:
                body = f"<binary, {len(msg.raw_content)} bytes: pick a decoder such as protobuf or hex dump>"
            return {"headers": list(msg.headers.items(multi=True)),
                    "body": body[:MAX_BODY], "truncated": len(body) > MAX_BODY}

        ws = None
        if f.websocket:
            ws = [{"from_client": m.from_client, "time": m.timestamp,
                   "text": m.text if m.is_text else f"<binary, {len(m.content)} bytes>"}
                  for m in f.websocket.messages[-MAX_WS_MESSAGES:]]
        return {"summary": self.summary(f), "request": message(f.request),
                "response": message(f.response), "websocket": ws}

    def view(self, f, part, view_name):
        """Body decoded by one of mitmproxy's content views (protobuf, gRPC, msgpack, hex, ...)."""
        msg = f.request if part == "request" else f.response
        if msg is None or msg.raw_content is None:
            raise ValueError("no body")
        res = contentviews.prettify_message(msg, f, view_name)
        text = res.text or ""
        return {"text": text[:MAX_BODY], "truncated": len(text) > MAX_BODY, "view": res.view_name,
                "views": sorted(contentviews.registry.keys())}

    def search(self, q):
        q = q.lower()
        return [self.ids[f.id] for f in list(self.flows)
                if any(q in (body_text(m) or "").lower() for m in (f.request, f.response))
                or (f.websocket and any(m.is_text and q in m.text.lower() for m in f.websocket.messages))]

    def resend(self, ui_id, method, url, headers, body):
        """Sends an edited copy of a flow; the result shows up as a new row."""
        src = self.get(ui_id)
        if src is None:
            raise ValueError("flow gone")

        def go():
            f = src.copy()
            f.request.method = method
            f.request.url = url
            f.request.headers.clear()
            for k, v in headers:
                f.request.headers.add(k, v)
            f.request.text = body
            f.response = f.error = f.websocket = None
            ctx.master.commands.call("replay.client", [f])
            self.touch(f, force=True)  # show it as pending right away, even when paused
            return self.ids[f.id]

        return self.on_loop(go)

    def mark(self, ui_id, marked=None, note=None):
        """Bookmark and note a flow. In a live capture the flow is saved again, so the
        session file keeps them (the newest copy of a flow wins when it is read back)."""
        f = self.get(ui_id)
        if f is None:
            raise ValueError("flow gone")

        def go():
            if marked is not None:
                f.marked = ":star:" if marked else ""
            if note is not None:
                f.comment = note
            save = ctx.master.addons.get("save")
            if save and save.stream and not f.live:
                save.save_flow(f)
            self.touch(f, force=True)

        self.on_loop(go)

    def har(self):
        return make_har([f for f in list(self.flows) if f.response])


def make_handler(addon):
    import mitmproxy_rs.process_info as pinfo

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, code, body, ctype="application/json", headers=()):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def allowed(self):
            # Blocks DNS rebinding: only accept requests addressed to our own origin.
            port = self.server.server_address[1]
            ok = self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")
            if not ok:
                self.send(403, {"error": "bad host"})
            return ok

        def do_GET(self):
            if not self.allowed():
                return
            addon.seen()
            url = urlparse(self.path)
            q = parse_qs(url.query)
            if url.path == "/":
                self.send(200, (HERE / "ui.html").read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/api/state":
                self.send(200, addon.state())
            elif url.path == "/api/flows":
                self.send(200, addon.changes(int(q.get("since", ["0"])[0])))
            elif url.path.startswith("/api/flow/"):
                f = addon.get(int(url.path.rsplit("/", 1)[1]))
                if f is None:
                    return self.send(404, {"error": "flow gone"})
                self.send(200, addon.detail(f))
            elif url.path.startswith("/api/body/") or url.path.startswith("/api/view/"):
                f = addon.get(int(url.path.rsplit("/", 1)[1]))
                part = q.get("part", ["response"])[0]
                msg = None if f is None else f.request if part == "request" else f.response
                if msg is None or msg.raw_content is None:
                    return self.send(404, {"error": "no body"})
                if url.path.startswith("/api/view/"):
                    return self.send(200, addon.view(f, part, q.get("view", ["auto"])[0]))
                # Raw body for image and HTML previews. The CSP sandboxes it and blocks every
                # external load, so a previewed page cannot run scripts or phone home.
                self.send(200, msg.get_content(strict=False) or b"",
                          msg.headers.get("content-type", "application/octet-stream"), [
                              ("Content-Security-Policy", "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'"),
                              ("X-Content-Type-Options", "nosniff")])
            elif url.path == "/api/search":
                self.send(200, addon.search(q.get("q", [""])[0]))
            elif url.path == "/api/processes":
                procs = [{"name": p.executable.name, "display": p.display_name, "path": str(p.executable)}
                         for p in pinfo.active_executables()
                         if not p.is_system and (p.is_visible or "all" in q)]
                self.send(200, sorted({p["name"]: p for p in procs}.values(), key=lambda p: p["display"].lower()))
            elif url.path == "/api/icon":
                try:
                    self.send(200, pinfo.executable_icon(q["path"][0]), "image/png",
                              [("Cache-Control", "max-age=3600")])
                except Exception:
                    self.send(404, b"", "image/png")
            elif url.path == "/api/har":
                self.send(200, addon.har(), headers=[
                    ("Content-Disposition", f'attachment; filename="tlspeek-{time.strftime("%Y%m%d-%H%M%S")}.har"')])
            else:
                self.send(404, {"error": "not found"})

        def do_POST(self):
            if not self.allowed():
                return
            # JSON content type forces a CORS preflight, so other sites cannot post here.
            if self.headers.get("Content-Type") != "application/json":
                return self.send(400, {"error": "bad request"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                if self.path == "/api/config":
                    if ctx.options.ui_file:
                        raise ValueError("viewing a saved session")
                    addon.configure_capture(body.get("program", ""), body.get("host_filter", ""))
                    return self.send(200, addon.state())
                if self.path == "/api/bye":
                    addon.seen(bye=True)
                    return self.send(200, {})
                addon.seen()
                if self.path == "/api/stop":
                    self.send(200, {})
                    addon.loop.call_soon_threadsafe(ctx.master.shutdown)
                    return
                if self.path == "/api/pause":
                    if ctx.options.ui_file:
                        raise ValueError("viewing a saved session")
                    addon.on_loop(lambda: addon.set_paused(bool(body.get("paused"))))
                    return self.send(200, addon.state())
                if self.path == "/api/mark":
                    addon.mark(int(body["id"]), body.get("marked"), body.get("note"))
                    return self.send(200, {})
                if self.path == "/api/resend":
                    new_id = addon.resend(int(body["id"]), body["method"], body["url"],
                                          body.get("headers", []), body.get("body", ""))
                    return self.send(200, {"id": new_id})
                self.send(404, {"error": "not found"})
            except Exception as e:
                self.send(400, {"error": str(e)})

    return Handler


addons = [TlsPeek()]
