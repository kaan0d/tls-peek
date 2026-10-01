"""mitmproxy addon for tls-peek.

Live capture (option ui_port > 0): serves the tls-peek web UI (ui.html) on
127.0.0.1 to pick the program, set the host filter and inspect traffic. Warns
when the monitored program rejects the mitmproxy certificate (pinning).

Export (option redact=true): masks credentials in every flow before the HAR is
written, e.g.
  mitmdump -nr capture.mitm -s tlspeek.py --set redact=true --set hardump=out.har
"""
import asyncio
import json
import logging
import re
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

from mitmproxy import ctx, http
from mitmproxy.addons.savehar import SaveHar

HERE = Path(__file__).parent
SETTINGS = HERE / "settings.json"
# Header, query, form and JSON key names whose values get masked.
SECRET = re.compile(r"auth|cookie|token|pass|secret|key|session|user|login|code|sig", re.I)
MASK = "***"
MAX_FLOWS = 5000  # ponytail: oldest flows drop from the UI past this; the .mitm file keeps all
MAX_BODY = 200_000
NO_PROGRAM = "tlspeek-no-program.exe"  # local mode needs a target; this matches nothing


def mask_json(obj):
    if isinstance(obj, dict):
        return {k: MASK if SECRET.search(k) else mask_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_json(v) for v in obj]
    return obj


def mask_message(msg):
    for name in list(msg.headers):
        if SECRET.search(name):
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
        msg.text = urlencode([(k, MASK if SECRET.search(k) else v) for k, v in pairs])


def redact(flow):
    req = flow.request
    req.query = [(k, MASK if SECRET.search(k) else v) for k, v in req.query.items(multi=True)]
    mask_message(req)
    if flow.response:
        mask_message(flow.response)


def read_settings():
    return json.loads(SETTINGS.read_text("utf-8-sig")) if SETTINGS.exists() else {}


def host_regex(text):
    """Plain domain -> regex. A value that already contains a backslash is a regex as-is."""
    return text if "\\" in text else re.escape(text)


def summary(i, f):
    r = f.response
    return {
        "id": i,
        "time": f.request.timestamp_start,
        "method": f.request.method,
        "url": f.request.pretty_url,
        "host": f.request.pretty_host,
        "status": r.status_code if r else None,
        "type": (r.headers.get("content-type", "") if r else "").split(";")[0],
        "size": len(r.raw_content or b"") if r else 0,
        "ms": round((r.timestamp_end - f.request.timestamp_start) * 1000) if r and r.timestamp_end else None,
        "error": f.error.msg if f.error else None,
    }


def message_detail(msg):
    if msg is None:
        return None
    body = msg.get_text(strict=False) if msg.raw_content else ""
    if body is None:
        body = f"<binary, {len(msg.raw_content)} bytes>"
    return {
        "headers": list(msg.headers.items(multi=True)),
        "body": body[:MAX_BODY],
        "truncated": len(body) > MAX_BODY,
    }


class TlsPeek:
    def __init__(self):
        self.flows = []
        self.dropped = 0
        self.events = []
        self.server = None
        self.loop = None
        self.program = ""
        self.host_text = ""

    def load(self, loader):
        loader.add_option("redact", bool, False, "Mask credentials in flows (for HAR export).")
        loader.add_option("ui_port", int, 0, "Serve the tls-peek web UI on this port (0 = off).")
        loader.add_option("ui_open", bool, True, "Open the web UI in the browser on start.")

    def running(self):
        self.loop = asyncio.get_running_loop()
        if ctx.options.ui_port and not self.server:
            settings = read_settings()
            self.apply(settings.get("program", ""), settings.get("host_filter", ""))
            self.server = ThreadingHTTPServer(("127.0.0.1", ctx.options.ui_port), make_handler(self))
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            if ctx.options.ui_open:
                webbrowser.open(f"http://127.0.0.1:{ctx.options.ui_port}")

    def done(self):
        if self.server:
            self.server.shutdown()

    def tls_failed_client(self, data):
        sni = data.conn.sni or "unknown host"
        msg = (f"Program rejected the mitmproxy certificate for {sni}: probably certificate "
               "pinning. Traffic to this host cannot be decrypted.")
        logging.warning(f"[tls-peek] {msg}")
        self.events.append({"time": time.time(), "msg": msg})

    def response(self, flow):
        if ctx.options.redact:
            redact(flow)
        self.keep(flow)

    def error(self, flow):
        self.keep(flow)

    def keep(self, flow):
        if not ctx.options.ui_port:
            return
        self.flows.append(flow)
        if len(self.flows) > MAX_FLOWS:
            del self.flows[0]
            self.dropped += 1

    # --- called from the UI thread ---

    def apply(self, program, host_filter):
        """Switch the captured program and host filter live. Runs on the event loop."""
        program = Path(program.strip()).name
        host_filter = host_filter.strip()
        ctx.options.update(
            mode=[f"local:{program or NO_PROGRAM}"],
            allow_hosts=[host_regex(host_filter)] if host_filter else [],
        )
        self.program, self.host_text = program, host_filter

    def state(self):
        return {"program": self.program, "host_filter": self.host_text, "events": self.events[-20:]}

    def configure_capture(self, program, host_filter):
        """Called from the UI thread; also saves the choice to settings.json."""
        async def run():
            self.apply(program, host_filter)

        asyncio.run_coroutine_threadsafe(run(), self.loop).result(timeout=10)
        settings = read_settings()
        settings.update(program=self.program, host_filter=self.host_text)
        SETTINGS.write_text(json.dumps(settings, indent=2), "utf-8")

    def har(self):
        flows = [f.copy() for f in self.flows]
        for f in flows:
            redact(f)
        return SaveHar().make_har(flows)


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
            url = urlparse(self.path)
            q = parse_qs(url.query)
            if url.path == "/":
                self.send(200, (HERE / "ui.html").read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/api/state":
                self.send(200, addon.state())
            elif url.path == "/api/flows":
                since = int(q.get("since", ["0"])[0])
                start = max(since - addon.dropped, 0)
                flows = addon.flows[start:]
                self.send(200, [summary(addon.dropped + start + i, f) for i, f in enumerate(flows)])
            elif url.path.startswith("/api/flow/"):
                i = int(url.path.rsplit("/", 1)[1]) - addon.dropped
                if not 0 <= i < len(addon.flows):
                    return self.send(404, {"error": "flow gone"})
                f = addon.flows[i]
                self.send(200, {"summary": summary(i + addon.dropped, f),
                                "request": message_detail(f.request),
                                "response": message_detail(f.response)})
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
            if self.path != "/api/config" or self.headers.get("Content-Type") != "application/json":
                return self.send(400, {"error": "bad request"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                addon.configure_capture(body.get("program", ""), body.get("host_filter", ""))
            except Exception as e:
                return self.send(400, {"error": str(e)})
            self.send(200, addon.state())

    return Handler


addons = [TlsPeek()]
