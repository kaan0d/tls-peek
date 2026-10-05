"""mitmproxy addon for tls-peek.

Serves the web UI (ui folder) on 127.0.0.1 when ui_port > 0: pick the program,
set the host filter, inspect, search, filter and resend traffic. Warns when the
monitored program rejects the mitmproxy certificate (pinning).

With redact=true it masks credentials in every flow (used for HAR export).
"""
import asyncio
import ctypes
import json
import logging
import re
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from mitmproxy import contentviews, ctx, http
from OpenSSL import SSL

import apimap
import findings
import observe
from export import body_text, make_har, make_postman, redact
from web import UI_DIR, LocalHandler

HERE = Path(__file__).resolve().parent
# settings.json and captures\ live next to tlspeek.exe when frozen, else in the folder above app\.
APP_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) else HERE.parent
SETTINGS = APP_DIR / "settings.json"
CONFDIR = APP_DIR / ".mitmproxy"
CAPTURES = APP_DIR / "captures"
MAX_FLOWS = 5000  # ponytail: oldest flows drop from the UI past this; the .mitm file keeps all
MAX_BODY = 200_000
MAX_WS_MESSAGES = 1000
NO_PROGRAM = "tlspeek-no-program.exe"  # local mode needs a target; this matches nothing
BYE_GRACE = 10  # seconds a closed tab has to come back (a refresh) before auto-stop


def quiet_tls_crashes(record):
    """Drops mitmproxy's "has crashed!" tracebacks for connections that died mid-TLS.
    Only that one connection is lost; the capture keeps running."""
    exc = record.exc_info[1] if record.exc_info else None
    return not isinstance(exc, SSL.Error)


def read_settings():
    return json.loads(SETTINGS.read_text("utf-8-sig")) if SETTINGS.exists() else {}


def save_settings(**changes):
    settings = read_settings()
    settings.update(changes)
    SETTINGS.write_text(json.dumps(settings, indent=2), "utf-8")


def matches(rule, flow):
    """URL substring (any case) and method of an intercept or rewrite rule; empty matches all."""
    return ((not rule["url"] or rule["url"].lower() in flow.request.pretty_url.lower())
            and (not rule["method"] or flow.request.method.upper() == rule["method"]))


def clean_rule(r):
    """A rewrite rule from the UI, checked and with every field present."""
    action = r.get("action")
    if action not in ("header", "replace", "respond"):
        raise ValueError(f"unknown rule action {action!r}")
    rule = {
        "enabled": bool(r.get("enabled", True)),
        "url": str(r.get("url", "")).strip(),
        "method": str(r.get("method", "")).strip().upper(),
        # respond answers instead of the server, so it always runs on the request
        "phase": "response" if r.get("phase") == "response" and action != "respond" else "request",
        "action": action,
        "name": str(r.get("name", "")).strip(),
        "value": str(r.get("value", "")),
        "find": str(r.get("find", "")),
        "replace": str(r.get("replace", "")),
        "status": int(r.get("status") or 200),
        "type": str(r.get("type", "")).strip() or "application/json",
        "body": str(r.get("body", "")),
    }
    if action == "header" and not rule["name"]:
        raise ValueError("a header rule needs a header name")
    if action == "replace" and not rule["find"]:
        raise ValueError("a replace rule needs text to find")
    if not 100 <= rule["status"] <= 599:
        raise ValueError("status must be between 100 and 599")
    return rule


def host_regex(text):
    """Plain domain -> regex. A value that already contains a backslash is a regex as-is."""
    return text if "\\" in text else re.escape(text)


class TlsPeek:
    def __init__(self):
        self.flows = []       # oldest first; ids are dropped + position
        self.dropped = 0
        self.ids = {}         # flow.id -> UI id
        self.seq = 0          # bumps on every change; the UI asks for changes since its last seq
        self.changed = {}     # flow.id -> seq of its last change
        self.rejected = {}    # host -> {"count", "last", "reason"} for failed client TLS handshakes
        self.paused = False
        # Intercept rule: hold matching requests and/or responses until the UI releases them.
        self.icpt = {"enabled": False, "url": "", "method": "", "request": True, "response": False}
        self.rules = []       # rewrite rules (clean_rule), applied in order, saved in settings.json
        self.server = None
        self.loop = None
        self.program = ""
        self.host_text = ""
        self.last_program = ""  # from settings.json; the UI offers it, nothing is captured until a pick
        self.last_seen = None  # last UI request; None until a tab has connected
        self.bye_at = None     # when a tab last said it is closing
        self.watcher = None
        self.opened_by = {}   # server connection id -> flow id that opened it (gets connect/TLS time)

    def load(self, loader):
        loader.add_option("redact", bool, False, "Mask credentials in flows (for HAR export).")
        loader.add_option("ui_port", int, 0, "Serve the tls-peek web UI on this port (0 = off).")
        loader.add_option("ui_file", str, "", "Session file shown read-only in the UI (open mode).")
        loader.add_option("ui_home", str, "", "URL of the start page this UI returns to when stopped.")
        loader.add_option("ui_auto_stop", int, 0,
                          "Stop when no UI tab has been open for this many seconds (0 = never).")

    def running(self):
        self.loop = asyncio.get_running_loop()
        for h in logging.getLogger().handlers:
            h.addFilter(quiet_tls_crashes)
        if ctx.options.ui_port and not self.server:
            try:
                self.rules = [clean_rule(r) for r in read_settings().get("rewrite_rules", [])]
            except (ValueError, TypeError, AttributeError) as e:
                print(f"[tls-peek] Ignoring rewrite rules in settings.json: {e}")
            if not ctx.options.ui_file and ctx.options.mode[0].startswith("local"):
                settings = read_settings()
                self.last_program = settings.get("program", "")
                self.apply("", settings.get("host_filter", ""))
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
        self.apply_rules(flow, "request")
        self.hold_if_matching(flow, "request")
        self.touch(flow)

    def response(self, flow):
        if ctx.options.redact:
            redact(flow)
        self.apply_rules(flow, "response")
        self.hold_if_matching(flow, "response")
        self.touch(flow)

    # --- rewrite rules ---

    def apply_rules(self, flow, phase):
        """Changes matching traffic automatically, without holding it."""
        if not self.rules or ctx.options.ui_file or flow.is_replay:
            return
        if phase == "response" and flow.metadata.get("tlspeek_answered"):
            return  # a rule answered it already
        msg = flow.request if phase == "request" else flow.response
        applied = 0
        for r in self.rules:
            if not r["enabled"] or r["phase"] != phase or not matches(r, flow):
                continue
            applied += 1
            if r["action"] == "respond":
                flow.response = http.Response.make(r["status"], r["body"], {"content-type": r["type"]})
                flow.metadata["tlspeek_answered"] = True
                break
            if r["action"] == "header":
                if r["value"]:
                    msg.headers[r["name"]] = r["value"]
                else:
                    msg.headers.pop(r["name"], None)
            else:
                if phase == "request":
                    flow.request.url = flow.request.url.replace(r["find"], r["replace"])
                text = body_text(msg) if msg.raw_content else None
                if text:
                    msg.text = text.replace(r["find"], r["replace"])
        if applied:
            flow.metadata["tlspeek_rules"] = flow.metadata.get("tlspeek_rules", 0) + applied
            if phase == "response":
                self.resave(flow)

    def set_rules(self, rules):
        self.rules = [clean_rule(r) for r in rules]
        save_settings(rewrite_rules=self.rules)

    def resave(self, flow):
        """The session file got the response before we changed it; save what the program received."""
        save = ctx.master.addons.get("save")
        if save and save.stream:
            save.save_flow(flow)

    # --- intercept ---

    def hold_if_matching(self, flow, phase):
        """Holds the flow (the program waits) when it matches the intercept rule."""
        r = self.icpt
        if not r["enabled"] or not r[phase] or self.paused or flow.is_replay or not ctx.options.ui_port or not matches(r, flow):
            return
        flow.intercept()

    def set_intercept(self, rule):
        self.icpt = {
            "enabled": bool(rule.get("enabled")),
            "url": str(rule.get("url", "")).strip(),
            "method": str(rule.get("method", "")).strip().upper(),
            "request": bool(rule.get("request", True)),
            "response": bool(rule.get("response", False)),
        }
        if not self.icpt["enabled"]:
            self.on_loop(self.release_all)

    def release(self, ui_id, drop=False, request=None, response=None):
        """Lets a held flow go on, with the edits made in the UI, or drops it."""
        f = self.get(ui_id)
        if f is None or not f.intercepted:
            raise ValueError("this request is no longer held")

        def go():
            if not f.intercepted:
                raise ValueError("this request is no longer held")
            phase = "response" if f.response else "request"
            edits = response if phase == "response" else request
            if edits and not drop:
                msg = f.response if phase == "response" else f.request
                if phase == "response":
                    msg.status_code = int(edits["status"])
                else:
                    msg.method = edits["method"]
                    msg.url = edits["url"]
                msg.headers.clear()
                for k, v in edits.get("headers", []):
                    msg.headers.add(k, v)
                if edits.get("body") is not None:  # None: binary or too big to edit, keep as is
                    msg.text = edits["body"]
                f.metadata.setdefault("tlspeek_edited", []).append(phase)
            # kill() alone would leave the proxy waiting on the hold forever: release, then kill.
            f.resume()
            if drop:
                f.kill()
            elif edits and phase == "response":
                self.resave(f)
            self.touch(f, force=True)

        self.on_loop(go)

    def release_all(self):
        for f in list(self.flows):
            if f.intercepted:
                f.resume()
                self.touch(f, force=True)

    def error(self, flow):
        self.touch(flow)

    def websocket_message(self, flow):
        self.touch(flow)

    def websocket_end(self, flow):
        self.touch(flow)

    # Non-HTTP traffic is listed too: raw TCP and UDP streams and DNS lookups.
    def tcp_start(self, flow):
        self.touch(flow)

    tcp_message = tcp_end = tcp_error = udp_start = udp_message = udp_end = udp_error = tcp_start
    dns_request = dns_response = dns_error = tcp_start

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
        sc = flow.server_conn
        if sc and sc.timestamp_tcp_setup and sc.id not in self.opened_by:
            self.opened_by[sc.id] = flow.id
        self.seq += 1
        self.changed[flow.id] = self.seq

    def opened_here(self, f):
        return self.opened_by.get(f.server_conn.id) == f.id

    def get(self, ui_id):
        i = ui_id - self.dropped
        return self.flows[i] if 0 <= i < len(self.flows) else None

    def summary(self, f):
        base = {
            "id": self.ids[f.id],
            "kind": f.type,
            "error": f.error.msg if f.error else None,
            "replay": bool(f.is_replay),
            "marked": bool(f.marked),
            "note": f.comment,
            "edited": f.metadata.get("tlspeek_edited", []),
            "rules": f.metadata.get("tlspeek_rules", 0),
            "ip": f.server_conn.peername[0] if f.server_conn.peername else None,
            "tls": f.server_conn.tls_version,
        }
        if f.type != "http":
            return {**base, "status": None, "ws": None, "held": None, "http": None, "phases": None, **observe.raw_fields(f)}
        r = f.response
        if f.intercepted:
            state = "held"
        elif f.error:
            state = "error"
        elif r is None or not r.timestamp_end:  # no response yet, or its body is still arriving
            state = "pending"
        else:
            state = "done"
        return {
            **base,
            "time": f.request.timestamp_start,
            "method": f.request.method,
            "url": f.request.pretty_url,
            "host": f.request.pretty_host,
            "status": r.status_code if r else None,
            "state": state,
            "type": (r.headers.get("content-type", "") if r else "").split(";")[0],
            "size": len(r.raw_content or b"") if r else 0,
            "ms": round((r.timestamp_end - f.request.timestamp_start) * 1000) if r and r.timestamp_end else None,
            "ws": len(f.websocket.messages) if f.websocket else None,
            "held": ("response" if r else "request") if f.intercepted else None,
            "http": f.request.http_version,
            "phases": observe.timing(f, self.opened_here(f)) if r and r.timestamp_end else None,
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
            "last_program": self.last_program,
            "host_filter": self.host_text,
            "file": Path(ctx.options.ui_file).name if ctx.options.ui_file else "",
            "paused": self.paused,
            "home": ctx.options.ui_home,
            "intercept": self.icpt,
            "rules": self.rules,
            "held": sum(1 for f in list(self.flows) if f.intercepted),
            "rejected": sorted(self.rejected.values(), key=lambda e: -e["last"]),
        }

    def configure_capture(self, program, host_filter):
        """Also saves the choice to settings.json."""
        self.on_loop(lambda: self.apply(program, host_filter))
        if self.program:
            self.last_program = self.program
        save_settings(program=self.last_program, host_filter=self.host_text)

    def changes(self, since):
        flows = [f for f in list(self.flows) if self.changed.get(f.id, 0) > since]
        return {"seq": self.seq, "dropped": self.dropped, "flows": [self.summary(f) for f in flows]}

    def detail(self, f):
        if f.type != "http":
            return {"summary": self.summary(f), "connection": observe.connection(f, self.opened_here(f)), **observe.raw_detail(f)}

        def message(msg):
            if msg is None:
                return None
            body = body_text(msg)
            editable = body is not None and msg.raw_content is not None and len(body) <= MAX_BODY
            if msg.raw_content is None:
                body = "<body streamed, not stored>"
            elif body is None:
                body = f"<binary, {len(msg.raw_content)} bytes: pick a decoder such as protobuf or hex dump>"
            return {"headers": list(msg.headers.items(multi=True)),
                    "body": body[:MAX_BODY], "truncated": len(body) > MAX_BODY, "editable": editable}

        ws = None
        if f.websocket:
            ws = [{"from_client": m.from_client, "time": m.timestamp,
                   "text": m.text if m.is_text else f"<binary, {len(m.content)} bytes>"}
                  for m in f.websocket.messages[-MAX_WS_MESSAGES:]]
        return {"summary": self.summary(f), "connection": observe.connection(f, self.opened_here(f)),
                "request": message(f.request),
                "response": message(f.response), "websocket": ws}

    def view(self, f, part, view_name):
        """Body decoded by one of mitmproxy's content views (protobuf, gRPC, msgpack, hex, ...)."""
        msg = None if f.type != "http" else f.request if part == "request" else f.response
        if msg is None or msg.raw_content is None:
            raise ValueError("no body")
        res = contentviews.prettify_message(msg, f, view_name)
        text = res.text or ""
        return {"text": text[:MAX_BODY], "truncated": len(text) > MAX_BODY, "view": res.view_name,
                "views": sorted(contentviews.registry.keys())}

    def search(self, q):
        q = q.lower()

        def hit(f):
            if f.type in ("tcp", "udp"):
                return any(q in m.content.decode("utf-8", "replace").lower() for m in f.messages)
            if f.type != "http":
                return False
            return (any(q in (body_text(m) or "").lower() for m in (f.request, f.response))
                    or (f.websocket and any(m.is_text and q in m.text.lower() for m in f.websocket.messages)))

        return [self.ids[f.id] for f in list(self.flows) if hit(f)]

    def resend(self, ui_id, method, url, headers, body):
        """Sends an edited copy of a flow; the result shows up as a new row."""
        src = self.get(ui_id)
        if src is None or src.type != "http":
            raise ValueError("flow gone" if src is None else "only HTTP requests can be resent")

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

    def export(self, fmt, ids=None, mask=True):
        """HAR or Postman collection of the given UI ids (all when None)."""
        flows = [f for f in (list(self.flows) if ids is None else map(self.get, ids)) if f is not None and f.type == "http"]
        if fmt == "postman":
            return make_postman(flows, mask)
        return make_har([f for f in flows if f.response], mask)


def make_handler(addon):
    import mitmproxy_rs.process_info as pinfo

    class Handler(LocalHandler):
        def do_GET(self):
            if not self.allowed():
                return
            try:
                self.get()
            except (ValueError, KeyError) as e:  # a malformed id or query
                self.send(400, {"error": str(e)})

        def get(self):
            if not self.headers.get("X-Tlspeek-Tray"):
                addon.seen()
            url = urlparse(self.path)
            q = parse_qs(url.query)
            if url.path == "/":
                self.send(200, (UI_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif self.send_static(url.path):
                pass
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
                msg = None if f is None or f.type != "http" else f.request if part == "request" else f.response
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
            elif url.path.startswith("/api/raw/"):
                f = addon.get(int(url.path.rsplit("/", 1)[1]))
                if f is None or f.type != "http":
                    return self.send(404, {"error": "no HTTP request with this id"})
                self.send(200, observe.wire(f))
            elif url.path == "/api/endpoints":
                self.send(200, apimap.endpoints(list(addon.flows), dict(addon.ids)))
            elif url.path == "/api/openapi":
                host = q["host"][0]
                spec = apimap.openapi(apimap.endpoints(list(addon.flows), dict(addon.ids)), host)
                name = re.sub(r"[^\w.-]", "_", host) + ".openapi.json"
                self.send(200, spec, headers=[("Content-Disposition", f'attachment; filename="{name}"')])
            elif url.path == "/api/findings":
                self.send(200, findings.check(list(addon.flows), dict(addon.ids)))
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
            else:
                self.send(404, {"error": "not found"})

        def do_POST(self):
            if not self.allowed():
                return
            try:
                body = self.json_body()
                if self.path == "/api/config":
                    if ctx.options.ui_file:
                        raise ValueError("viewing a saved session")
                    addon.configure_capture(body.get("program", ""), body.get("host_filter", ""))
                    return self.send(200, addon.state())
                if self.path == "/api/bye":
                    addon.seen(bye=True)
                    return self.send(200, {})
                if not self.headers.get("X-Tlspeek-Tray"):
                    addon.seen()
                if self.path == "/api/console":
                    # The tray icon shows or hides this process's log window.
                    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
                    if hwnd:
                        ctypes.windll.user32.ShowWindow(hwnd, 5 if body.get("show") else 0)
                    return self.send(200, {})
                if self.path == "/api/stop":
                    self.send(200, {})
                    addon.loop.call_soon_threadsafe(ctx.master.shutdown)
                    return
                if self.path == "/api/intercept":
                    if ctx.options.ui_file:
                        raise ValueError("viewing a saved session")
                    addon.set_intercept(body)
                    return self.send(200, addon.state())
                if self.path == "/api/rules":
                    if ctx.options.ui_file:
                        raise ValueError("viewing a saved session")
                    addon.on_loop(lambda: addon.set_rules(body.get("rules", [])))
                    return self.send(200, addon.state())
                if self.path == "/api/release":
                    addon.release(int(body["id"]), bool(body.get("drop")), body.get("request"), body.get("response"))
                    return self.send(200, {})
                if self.path == "/api/release-all":
                    addon.on_loop(addon.release_all)
                    return self.send(200, {})
                if self.path == "/api/pause":
                    if ctx.options.ui_file:
                        raise ValueError("viewing a saved session")
                    addon.on_loop(lambda: addon.set_paused(bool(body.get("paused"))))
                    return self.send(200, addon.state())
                if self.path == "/api/mark":
                    addon.mark(int(body["id"]), body.get("marked"), body.get("note"))
                    return self.send(200, {})
                if self.path == "/api/export":
                    fmt = "postman" if body.get("format") == "postman" else "har"
                    data = addon.export(fmt, body.get("ids"), body.get("mask", True) is not False)
                    name = f'tlspeek-{time.strftime("%Y%m%d-%H%M%S")}' + (".postman_collection.json" if fmt == "postman" else ".har")
                    return self.send(200, data, headers=[("Content-Disposition", f'attachment; filename="{name}"')])
                if self.path == "/api/resend":
                    new_id = addon.resend(int(body["id"]), body["method"], body["url"],
                                          body.get("headers", []), body.get("body", ""))
                    return self.send(200, {"id": new_id})
                self.send(404, {"error": "not found"})
            except Exception as e:
                self.send(400, {"error": str(e)})

    return Handler


addons = [TlsPeek()]
