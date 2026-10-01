"""Checks redaction, HAR export and the UI server API.

Run: python test_tlspeek.py   (needs mitmproxy installed)
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mitmproxy import io
from mitmproxy.test import tflow, tutils

import addon
import tlspeek

here = pathlib.Path(__file__).parent
tmp = pathlib.Path(tempfile.mkdtemp())

# --- field-name matching ---
for name in ("Authorization", "X-Api-Key", "accessToken", "PASSWORD", "user_name", "sessionId", "Set-Cookie"):
    assert addon.is_secret(name), name
for name in ("User-Agent", "monkey", "design", "keyword", "Content-Type", "page"):
    assert not addon.is_secret(name), name

# --- redacted HAR export ---
f = tflow.tflow(
    req=tutils.treq(
        method=b"POST", path=b"/login?token=QTOKEN&page=2",
        headers=[(b"authorization", b"Bearer HTOKEN"), (b"content-type", b"application/json"),
                 (b"user-agent", b"KeepMe/1.0")],
        content=b'{"username": "alice", "password": "PW", "data": {"apiKey": "K", "n": 1}}',
    ),
    resp=tutils.tresp(headers=[(b"set-cookie", b"sid=SID")], content=b"ok"),
)
pending = tflow.tflow(req=tutils.treq(path=b"/slow"))  # no response yet
with open(tmp / "c.mitm", "wb") as fo:
    w = io.FlowWriter(fo)
    w.add(f)
    w.add(pending)

tlspeek.export_har(tmp / "c")
har = (tmp / "c.har").read_text()
for secret in ("QTOKEN", "HTOKEN", "alice", "PW", '"K"', "SID"):
    assert secret not in har, f"{secret} leaked into HAR"
entry = json.loads(har)["log"]["entries"][0]
assert "page=2" in entry["request"]["url"] and '"n": 1' in entry["request"]["postData"]["text"]
assert "KeepMe/1.0" in har
print("redaction ok")

# --- console noise and certificate warnings ---
import logging
from types import SimpleNamespace
from OpenSSL import SSL

try:
    raise SSL.Error([])
except SSL.Error:
    rec = logging.LogRecord("x", logging.ERROR, "", 0, "mitmproxy has crashed!", None, sys.exc_info())
assert not addon.quiet_tls_crashes(rec)
assert addon.quiet_tls_crashes(logging.LogRecord("x", logging.ERROR, "", 0, "other", None, None))

peek = addon.TlsPeek()
for sni, err in [("a.com", "The client does not trust the proxy's certificate for a.com (unknown ca)"),
                 ("a.com", "The client does not trust the proxy's certificate for a.com (unknown ca)"),
                 ("b.com", "The client disconnected during the handshake. If this happens ..."),
                 ("c.com", "connection closed early")]:
    peek.tls_failed_client(SimpleNamespace(conn=SimpleNamespace(sni=sni, error=err)))
assert peek.rejected["a.com"]["count"] == 2 and peek.rejected["a.com"]["reason"] == "rejected"
assert peek.rejected["b.com"]["reason"] == "closed" and "c.com" not in peek.rejected
print("warnings ok")


# --- UI server ---
class Echo(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"echo:" + body)

    def log_message(self, *args):
        pass


echo = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
threading.Thread(target=echo.serve_forever, daemon=True).start()
port = tlspeek.free_port()
settings_before = (here / "settings.json").read_bytes()
mitmdump = pathlib.Path(sys.executable).with_name("mitmdump")
srv = subprocess.Popen(
    [mitmdump, "-q", "-n", "-r", tmp / "c.mitm", "--set", "keepserving=true",
     "--set", f"confdir={tmp / 'conf'}", "--mode", f"local:{addon.NO_PROGRAM}",
     "-s", here / "addon.py", "--set", f"ui_port={port}", "--save-stream-file", tmp / "saved.mitm"],
)


def call(path, data=None, host=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 headers={"Content-Type": "application/json"} if data else {})
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def post(path, obj):
    return call(path, json.dumps(obj).encode())


try:
    for _ in range(50):
        try:
            if len(call("/api/flows")[1]["flows"]) == 2:
                break
        except OSError:
            pass
        time.sleep(0.2)
    status, ch = call("/api/flows")
    done, slow = ch["flows"]
    assert done["state"] == "done" and done["status"] == 200 and slow["state"] == "pending", ch
    assert call(f"/api/flows?since={ch['seq']}")[1]["flows"] == []
    status, detail = call(f"/api/flow/{done['id']}")
    assert "HTOKEN" in json.dumps(detail["request"]), "live view must show unredacted data"
    assert call("/api/search?q=alice")[1] == [done["id"]]
    assert call("/api/state", host="evil.example:80")[0] == 403
    assert call("/api/config", data=b"{not json")[0] == 400

    status, state = post("/api/config", {"program": r"C:\x\Some App.exe", "host_filter": "api.example.com"})
    assert status == 200 and state["program"] == "Some App.exe", state
    assert json.loads((here / "settings.json").read_text("utf-8"))["program"] == "Some App.exe"

    status, state = post("/api/pause", {"paused": True})
    assert status == 200 and state["paused"], state
    status, state = post("/api/pause", {"paused": False})
    assert status == 200 and not state["paused"], state

    status, res = post("/api/resend", {"id": done["id"], "method": "POST",
                                       "url": f"http://127.0.0.1:{echo.server_address[1]}/x",
                                       "headers": [["content-type", "text/plain"]], "body": "hello"})
    assert status == 200, res
    for _ in range(50):
        resent = call(f"/api/flow/{res['id']}")[1]
        if resent["summary"]["state"] != "pending":
            break
        time.sleep(0.2)
    assert resent["summary"]["replay"] and resent["response"]["body"] == "echo:hello", resent
finally:
    srv.kill()
    echo.shutdown()
    (here / "settings.json").write_bytes(settings_before)
print("ui ok")

# --- Stop button and auto-stop ---
def start(*extra):
    global port
    port = tlspeek.free_port()
    proc = subprocess.Popen(
        [mitmdump, "-q", "-n", "-r", tmp / "c.mitm", "--set", "keepserving=true",
         "--set", f"confdir={tmp / 'conf'}", "-s", here / "addon.py", "--set", f"ui_port={port}", *extra])
    for _ in range(50):
        try:
            call("/api/state")
            return proc
        except OSError:
            time.sleep(0.2)
    raise AssertionError("server did not start")


def exits_within(proc, seconds):
    try:
        proc.wait(seconds)
        return True
    except subprocess.TimeoutExpired:
        proc.kill()
        return False


proc = start()
post("/api/stop", {})
assert exits_within(proc, 10), "Stop did not end mitmproxy"

proc = start("--set", "ui_auto_stop=60")
post("/api/bye", {})
assert exits_within(proc, addon.BYE_GRACE + 8), "closing the last tab did not stop it"

proc = start("--set", "ui_auto_stop=60")
post("/api/bye", {})
time.sleep(2)
call("/api/state")  # a refresh: the tab came back
assert not exits_within(proc, addon.BYE_GRACE + 4), "a refresh must not stop it"

proc = start("--set", "ui_auto_stop=3")
assert exits_within(proc, 10), "an idle UI did not stop it"
print("stop ok")

# --- bookmarks and notes survive in the session file ---
saved = tmp / "marks.mitm"
proc = start("--save-stream-file", saved)
for _ in range(50):
    flows = call("/api/flows")[1]["flows"]
    if len(flows) == 2:
        break
    time.sleep(0.2)
first = flows[0]["id"]
assert post("/api/mark", {"id": first, "marked": True, "note": "login call"})[0] == 200
ch = call("/api/flows")[1]
mine = next(f for f in ch["flows"] if f["id"] == first)
assert mine["marked"] and mine["note"] == "login call", mine
proc.kill()
proc.wait()

with open(saved, "rb") as fo:
    copies = [f for f in io.FlowReader(fo).stream() if f.comment]
assert copies and copies[-1].marked and copies[-1].comment == "login call"
tlspeek.export_har(saved.with_suffix(""))
har_entries = json.loads(saved.with_suffix(".har").read_text())["log"]["entries"]
assert len(har_entries) == 1 and har_entries[0]["comment"] == "login call", har_entries
print("marks ok")

# --- decoders and previews ---
png = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000")
html_flow = tflow.tflow(resp=tutils.tresp(headers=[(b"content-type", b"text/html")], content=b"<script>x()</script>hi"))
proto_flow = tflow.tflow(resp=tutils.tresp(headers=[(b"content-type", b"application/x-protobuf")],
                                           content=bytes([8, 150, 1, 18, 3, 97, 98, 99])))
img_flow = tflow.tflow(resp=tutils.tresp(headers=[(b"content-type", b"image/png")], content=png))
with open(tmp / "views.mitm", "wb") as fo:
    w = io.FlowWriter(fo)
    for fl in (html_flow, proto_flow, img_flow):
        w.add(fl)
proc = subprocess.Popen(
    [mitmdump, "-q", "-n", "-r", tmp / "views.mitm", "--set", "keepserving=true",
     "--set", f"confdir={tmp / 'conf'}", "-s", here / "addon.py", "--set", f"ui_port={(port := tlspeek.free_port())}"])
try:
    for _ in range(50):
        try:
            if len(call("/api/flows")[1]["flows"]) == 3:
                break
        except OSError:
            pass
        time.sleep(0.2)
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/body/0?part=response") as r:
        assert "sandbox" in r.headers["Content-Security-Policy"] and "default-src 'none'" in r.headers["Content-Security-Policy"]
        assert r.read() == b"<script>x()</script>hi"
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/body/2?part=response") as r:
        assert r.headers["Content-Type"] == "image/png" and r.read() == png
    status, view = call("/api/view/1?part=response&view=protobuf")
    assert status == 200 and "150" in view["text"] and "abc" in view["text"], view
    status, view = call("/api/view/1?part=response&view=hex%20dump")
    assert status == 200 and "08 96 01" in view["text"].lower(), view
    assert call("/api/view/99?part=response&view=auto")[0] == 404  # unknown flow
finally:
    proc.kill()
print("views ok")

# --- export: HAR or Postman, all or chosen ids, masked by default ---
proc = start()
try:
    for _ in range(50):
        if len(call("/api/flows")[1]["flows"]) == 2:
            break
        time.sleep(0.2)
    status, har = post("/api/export", {"format": "har", "ids": [0]})
    assert status == 200 and len(har["log"]["entries"]) == 1 and "HTOKEN" not in json.dumps(har)
    status, pm = post("/api/export", {"format": "postman", "ids": None})
    assert status == 200 and pm["info"]["schema"].endswith("v2.1.0/collection.json")
    req = pm["item"][0]["item"][0]["request"]
    assert req["method"] == "POST" and "HTOKEN" not in json.dumps(pm), req
    assert {"key": "page", "value": "2"} in req["url"]["query"] and req["body"]["options"]["raw"]["language"] == "json"
    status, raw = post("/api/export", {"format": "postman", "ids": [0], "mask": False})
    assert "HTOKEN" in json.dumps(raw), "unmasked export must keep the token"
finally:
    proc.kill()
print("export ok")

# --- tray: its polling must not keep an unattended capture alive ---
proc = start("--set", "ui_auto_stop=4")
tray_req = lambda: urllib.request.urlopen(urllib.request.Request(
    f"http://127.0.0.1:{port}/api/state", headers=tlspeek.TRAY_HEADER), timeout=2).read()
try:
    for _ in range(8):
        tray_req()
        time.sleep(1)
except OSError:
    pass  # stopped while the tray was still polling: what we want
assert exits_within(proc, 5), "tray polling kept the capture alive"
if tlspeek.tray_available():
    assert tlspeek.tray_icon_image(True).size == (64, 64)
print("tray ok")
