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
     "-s", here / "addon.py", "--set", f"ui_port={port}"],
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
