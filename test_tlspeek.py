"""Check that a redacted HAR export contains no secrets.

Run: python test_tlspeek.py   (needs mitmproxy installed)
"""
import json
import pathlib
import subprocess
import sys
import tempfile

from mitmproxy import io
from mitmproxy.test import tflow, tutils

here = pathlib.Path(__file__).parent
tmp = pathlib.Path(tempfile.mkdtemp())

f = tflow.tflow(
    req=tutils.treq(
        method=b"POST", path=b"/login?token=QTOKEN&page=2",
        headers=[(b"authorization", b"Bearer HTOKEN"), (b"content-type", b"application/json")],
        content=b'{"username": "alice", "password": "PW", "data": {"apiKey": "K", "n": 1}}',
    ),
    resp=tutils.tresp(headers=[(b"set-cookie", b"sid=SID")], content=b"ok"),
)
with open(tmp / "c.mitm", "wb") as fo:
    io.FlowWriter(fo).add(f)

mitmdump = pathlib.Path(sys.executable).with_name("mitmdump")
subprocess.run(
    [mitmdump, "-q", "-nr", tmp / "c.mitm", "-s", here / "tlspeek.py",
     "--set", "redact=true", "--set", f"hardump={tmp / 'c.har'}"],
    check=True,
)
har = (tmp / "c.har").read_text()
for secret in ("QTOKEN", "HTOKEN", "alice", "PW", '"K"', "SID"):
    assert secret not in har, f"{secret} leaked into HAR"
entry = json.loads(har)["log"]["entries"][0]
assert "page=2" in entry["request"]["url"] and '"n": 1' in entry["request"]["postData"]["text"]
print("ok")

# --- UI server: flows API, host guard, live config ---
import socket
import time
import urllib.request

with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
settings_before = (here / "settings.json").read_bytes()
srv = subprocess.Popen(
    [mitmdump, "-q", "-n", "-r", tmp / "c.mitm", "--set", "keepserving=true",
     "--set", f"confdir={tmp / 'conf'}", "--mode", "local:tlspeek-no-program.exe",
     "-s", here / "tlspeek.py", "--set", f"ui_port={port}", "--set", "ui_open=false"],
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


try:
    for _ in range(50):
        try:
            if call("/api/flows")[1]:
                break
        except OSError:
            pass
        time.sleep(0.2)
    status, flows = call("/api/flows")
    assert status == 200 and flows[0]["method"] == "POST" and flows[0]["status"] == 200
    status, detail = call(f"/api/flow/{flows[0]['id']}")
    assert "HTOKEN" in json.dumps(detail["request"]), "live view must show unredacted data"
    assert call("/api/state", host="evil.example:80")[0] == 403
    assert call("/api/config", data=b"{not json")[0] == 400
    status, state = call("/api/config", data=json.dumps(
        {"program": r"C:\x\Some App.exe", "host_filter": "api.example.com"}).encode())
    assert status == 200 and state["program"] == "Some App.exe", state
    assert json.loads((here / "settings.json").read_text("utf-8"))["program"] == "Some App.exe"
finally:
    srv.kill()
    (here / "settings.json").write_bytes(settings_before)
print("ui ok")
