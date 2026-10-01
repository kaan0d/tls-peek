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
