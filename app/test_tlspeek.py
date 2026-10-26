"""Checks redaction, HAR export and the UI server API.

Run: python app/test_tlspeek.py   (needs mitmproxy installed)
"""
import atexit
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mitmproxy import dns as mdns, io
from mitmproxy.test import tflow, tutils

import addon
import export
import tlspeek
import win

here = pathlib.Path(__file__).parent
root = here.parent  # settings.json and the ui folder
tmp = pathlib.Path(tempfile.mkdtemp())
# The tests change settings.json (it is not in git); put the user's copy back at the end.
settings_file = root / "settings.json"
settings_before = settings_file.read_bytes() if settings_file.exists() else None
saved_before = addon.SAVED.read_bytes() if addon.SAVED.exists() else None  # saved requests, same story


@atexit.register
def restore_settings():
    for path, before in ((settings_file, settings_before), (addon.SAVED, saved_before)):
        if before is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(before)


# --- field-name matching ---
for name in ("Authorization", "X-Api-Key", "accessToken", "PASSWORD", "user_name", "sessionId", "Set-Cookie"):
    assert export.is_secret(name), name
for name in ("User-Agent", "monkey", "design", "keyword", "Content-Type", "page"):
    assert not export.is_secret(name), name

# --- redacted HAR export ---
f = tflow.tflow(
    req=tutils.treq(
        method=b"POST", path=b"/login?token=QTOKEN&page=2",
        headers=[(b"authorization", b"Bearer HTOKEN"), (b"content-type", b"application/json"),
                 (b"user-agent", b"KeepMe/1.0")],
        content=b'{"username": "alice", "password": "PW", "data": {"apiKey": "K", "n": 1, "blob": "eyJhbGciOiJ.eyJzdWIiOiJ.SIGJWT"}}',
    ),
    resp=tutils.tresp(headers=[(b"set-cookie", b"sid=SID"), (b"x-debug", b"seen Bearer HDRTOKEN")],
                      content=b"ok, use Bearer BODYTOKEN next time"),
)
pending = tflow.tflow(req=tutils.treq(path=b"/slow"))  # no response yet
with open(tmp / "c.mitm", "wb") as fo:
    w = io.FlowWriter(fo)
    w.add(f)
    w.add(pending)

tlspeek.export_har(tmp / "c")
har = (tmp / "c.har").read_text()
import hashlib
assert (tmp / "c.har.sha256").read_text().split()[0] == hashlib.sha256((tmp / "c.har").read_bytes()).hexdigest(), "export hash file"
for secret in ("QTOKEN", "HTOKEN", "alice", "PW", '"K"', "SID", "SIGJWT", "HDRTOKEN", "BODYTOKEN"):
    assert secret not in har, f"{secret} leaked into HAR"
entry = json.loads(har)["log"]["entries"][0]
assert "page=2" in entry["request"]["url"] and '"n": 1' in entry["request"]["postData"]["text"]
assert "KeepMe/1.0" in har

# ordinary fields stay readable, secrets in every place go, and the file says what it did
tricky = tflow.tflow(
    req=tutils.treq(method=b"POST", path=b"/reset/tok9f8e7d6c5b4a3210abcd?zip_code=123&sort_key=n&page=2",
                    headers=[(b"content-type", b"text/plain"), (b"cookie", b"sid=CKVAL; theme=dark")],
                    content=b"password=PLAIN1&card=4111"),
    resp=tutils.tresp(headers=[(b"content-type", b"application/json"), (b"set-cookie", b"sid=SETVAL; Path=/; Secure; HttpOnly"),
                               (b"access-control-allow-credentials", b"true")],
                      content=json.dumps({"statusCode": 200, "error": {"code": "NOT_FOUND"}, "user": {"id": 7, "email": "x@y.z"},
                                          "access_tokens": ["TKA1", "TKB2"], "echo": json.dumps({"token": "NESTED"})}).encode()))
xml = tflow.tflow(req=tutils.treq(headers=[(b"content-type", b"application/xml")], content=b"<a><password>XMLPW</password><n>5</n></a>"),
                  resp=tutils.tresp())
failed = tflow.tflow(err=True)
har = export.make_har([tricky, xml, failed])
text = json.dumps(har)
for secret in ("tok9f8e7d6c5b4a3210abcd", "PLAIN1", "CKVAL", "SETVAL", "TKA1", "TKB2", "NESTED", "XMLPW"):
    assert secret not in text, f"{secret} leaked"
for kept in ("zip_code=123", "sort_key=n", "NOT_FOUND", "x@y.z", "theme=***", "Secure", "HttpOnly"):
    assert kept in text, f"{kept} was masked"
body = json.loads(har["log"]["entries"][0]["response"]["content"]["text"])
assert body["statusCode"] == 200 and body["user"] == {"id": 7, "email": "x@y.z"}, body  # plain data stays readable
assert len(har["log"]["entries"]) == 3 and "no response" in har["log"]["entries"][2]["comment"], "failed requests stay in the HAR"
assert har["log"]["comment"].startswith("tls-peek ") and "masked " in har["log"]["comment"] and "password" in har["log"]["comment"], har["log"]["comment"]
assert "not masked" in export.make_har([tricky], mask=False)["log"]["comment"]
print("redaction ok")

# --- findings: passive checks ---
import base64
import findings


def jwt(head, body):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc(head)}.{enc(body)}.sig"


a = tflow.tflow(
    req=tutils.treq(scheme=b"http", host=b"api.example.com", port=80, path=b"/login?access_token=abc&page=1",
                    headers=[(b"authorization", b"Basic dTpw"), (b"x-token", jwt({"alg": "none"}, {"sub": "u"}).encode())]),
    resp=tutils.tresp(headers=[(b"set-cookie", b"sid=1; Path=/"), (b"access-control-allow-origin", b"*"),
                               (b"server", b"nginx/1.2.3")]))
b = tflow.tflow(
    req=tutils.treq(scheme=b"https", host=b"shop.example.com", port=443, path=b"/me",
                    headers=[(b"origin", b"https://evil.example"), (b"authorization", f"Bearer {jwt({'alg': 'HS256'}, {'exp': 1})}".encode())]),
    resp=tutils.tresp(headers=[(b"access-control-allow-origin", b"https://evil.example"),
                               (b"access-control-allow-credentials", b"true"),
                               (b"set-cookie", b"s=2; Secure; HttpOnly; SameSite=Lax"),
                               (b"set-cookie", b"__Secure-x=1; HttpOnly; SameSite=Lax")]))
got = findings.check([a, b], {a.id: 0, b.id: 1})
by = {(x["check"], x["host"]): x for x in got}
for key in ("plain-http", "secret-in-url", "basic-auth", "jwt-none", "jwt-no-exp", "cookie-flags", "cors-wildcard", "server-version"):
    assert (key, "api.example.com") in by and by[(key, "api.example.com")]["ids"] == [0], key
for key in ("cors-credentials", "jwt-expired-accepted", "no-hsts"):
    assert (key, "shop.example.com") in by, key
assert by[("secret-in-url", "api.example.com")]["detail"] == "access_token"
assert by[("cookie-flags", "api.example.com")]["detail"] == "sid: no Secure, HttpOnly, SameSite"  # over plain HTTP too: that is where Secure matters most
assert by[("cookie-flags", "shop.example.com")]["detail"] == "__Secure-x: no Secure"  # the name is not the flag
assert got[0]["severity"] == "high"

# transparency: response side, paths, loopback and LAN are all reported, nothing is skipped quietly
leaky = tflow.tflow(
    req=tutils.treq(scheme=b"http", host=b"127.0.0.1", port=80, path=b"/reset/tok9f8e7d6c5b4a3210abcd?user=42&code=7&sort_key=n",
                    method=b"POST", headers=[(b"content-type", b"application/json")], content=b'{"password": "hunter2"}'),
    resp=tutils.tresp(status_code=500, headers=[(b"content-type", b"application/json"), (b"server", b"a/1.0"), (b"server", b"b/2.0"),
                                                 (b"access-control-allow-origin", b"*"), (b"access-control-allow-credentials", b"true")],
                      content=json.dumps({"access_token": jwt({"alg": "none"}, {"sub": "u"}), "password": "p1",
                                          "trace": "Traceback (most recent call last)"}).encode()))
lan = tflow.tflow(req=tutils.treq(scheme=b"http", host=b"192.168.1.20", port=80, path=b"/"), resp=tutils.tresp())
got = findings.check([leaky, lan], {leaky.id: 0, lan.id: 1})
kinds = {(x["check"], x["host"], x["detail"]) for x in got}
for want in (("plain-http-local", "127.0.0.1", ""), ("plain-http-lan", "192.168.1.20", ""), ("secret-in-path", "127.0.0.1", "tok9f8…"),
             ("jwt-none", "127.0.0.1", "in response"), ("secret-in-response", "127.0.0.1", "password"),
             ("error-leak", "127.0.0.1", ""), ("server-error", "127.0.0.1", "500"), ("cors-credentials", "127.0.0.1", "* with credentials"),
             ("server-version", "127.0.0.1", "server: a/1.0"), ("server-version", "127.0.0.1", "server: b/2.0")):
    assert want in kinds, (want, sorted(kinds))
assert not any(x["check"] in ("secret-in-url", "password-over-http") for x in got), "user, code, sort_key are data; loopback is not the network"
lan_login = tflow.tflow(req=tutils.treq(scheme=b"http", host=b"example.org", port=80, method=b"POST",
                                        headers=[(b"content-type", b"application/x-www-form-urlencoded")], content=b"name=a&password=b"))
assert any(x["check"] == "password-over-http" for x in findings.check([lan_login], {lan_login.id: 0}))

# certificates, ciphers, missing headers, rate limits and timers
from mitmproxy import certs
_, ca_cert = certs.create_ca("tls-peek test", "tls-peek", 2048)
page = tflow.tflow(req=tutils.treq(scheme=b"https", host=b"shop.example.org", port=443, path=b"/"),
                   resp=tutils.tresp(headers=[(b"content-type", b"text/html")]))
page.server_conn.certificate_list = [certs.Cert(ca_cert)]
page.server_conn.cipher, page.server_conn.tls_version = "RC4-SHA", "TLSv1.2"
limited = tflow.tflow(req=tutils.treq(path=b"/q"), resp=tutils.tresp(status_code=429, headers=[(b"retry-after", b"7")]))
ticks = []
for n in range(6):
    t = tflow.tflow(req=tutils.treq(path=b"/poll?x=%d" % n), resp=tutils.tresp())
    t.request.timestamp_start = 1000 + n * 5
    ticks.append(t)
burst = tflow.tflow(req=tutils.treq(path=b"/b"), resp=tutils.tresp())
got = findings.check([page, limited, *ticks], {fl.id: i for i, fl in enumerate([page, limited, *ticks])})
kinds = {(x["check"], x["detail"]) for x in got}
for want in (("cert-self-signed", ""), ("weak-cipher", "RC4-SHA"),
             ("security-headers", "missing Content-Security-Policy, X-Content-Type-Options, frame protection"),
             ("rate-limited", "Retry-After: 7"), ("beacon", "GET /poll: 6 calls every 5.0s")):
    assert want in kinds, (want, sorted(kinds))
assert any(x["check"] == "cert-name-mismatch" for x in got)
pre = tflow.tflow(req=tutils.treq(method=b"OPTIONS", path=b"/api", headers=[(b"access-control-request-method", b"POST"),
                                                                              (b"access-control-request-headers", b"x-foo, content-type")]),
                  resp=tutils.tresp(status_code=204, headers=[(b"access-control-allow-headers", b"content-type")]))
nope = tflow.tflow(req=tutils.treq(path=b"/priv", headers=[(b"authorization", b"Bearer x")]), resp=tutils.tresp(status_code=403))
fail1 = tflow.tflow(req=tutils.treq(path=b"/job"), resp=tutils.tresp(status_code=503))
fail2 = tflow.tflow(req=tutils.treq(path=b"/job"), resp=tutils.tresp(status_code=200))
fail2.request.timestamp_start = fail1.request.timestamp_start + 3
got = findings.check([pre, nope, fail1, fail2], {fl.id: i for i, fl in enumerate([pre, nope, fail1, fail2])})
kinds = {(x["check"], x["detail"]) for x in got}
for want in (("cors-preflight", "headers not allowed: x-foo"), ("refused", "403, sent authorization"), ("retry", "GET /job: 1 retries")):
    assert want in kinds, (want, sorted(kinds))
pii = tflow.tflow(req=tutils.treq(path=b"/t?device_id=abc&n=1", method=b"POST", headers=[(b"content-type", b"application/json")],
                                  content=b'{"mail": "a.b@example.com", "pan": "4111 1111 1111 1111", "order": "1234567890123"}'),
                  resp=tutils.tresp())
got = findings.check([pii], {pii.id: 0})
kinds = {(x["check"], x["detail"]) for x in got}
for want in (("pii-email", ""), ("pii-card", ""), ("identifier-sent", "device_id")):
    assert want in kinds, (want, sorted(kinds))
assert not any("4111" in str(x) for x in got), "findings name the kind, never the value"
assert sum(x["check"] == "pii-card" for x in got) == 1, "an order number that fails the checksum is not a card"
print("findings ok")

# --- API map and OpenAPI ---
import apimap

assert apimap.template("/v1/users/123/posts/9f86d081884c7d659a2feaa0c55ad015?x=1") == ("/v1/users/{id}/posts/{hash}", ["id", "hash"])
assert apimap.template("/api/app-config-settings-v2-final")[0] == "/api/app-config-settings-v2-final"  # a slug is not a token
bad = tflow.tflow(req=tutils.treq(path=b"/boom"), resp=tutils.tresp(status_code=500, content=b"db is down"))
assert apimap.endpoints([bad], {bad.id: 7})[0]["last_error"] == {"id": 7, "status": 500, "text": "db is down"}
mixed = apimap.merge(apimap.shape([1, 2, {"x": None}]), apimap.shape([3]))
assert mixed["items"] == {"oneOf": [{"type": "integer"}, {"type": "object", "properties": {"x": {"nullable": True}}}]}, mixed
assert apimap.template("/a/1/b/2/c/3")[0] == "/a/{id}/b/{id2}/c/{id3}" and apimap.template("/")[0] == "/"
named = [tflow.tflow(req=tutils.treq(path=f"/users/{n}".encode()),
                    resp=tutils.tresp(headers=[(b"content-type", b"application/json")], content=b'{"login": "x", "id": 1}'))
         for n in ("octocat", "torvalds")]
named.append(tflow.tflow(req=tutils.treq(path=b"/users/settings"),
                         resp=tutils.tresp(headers=[(b"content-type", b"application/json")], content=b'{"theme": "dark"}')))
eps = apimap.endpoints(named, {c.id: i for i, c in enumerate(named)})
assert [(e["path"], e["count"]) for e in eps] == [("/users/settings", 1), ("/users/{name}", 2)], eps
calls = []
for n, body in ((1, b'{"name": "a", "tags": ["x"], "age": 3}'), (2, b'{"name": "b", "tags": [], "age": 4.5, "extra": null}')):
    calls.append(tflow.tflow(req=tutils.treq(path=f"/users/{n}?fields=all".encode()),
                             resp=tutils.tresp(headers=[(b"content-type", b"application/json")], content=body)))
eps = apimap.endpoints(calls, {c.id: i for i, c in enumerate(calls)})
assert len(eps) == 1 and eps[0]["path"] == "/users/{id}" and eps[0]["count"] == 2 and eps[0]["query"] == ["fields"], eps
props = eps[0]["responses"]["200"]["properties"]
assert props["age"]["type"] == "number" and props["tags"]["items"] == {"type": "string"} and props["extra"] == {"nullable": True}, props
spec = apimap.openapi(eps, "address")
op = spec["paths"]["/users/{id}"]["get"]
assert op["parameters"][0] == {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
assert op["responses"]["200"]["content"]["application/json"]["schema"]["type"] == "object"
print("api map ok")

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
hellos = {sni: SimpleNamespace(client_hello=SimpleNamespace(sni=sni), ignore_connection=False) for sni in ["a.com", "d.com", None]}
for h in hellos.values():
    peek.tls_clienthello(h)
assert [h.ignore_connection for h in hellos.values()] == [True, False, False] and peek.rejected["a.com"]["passed"] == 1
assert addon.read_settings()["passthrough_hosts"] == ["a.com", "b.com"]
peek.retry_rejected()
assert not peek.rejected and addon.read_settings()["passthrough_hosts"] == []
print("warnings ok")

# A flow the summary code chokes on becomes an error row; the others still list.
odd, fine = tflow.ttcpflow(), tflow.ttcpflow()
odd.messages = None
lister = addon.TlsPeek()
lister.flows, lister.ids, lister.changed = [odd, fine], {odd.id: 0, fine.id: 1}, {odd.id: 1, fine.id: 1}
rows = lister.changes(0)["flows"]
assert rows[0]["state"] == "error" and "could not read" in rows[0]["error"] and rows[1]["method"] == "TCP", rows
fine.messages[0].content = b"needle"
assert lister.search("needle") == [1]
hdr = tflow.tflow(req=tutils.treq(path=b"/p?trace=URLNEEDLE"), resp=tutils.tresp(headers=[(b"set-cookie", b"sid=HDRNEEDLE")]))
finder = addon.TlsPeek()
finder.flows, finder.ids = [hdr], {hdr.id: 0}
assert finder.search("urlneedle") == [0] and finder.search("hdrneedle") == [0], "search covers URL and headers"
print("unreadable flow ok")

# The event loop changes flows while the UI thread lists them.
class TouchDuringList(dict):  # a touch() on the first flow lands after it was checked
    def get(self, key, default=None):
        if key == fine.id and lister.seq == 1:
            lister.seq = self[odd.id] = 2
        return super().get(key, default)


lister.seq, lister.changed = 1, TouchDuringList({odd.id: 0, fine.id: 0})
assert lister.changes(0)["seq"] == 1, "a change made while listing must not be skipped"
assert [r["id"] for r in lister.changes(1)["flows"]] == [0]
lister.flows.pop(0); lister.ids.pop(odd.id)  # touch() dropping the oldest flow, before dropped += 1
assert lister.get(0) is None and lister.get(1) is None, "a lookup mid-drop must not return a neighbour"
lister.dropped = 1
assert lister.get(1) is fine and lister.get(0) is None
print("ui thread races ok")


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


settings_file.write_text(json.dumps({"program": "Prev.exe"}), "utf-8")
echo = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
threading.Thread(target=echo.serve_forever, daemon=True).start()
port = win.free_port()
# Same entry point as tlspeek.py, so it works with a --user install where mitmdump.exe is not next to python.exe.
mitmdump = [sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()"]
srv = subprocess.Popen(
    [*mitmdump, "-q", "-n", "-r", tmp / "c.mitm", "--set", "keepserving=true",
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
    state = call("/api/state")[1]
    assert state["program"] == "" and state["last_program"] == "Prev.exe", "a capture must wait for a program pick"
    status, detail = call(f"/api/flow/{done['id']}")
    assert "HTOKEN" in json.dumps(detail["request"]), "live view must show unredacted data"
    conn = detail["connection"]
    assert conn["server"]["tls"] == "TLSv1.2" and conn["client"]["alpn"] == "http/1.1" and not conn["server"]["reused"], conn
    assert conn["timing"] == {"connect": 1000, "tls": 1000, "send": 1000, "wait": 1000, "receive": 1000}, conn["timing"]
    assert done["phases"]["wait"] == 1000 and done["ip"] == "192.168.0.1" and done["http"] == "HTTP/1.1", done
    assert call("/api/search?q=alice")[1] == [done["id"]]
    assert call("/api/state", host="evil.example:80")[0] == 403
    assert call("/api/config", data=b"{not json")[0] == 400
    assert call("/api/flows?since=x")[0] == 400 and call("/api/flow/abc")[0] == 400

    status, state = post("/api/config", {"program": r"C:\x\Some App.exe", "host_filter": "api.example.com"})
    assert status == 200 and state["program"] == "Some App.exe", state
    assert json.loads((root / "settings.json").read_text("utf-8"))["program"] == "Some App.exe"

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
    assert resent["summary"]["source"] == done["id"], "a resent request must point back to its original"

    def answered(res):
        for _ in range(50):
            d = call(f"/api/flow/{res['id']}")[1]
            if d["summary"]["state"] != "pending":
                return d
            time.sleep(0.2)
        return d

    # Duplicate: only an id, everything else as captured.
    status, res = post("/api/resend", {"id": res["id"]})
    dup = answered(res)
    assert status == 200 and dup["response"]["body"] == "echo:hello" and dup["summary"]["method"] == "POST", dup

    # A new request, not copied from any flow.
    echo_url = f"http://127.0.0.1:{echo.server_address[1]}/new"
    status, res = post("/api/resend", {"method": "POST", "url": echo_url, "headers": [["x-a", "1"]], "body": "fresh"})
    new = answered(res)
    assert status == 200 and new["response"]["body"] == "echo:fresh" and new["summary"]["source"] is None, new
    assert ["x-a", "1"] in new["request"]["headers"], new["request"]["headers"]
    assert post("/api/resend", {"url": echo_url})[0] == 400, "a new request needs a method"

    # Saved requests live in captures\saved-requests.json.
    item = {"name": "login", "method": "POST", "url": echo_url, "headers": [["x-a", "1"]], "body": "b"}
    assert post("/api/saved", {"items": [item]}) == (200, [item])
    assert call("/api/saved")[1] == [item] and json.loads(addon.SAVED.read_text("utf-8")) == [item]
    assert post("/api/saved", {"items": [{"name": "no url"}]})[0] == 400
finally:
    srv.kill()
    echo.shutdown()
    restore_settings()
print("ui ok")

# --- Stop button and auto-stop ---
def start(*extra, file="c.mitm"):
    global port
    port = win.free_port()
    proc = subprocess.Popen(
        [*mitmdump, "-q", "-n", "-r", tmp / file, "--set", "keepserving=true",
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
    [*mitmdump, "-q", "-n", "-r", tmp / "views.mitm", "--set", "keepserving=true",
     "--set", f"confdir={tmp / 'conf'}", "-s", here / "addon.py", "--set", f"ui_port={(port := win.free_port())}"])
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
    # The UI page and every module it is split into are served with the type a browser needs.
    types = {".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml"}
    for name, ctype in [("", "text/html"), *((f"ui/{f.name}", types[f.suffix]) for f in (root / "ui").glob("*.*") if f.suffix in types)]:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/{name}") as r:
            assert r.headers["Content-Type"].startswith(ctype) and r.read() == (root / (name or "ui/index.html")).read_bytes(), name
    assert call("/ui/..%5Caddon.py")[0] == 404 and call("/ui/index.html")[0] == 404
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

# --- TCP, UDP and DNS flows are listed; HTTP has a raw view ---
with open(tmp / "raw.mitm", "wb") as fo:
    w = io.FlowWriter(fo)
    lookup = tflow.tdnsflow(resp=True)  # browsers also ask for HTTPS records, whose data is a dict
    lookup.response.answers.append(mdns.ResourceRecord("dns.google", mdns.types.HTTPS, mdns.classes.IN, 60,
                                                       bytes.fromhex("00010000010003026832")))
    for fl in (tflow.ttcpflow(), tflow.tudpflow(), lookup, tflow.tflow(resp=True)):
        w.add(fl)
proc = start(file="raw.mitm")
try:
    for _ in range(50):
        flows = call("/api/flows")[1]["flows"]
        if len(flows) == 4:
            break
        time.sleep(0.2)
    tcp, udp, dns, web = flows
    assert [f["kind"] for f in flows] == ["tcp", "udp", "dns", "http"], flows
    assert tcp["method"] == "TCP" and tcp["msgs"] == 2 and dns["info"] == "dns.google A → 8.8.8.8, 8.8.4.4, HTTPS", (tcp, dns)
    d = call(f"/api/flow/{tcp['id']}")[1]
    assert d["raw_messages"][0]["text"] == "hello" and d["raw_messages"][0]["hex"].startswith("000000  68 65"), d
    assert d["connection"]["timing"]["send"] is None, d["connection"]  # the Connection tab needs a timing object
    assert call(f"/api/flow/{dns['id']}")[1]["dns"]["response"]["answers"][0]["data"] == "8.8.8.8"
    assert call("/api/search?q=hello")[1] == [tcp["id"], udp["id"]]
    wire = call(f"/api/raw/{web['id']}")[1]
    assert wire["request"]["head"].startswith("GET /path HTTP/1.1\r\n") and wire["response"]["body_size"] == 7, wire
    assert call(f"/api/raw/{tcp['id']}")[0] == 404 and call(f"/api/body/{tcp['id']}")[0] == 404
    assert call("/api/findings")[0] == 200 and len(call("/api/endpoints")[1]) == 1
    first = call("/api/findings")[1][0]
    assert not first["dismissed"] and first["count"] == len(first["ids"]) and first["first"] <= first["last"], first
    post("/api/dismiss", {"check": first["check"], "host": first["host"]})
    assert [x["dismissed"] for x in call("/api/findings")[1] if x["check"] == first["check"] and x["host"] == first["host"]] == [True], "dismissed stays listed"
    post("/api/dismiss", {"check": first["check"], "host": first["host"], "undo": True})
    assert not call("/api/findings")[1][0]["dismissed"]
    assert len(post("/api/export", {"format": "har"})[1]["log"]["entries"]) == 1
finally:
    proc.kill()
print("raw flows ok")

# --- every kind of flow goes through every view: one odd flow once broke the whole list ---
https_lookup = tflow.tdnsflow(resp=True)
https_lookup.response.answers.append(mdns.ResourceRecord("dns.google", mdns.types.HTTPS, mdns.classes.IN, 60,
                                                         bytes.fromhex("00010000010003026832")))
h2 = tflow.tflow(resp=True)
h2.request.http_version = h2.response.http_version = "HTTP/2.0"
streamed = tflow.tflow(resp=True)
streamed.response.raw_content = None  # bodies over stream_large_bodies are not stored
silent = tflow.ttcpflow()
silent.messages = []  # a connection that never sent data
variety = [
    *tflow.tflows(), tflow.tflow(), tflow.tflow(err=True), tflow.tflow(resp=True, err=True), h2, streamed,
    tflow.tflow(resp=tutils.tresp(content=bytes(range(256)), headers=[(b"content-type", b"application/octet-stream")])),
    tflow.tflow(resp=tutils.tresp(content=b'{"a": [1, {"b": null}], "c": "eyJhbGciOiJub25lIn0.eyJ4IjoxfQ."}',
                                  headers=[(b"content-type", b"application/json")])),
    tflow.twebsocketflow(), tflow.twebsocketflow(err=tflow.terr(), close_code=1006),
    tflow.ttcpflow(err=tflow.terr()), silent, tflow.tudpflow(err=tflow.terr()),
    tflow.tdnsflow(), tflow.tdnsflow(err=True), https_lookup,
]
with open(tmp / "variety.mitm", "wb") as fo:
    w = io.FlowWriter(fo)
    for fl in variety:
        w.add(fl)
proc = start(file="variety.mitm")
try:
    for _ in range(50):
        rows = call("/api/flows")[1]["flows"]
        if len(rows) == len(variety):
            break
        time.sleep(0.2)
    assert len(rows) == len(variety), rows
    unread = [r for r in rows if "could not read" in (r["error"] or "")]
    assert not unread, unread
    for r in rows:
        assert call(f"/api/flow/{r['id']}")[0] == 200, r
        if r["kind"] == "http":
            assert call(f"/api/raw/{r['id']}")[0] == 200, r
    for path in ("/api/findings", "/api/endpoints", "/api/openapi?host=address", "/api/search?q=a"):
        assert call(path)[0] == 200, path
    for fmt in ("har", "postman"):
        assert post("/api/export", {"format": fmt})[0] == 200, fmt
    # the same session in a real browser: every row, every tab, no script error (needs playwright-core and Chrome)
    ui_test = here / "test_ui.mjs"
    if (here.parent / "node_modules" / "playwright-core").exists():
        subprocess.run(["node", ui_test, str(port)], check=True)
    else:
        assert not os.environ.get("CI"), "playwright-core missing in CI"
        print("ui in browser skipped: npm i --no-save playwright-core")
finally:
    proc.kill()
print("every flow kind ok")

# report: the findings of a saved session for scripts, with an exit code
run = subprocess.run([sys.executable, here / "tlspeek.py", "report", tmp / "variety.mitm", "--json", "--fail-on", "info"],
                     capture_output=True, text=True)
rep = json.loads(run.stdout)
assert run.returncode == 1 and rep["requests"] > 0 and rep["findings"] and rep["endpoints"] is not None, run.stderr
run = subprocess.run([sys.executable, here / "tlspeek.py", "report", tmp / "variety.mitm", "--fail-on", "high"], capture_output=True, text=True)
assert run.returncode == 1 and "findings" in run.stdout, run.stdout  # the alg none token in the session is high
run = subprocess.run([sys.executable, here / "tlspeek.py", "report", tmp / "variety.mitm"], capture_output=True, text=True)
assert run.returncode == 0, "without --fail-on the report never fails"
print("report ok")

# --- tray: its polling must not keep an unattended capture alive ---
proc = start("--set", "ui_auto_stop=4")
tray_req = lambda: urllib.request.urlopen(urllib.request.Request(
    f"http://127.0.0.1:{port}/api/state", headers=win.TRAY_HEADER), timeout=2).read()
try:
    for _ in range(8):
        tray_req()
        time.sleep(1)
except OSError:
    pass  # stopped while the tray was still polling: what we want
assert exits_within(proc, 5), "tray polling kept the capture alive"
if win.tray_available():
    assert win.tray_icon_image(True).size == (64, 64)
print("tray ok")

# --- a capture stops when the window that started it goes away ---
starter = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
viewer = subprocess.Popen([sys.executable, here / "tlspeek.py", "open", tmp / "c.mitm", "--no-browser",
                           "--parent", str(starter.pid)], stdout=subprocess.DEVNULL)
time.sleep(6)
assert viewer.poll() is None, "it should run while the starter is alive"
starter.kill()
t = time.time()
assert exits_within(viewer, 10), "it kept running after the starter was killed"
print(f"parent ok (stopped {time.time() - t:.1f}s after the starter died)")

# the starter's wait loop: exited() sees a process end
short = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"])
h = win.kernel32.OpenProcess(win.SYNCHRONIZE, False, short.pid)
assert h and not win.exited(h)
assert win.exited(h, 5000)
print("wait ok")

# --- start page: list, open and close a saved session, delete, refuse paths outside captures\ ---
addon.CAPTURES.mkdir(exist_ok=True)
fake = addon.CAPTURES / f"session-test-{int(time.time())}.mitm"
fake.write_bytes((tmp / "c.mitm").read_bytes())
port = win.free_port()
home = subprocess.Popen([sys.executable, here / "tlspeek.py", "--no-browser", "--port", str(port)], stdout=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            st = call("/api/home")[1]
            break
        except OSError:
            time.sleep(0.2)
    assert any(x["name"] == fake.name for x in st["sessions"]) and st["child"] is None, st
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/ui/base.css") as r:  # the start page shares the UI colours
        assert r.headers["Content-Type"].startswith("text/css") and r.read() == (root / "ui/base.css").read_bytes()
    assert post("/api/open", {"name": "../settings.json"})[0] == 400
    assert post("/api/delete", {"name": "..\tlspeek.py"})[0] == 400
    status, st = post("/api/open", {"name": fake.name})
    assert status == 200 and st["child"]["kind"] == "viewer", st
    viewer_port = st["child"]["port"]
    for _ in range(50):
        if call("/api/home")[1]["child"]["up"]:
            break
        time.sleep(0.3)
    home_port, port = port, viewer_port
    state = call("/api/state")[1]
    assert state["file"] == fake.name and state["home"] == f"http://127.0.0.1:{home_port}/", state
    post("/api/stop", {})  # "Close session" in the viewer
    port = home_port
    for _ in range(30):
        if call("/api/home")[1]["child"] is None:
            break
        time.sleep(0.3)
    assert call("/api/home")[1]["child"] is None, "the viewer did not end"
    assert post("/api/delete", {"name": fake.name})[0] == 200 and not fake.exists()
    post("/api/bye", {})  # the start page closes with nothing running: tls-peek ends
    assert exits_within(home, 20), "tls-peek kept running after its start page closed"
finally:
    home.kill()
    fake.unlink(missing_ok=True)
print("home ok")

# --- intercept: hold, edit and release requests and responses of a real proxied call ---
class Upper(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"server got:" + body)

    def log_message(self, *args):
        pass


upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upper)
threading.Thread(target=upstream.serve_forever, daemon=True).start()
proxy_port, port = win.free_port(), win.free_port()
proxy = subprocess.Popen([*mitmdump, "-q", "--mode", f"regular@{proxy_port}", "--set", f"confdir={tmp / 'conf'}",
                          "-s", here / "addon.py", "--set", f"ui_port={port}"])
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"}))
results = {}


def program_call(key, body):
    """What the monitored program does: one POST that waits while it is held."""
    try:
        with opener.open(urllib.request.Request(f"http://127.0.0.1:{upstream.server_address[1]}/x",
                                                data=body, method="POST"), timeout=20) as r:
            results[key] = r.read().decode()
    except Exception as e:
        results[key] = f"error: {e}"


def held_flow():
    for _ in range(50):
        held = [f for f in call(f"/api/flows")[1]["flows"] if f["state"] == "held"]
        if held:
            return held[0]
        time.sleep(0.2)
    raise AssertionError("nothing was held")


try:
    for _ in range(50):
        try:
            call("/api/state")
            break
        except OSError:
            time.sleep(0.2)
    status, st = post("/api/intercept", {"enabled": True, "url": "/x", "request": True, "response": True})
    assert status == 200 and st["intercept"]["enabled"], st

    t = threading.Thread(target=program_call, args=("edited", b"original"))
    t.start()
    f = held_flow()
    assert f["held"] == "request" and call("/api/state")[1]["held"] == 1
    time.sleep(1)
    assert "edited" not in results, "the program must wait while its request is held"
    post("/api/release", {"id": f["id"], "request": {"method": "POST", "url": f["url"], "headers": [["content-type", "text/plain"]], "body": "changed"}})
    f = held_flow()  # now the response is held
    assert f["held"] == "response", f
    post("/api/release", {"id": f["id"], "response": {"status": 201, "headers": [["content-type", "text/plain"]], "body": "fake answer"}})
    t.join(10)
    assert results["edited"] == "fake answer", results
    detail = call(f"/api/flow/{f['id']}")[1]
    assert detail["request"]["body"] == "changed" and detail["summary"]["edited"] == ["request", "response"], detail

    t = threading.Thread(target=program_call, args=("dropped", b"x"))
    t.start()
    f = held_flow()
    post("/api/release", {"id": f["id"], "drop": True})
    t.join(10)
    assert results["dropped"].startswith("error"), results

    t = threading.Thread(target=program_call, args=("off", b"y"))
    t.start()
    held_flow()
    post("/api/intercept", {"enabled": False})  # turning intercept off lets everything go
    t.join(10)
    assert results["off"] == "server got:y", results

    # rewrite rules change traffic without holding it, and are saved in settings.json
    assert post("/api/rules", {"rules": [{"action": "bogus"}]})[0] == 400
    status, st = post("/api/rules", {"rules": [
        {"action": "replace", "url": "/X", "method": "post", "find": "orig", "replace": "CHANGED"},
        {"action": "replace", "phase": "response", "find": "server got", "replace": "rewritten"},
        {"action": "header", "phase": "response", "name": "x-added", "value": "1"},
        {"action": "replace", "enabled": False, "find": "rewritten", "replace": "never"}]})
    assert status == 200 and len(st["rules"]) == 4, st
    assert json.loads(settings_file.read_text("utf-8"))["rewrite_rules"][0]["find"] == "orig"
    program_call("rule", b"original")
    assert results["rule"] == "rewritten:CHANGEDinal", results
    last = call("/api/flows")[1]["flows"][-1]
    assert last["rules"] == 3 and any("header x-added" in x for x in last["rule_log"]), last  # the list says which rules changed it
    assert ["x-added", "1"] in call(f"/api/flow/{last['id']}")[1]["response"]["headers"]

    post("/api/rules", {"rules": [{"action": "respond", "url": "/x", "type": "text/plain", "body": "mocked"}]})
    program_call("mock", b"z")
    assert results["mock"] == "mocked", results
    post("/api/rules", {"rules": []})

    # an event stream is passed on event by event (not buffered until it ends) and visible while it runs
    class Events(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for i in range(4):
                self.wfile.write(f"data: {i}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.5)

        def log_message(self, *args):
            pass

    events = ThreadingHTTPServer(("127.0.0.1", 0), Events)
    threading.Thread(target=events.serve_forever, daemon=True).start()
    started, seen, live = time.time(), [], None
    with opener.open(f"http://127.0.0.1:{events.server_address[1]}/sse", timeout=20) as r:
        for line in r:
            if line.startswith(b"data"):
                seen.append(time.time() - started)
                if len(seen) == 2:
                    time.sleep(0.8)  # the UI poll sees a pending flow with the events so far
                    row = call("/api/flows")[1]["flows"][-1]
                    live = (row["state"], row["size"], call(f"/api/flow/{row['id']}")[1]["response"]["body"])
    events.shutdown()
    assert seen[0] < 0.4 and seen[-1] - seen[0] > 1, f"events were buffered: {seen}"
    assert live[0] == "pending" and live[1] > 0 and "data: 0" in live[2] and "data: 3" not in live[2], live
    time.sleep(0.5)
    end = call("/api/flows")[1]["flows"][-1]
    assert end["state"] == "done" and "data: 3" in call(f"/api/flow/{end['id']}")[1]["response"]["body"], end
finally:
    proxy.kill()
    upstream.shutdown()
print("intercept and rules ok")
