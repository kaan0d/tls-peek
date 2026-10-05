"""Passive checks over captured flows: things worth a look, found without sending anything."""
import base64
import json
import re
import time

from export import SECRET_VALUE, is_secret

JWT = re.compile(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*")
VERSION = re.compile(r"\d+\.\d+")
LOCAL = ("localhost", "127.0.0.1", "::1")
ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

CHECKS = {
    "secret-in-url": ("high", "Credential in the URL",
                      "URLs end up in logs, proxies and browser history. Send it in a header or the body."),
    "jwt-none": ("high", "JWT signed with alg none",
                 "Anyone can forge this token if the server accepts unsigned JWTs."),
    "plain-http": ("medium", "Unencrypted HTTP",
                   "Anyone on the network path can read and change this traffic."),
    "basic-auth": ("medium", "HTTP Basic credentials",
                   "Username and password are only Base64 encoded and sent with every request."),
    "cors-credentials": ("medium", "CORS allows credentials from any origin",
                         "The server echoes the caller's Origin and allows credentials, so other sites can read responses as the user."),
    "jwt-expired-accepted": ("medium", "Expired JWT accepted",
                             "The server answered 2xx to a request carrying an expired token."),
    "old-tls": ("medium", "Old TLS version", "TLS 1.0 and 1.1 are deprecated and have known weaknesses."),
    "cert-expired": ("medium", "Expired server certificate", "The real server's certificate is out of date."),
    "cookie-flags": ("low", "Cookie without Secure, HttpOnly or SameSite",
                     "Missing flags let scripts read the cookie, send it over HTTP or attach it to cross-site requests."),
    "jwt-no-exp": ("low", "JWT without expiry", "A leaked token without exp stays valid until its key changes."),
    "cors-wildcard": ("low", "CORS open to every origin", "Access-Control-Allow-Origin: * lets any site read these responses."),
    "no-hsts": ("info", "No HSTS header", "Without Strict-Transport-Security a first visit can be downgraded to HTTP."),
    "server-version": ("info", "Server software version disclosed",
                       "Version numbers in headers help attackers pick known exploits."),
}


def jwt_parts(token):
    def part(s):
        return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    try:
        head, body = token.split(".")[:2]
        return part(head), part(body)
    except (ValueError, UnicodeDecodeError):
        return None, None


def check(flows, ids):
    """Findings for HTTP flows; ids maps flow.id to the UI id. Grouped by check, host and detail."""
    found = {}
    now = time.time()

    def add(key, f, detail=""):
        host = f.request.pretty_host
        entry = found.setdefault((key, host, detail), {"check": key, "host": host, "detail": detail, "ids": []})
        if ids[f.id] not in entry["ids"]:
            entry["ids"].append(ids[f.id])

    for f in flows:
        if f.type != "http" or f.id not in ids:
            continue
        req, resp = f.request, f.response
        local = req.pretty_host in LOCAL
        if req.scheme == "http" and not local and not f.websocket:
            add("plain-http", f)
        for k, v in req.query.items(multi=True):
            if is_secret(k) or SECRET_VALUE.search(v):
                add("secret-in-url", f, k)
        if req.headers.get("authorization", "").lower().startswith("basic "):
            add("basic-auth", f)
        texts = [v for _, v in req.headers.items(multi=True)] + [req.url, req.get_text(strict=False) or ""]
        for token in {t for text in texts for t in JWT.findall(text)}:
            head, body = jwt_parts(token)
            if not isinstance(head, dict) or not isinstance(body, dict):
                continue
            if str(head.get("alg", "")).lower() == "none":
                add("jwt-none", f)
            if "exp" not in body:
                add("jwt-no-exp", f)
            elif isinstance(body["exp"], (int, float)) and body["exp"] < req.timestamp_start and resp and 200 <= resp.status_code < 300:
                add("jwt-expired-accepted", f)
        sc = f.server_conn
        if sc and sc.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            add("old-tls", f, sc.tls_version)
        if sc and sc.certificate_list and sc.certificate_list[0].notafter.timestamp() < now:
            add("cert-expired", f)
        if not resp:
            continue
        h = resp.headers
        origin = req.headers.get("origin")
        acao = h.get("access-control-allow-origin")
        if acao == "*":
            add("cors-wildcard", f)
        elif origin and acao == origin and h.get("access-control-allow-credentials", "").lower() == "true":
            add("cors-credentials", f, origin)
        for raw in h.get_all("set-cookie"):
            name = raw.split("=", 1)[0].strip()
            flags = {a.split("=", 1)[0].strip().lower() for a in raw.split(";")[1:]}
            missing = [flag for flag, ok in (("Secure", "secure" in flags or req.scheme == "http"),
                                             ("HttpOnly", "httponly" in flags),
                                             ("SameSite", "samesite" in flags)) if not ok]
            if missing:
                add("cookie-flags", f, f"{name}: no {', '.join(missing)}")
        if req.scheme == "https" and not local and "strict-transport-security" not in h:
            add("no-hsts", f)
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            if VERSION.search(h.get(name, "")):
                add("server-version", f, f"{name}: {h[name]}")

    out = []
    for e in found.values():
        severity, title, why = CHECKS[e["check"]]
        out.append({**e, "severity": severity, "title": title, "why": why})
    return sorted(out, key=lambda e: (ORDER[e["severity"]], e["check"], e["host"], e["detail"]))
