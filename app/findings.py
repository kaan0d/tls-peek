"""Passive checks over captured flows: things worth a look, found without sending anything."""
import base64
import ipaddress
import json
import re
import time
from urllib.parse import parse_qsl

from export import SECRET_VALUE, body_text, is_secret, secret_path_segments

JWT = re.compile(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*")
VERSION = re.compile(r"\d+\.\d+")
LOCAL = ("localhost", "127.0.0.1", "::1")
STRONG = re.compile(r"pass|secret|pwd|private", re.I)  # field names whose value is a password, not just a token
ERROR_TEXT = re.compile(r"Traceback \(most recent|SQLSTATE|You have an error in your SQL|ORA-\d{5}|Exception in thread"
                        r"|at [\w.$]+\([\w.]+:\d+\)|stack ?trace|Fatal error:.*on line \d+", re.I)
ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

CHECKS = {
    "secret-in-url": ("high", "Credential in the URL",
                      "URLs end up in logs, proxies and browser history. Send it in a header or the body."),
    "jwt-none": ("high", "JWT signed with alg none",
                 "Anyone can forge this token if the server accepts unsigned JWTs."),
    "plain-http": ("medium", "Unencrypted HTTP",
                   "Anyone on the network path can read and change this traffic."),
    "plain-http-lan": ("info", "Unencrypted HTTP to a local network address",
                       "Common for devices on a LAN, but anyone on that network can read and change this traffic."),
    "plain-http-local": ("info", "Unencrypted HTTP to this machine",
                         "Loopback traffic does not leave the computer; shown so nothing is hidden."),
    "password-over-http": ("high", "Password sent over unencrypted HTTP",
                           "The request body carries a password field and anyone on the path can read it."),
    "secret-in-path": ("high", "Secret in the URL path",
                       "Paths end up in logs, proxies and browser history just like query strings."),
    "secret-in-response": ("medium", "Password or secret in a response body",
                           "The server sends back a field that holds a password or secret. Check that it must leave the server."),
    "error-leak": ("medium", "Stack trace or database error in a response",
                   "Error text shows internal paths, queries or software and helps an attacker."),
    "server-error": ("info", "Server error (5xx)", "The server failed to handle the request; the body may explain why."),
    "basic-auth": ("medium", "HTTP Basic credentials",
                   "Username and password are only Base64 encoded and sent with every request."),
    "cors-credentials": ("medium", "CORS allows credentials from any origin",
                         "The server echoes the caller's Origin and allows credentials, so other sites can read responses as the user."),
    "jwt-expired-accepted": ("low", "2xx answer to an expired JWT",
                             "The server answered 2xx to a request carrying an expired token. It may also ignore the token on this endpoint; check before treating it as a flaw."),
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


def body_keys(msg):
    """Names of the fields with a non-empty value in a JSON or form body."""
    text = body_text(msg)
    if not text:
        return []
    ctype = msg.headers.get("content-type", "")
    keys = []

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    walk(v)
                elif v not in (None, ""):
                    keys.append(k)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    if "json" in ctype:
        try:
            walk(json.loads(text))
        except ValueError:
            pass
    elif "x-www-form-urlencoded" in ctype:
        keys = [k for k, v in parse_qsl(text) if v]
    return keys


def lan(host):
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


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
        if req.scheme == "http" and not f.websocket:
            add("plain-http-local" if local else "plain-http-lan" if lan(req.pretty_host) else "plain-http", f)
            if not local and any(STRONG.search(k) for k in body_keys(req)):
                add("password-over-http", f)
        for i in secret_path_segments(req.path):
            seg = req.path.split("?")[0].split("/")[i]
            add("secret-in-path", f, seg[:6] + "…")
        for k, v in req.query.items(multi=True):
            if is_secret(k) or SECRET_VALUE.search(v):
                add("secret-in-url", f, k)
        if req.headers.get("authorization", "").lower().startswith("basic "):
            add("basic-auth", f)
        sides = [("", req)] + ([(" in response", resp)] if resp else [])
        for where, msg in sides:
            texts = [v for _, v in msg.headers.items(multi=True)] + [body_text(msg) or ""] + ([req.url] if msg is req else [])
            for token in {t for text in texts for t in JWT.findall(text)}:
                head, body = jwt_parts(token)
                if not isinstance(head, dict) or not isinstance(body, dict):
                    continue
                if str(head.get("alg", "")).lower() == "none":
                    add("jwt-none", f, where.strip())
                if "exp" not in body:
                    add("jwt-no-exp", f, where.strip())
                elif msg is req and isinstance(body["exp"], (int, float)) and body["exp"] < req.timestamp_start                         and resp and 200 <= resp.status_code < 300:
                    add("jwt-expired-accepted", f)
        sc = f.server_conn
        if sc and sc.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            add("old-tls", f, sc.tls_version)
        if sc and sc.certificate_list and sc.certificate_list[0].notafter.timestamp() < now:
            add("cert-expired", f)
        if not resp:
            continue
        h = resp.headers
        if resp.status_code >= 500:
            add("server-error", f, str(resp.status_code))
        if ERROR_TEXT.search(body_text(resp) or ""):
            add("error-leak", f)
        leaked = sorted({k for k in body_keys(resp) if STRONG.search(k)})
        if leaked:
            add("secret-in-response", f, ", ".join(leaked))
        origin = req.headers.get("origin")
        acao = h.get("access-control-allow-origin")
        if acao == "*":
            add("cors-wildcard", f)
            if h.get("access-control-allow-credentials", "").lower() == "true":
                add("cors-credentials", f, "* with credentials")
        elif origin and acao == origin and h.get("access-control-allow-credentials", "").lower() == "true":
            add("cors-credentials", f, origin)
        for raw in h.get_all("set-cookie"):
            name = raw.split("=", 1)[0].strip()
            flags = {a.split("=", 1)[0].strip().lower() for a in raw.split(";")[1:]}
            missing = [flag for flag, ok in (("Secure", "secure" in flags),
                                             ("HttpOnly", "httponly" in flags),
                                             ("SameSite", "samesite" in flags)) if not ok]
            if missing:
                add("cookie-flags", f, f"{name}: no {', '.join(missing)}")
        if req.scheme == "https" and not local and "strict-transport-security" not in h:
            add("no-hsts", f)
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            for value in h.get_all(name):
                if VERSION.search(value):
                    add("server-version", f, f"{name}: {value}")

    out = []
    for e in found.values():
        severity, title, why = CHECKS[e["check"]]
        out.append({**e, "severity": severity, "title": title, "why": why})
    return sorted(out, key=lambda e: (ORDER[e["severity"]], e["check"], e["host"], e["detail"]))
