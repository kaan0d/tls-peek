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
WEAK_CIPHER = re.compile(r"RC4|3DES|DES-CBC|NULL|EXPORT|MD5|anon", re.I)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
CARD = re.compile(r"(?<![\d.])(?:\d[ -]?){13,19}(?![\d.])")
ID_KEY = re.compile(r"(uid|uuid|guid|cid|clientid|deviceid|idfa|gaid|aaid|adid|advertisingid|visitorid|anonymousid|installid|androidid|imei|macaddress)", re.I)
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
    "cert-self-signed": ("medium", "Self-signed server certificate",
                         "No certificate authority vouches for this server, so the connection can be intercepted without a warning if trust is skipped."),
    "cert-name-mismatch": ("medium", "Certificate does not name this host",
                           "The server certificate's names do not include the host that was requested."),
    "cert-expiring": ("low", "Server certificate expires within 30 days", "The service will break or warn when it runs out."),
    "cert-weak-key": ("medium", "Weak certificate key", "RSA keys under 2048 bits can be broken with modest resources."),
    "weak-cipher": ("medium", "Weak TLS cipher", "This cipher suite is broken or deprecated."),
    "no-forward-secrecy": ("low", "No forward secrecy",
                           "Without an ephemeral key exchange, a stolen server key decrypts recorded traffic."),
    "security-headers": ("info", "Security headers missing on an HTML page",
                         "Content-Security-Policy, X-Content-Type-Options and frame protection limit what injected content can do."),
    "rate-limited": ("info", "Rate limited (429)", "The server asked the caller to slow down; Retry-After says for how long."),
    "proxy-auth": ("info", "Proxy authentication required (407)",
                   "A proxy between this program and the server wants credentials; the program may not support it."),
    "ip-literal": ("info", "Request to a bare IP address", "No host name to check a certificate against; unusual for normal services and common for malware and LAN devices."),
    "beacon": ("low", "Requests at a regular interval",
               "The same URL is called on a steady timer. Normal for polling and telemetry, also how malware checks in."),
    "pii-email": ("low", "Email address sent", "The request carries an email address; check that this host should receive it."),
    "pii-card": ("high", "Payment card number sent", "A value passes the card number checksum. Card data belongs only with a payment provider."),
    "identifier-sent": ("info", "Device or user identifier sent",
                        "Stable identifiers let a host recognise the same person or device across requests; this is how tracking works."),
    "refused": ("info", "Request refused (401 or 403)", "The server did not accept the caller; the detail says whether any credentials were sent."),
    "cors-preflight": ("low", "CORS preflight refused",
                       "A browser would block the real request because the OPTIONS answer does not allow it."),
    "retry": ("info", "Retried after a server error or rate limit",
              "The same URL was called again within a minute of a 5xx or 429. Check that the program backs off."),
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


def body_pairs(msg):
    """(name, value) of the fields with a non-empty value in a JSON or form body."""
    text = body_text(msg)
    if not text:
        return []
    ctype = msg.headers.get("content-type", "")
    pairs = []

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    walk(v)
                elif v not in (None, ""):
                    pairs.append((k, str(v)))
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    if "json" in ctype:
        try:
            walk(json.loads(text))
        except ValueError:
            pass
    elif "x-www-form-urlencoded" in ctype:
        pairs = [(k, v) for k, v in parse_qsl(text) if v]
    return pairs


def body_keys(msg):
    return [k for k, _ in body_pairs(msg)]


def luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def lan(host):
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def name_matches(pattern, host):
    """Certificate name against host, with a leading * standing for one label."""
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and host.endswith(pattern[1:])
    return pattern == host


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def beacons(flows, ids):
    """Same URL called 5+ times at near-equal gaps of at least a second."""
    calls = {}
    for f in flows:
        if f.type == "http" and f.id in ids:
            calls.setdefault((f.request.method, f.request.pretty_host, f.request.path.split("?")[0]), []).append(f)
    out = []
    for (method, host, path), group in calls.items():
        if len(group) < 5:
            continue
        times = sorted(f.request.timestamp_start for f in group)
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = sum(gaps) / len(gaps)
        if mean >= 1 and max(abs(g - mean) for g in gaps) <= mean * 0.2:
            out.append({"check": "beacon", "host": host, "detail": f"{method} {path}: {len(group)} calls every {mean:.1f}s",
                        "ids": [ids[f.id] for f in group], "first": times[0], "last": times[-1]})
    return out


def retries(flows, ids):
    """Same URL called again within a minute after a 5xx or 429."""
    calls = {}
    for f in flows:
        if f.type == "http" and f.id in ids and f.response:
            calls.setdefault((f.request.method, f.request.pretty_host, f.request.path.split("?")[0]), []).append(f)
    out = []
    for (method, host, path), group in calls.items():
        group.sort(key=lambda f: f.request.timestamp_start)
        again = [b for a, b in zip(group, group[1:])
                 if (a.response.status_code >= 500 or a.response.status_code == 429) and b.request.timestamp_start - a.request.timestamp_start <= 60]
        if again:
            out.append({"check": "retry", "host": host, "detail": f"{method} {path}: {len(again)} retries",
                        "ids": [ids[f.id] for f in again], "first": again[0].request.timestamp_start, "last": again[-1].request.timestamp_start})
    return out


def check(flows, ids):
    """Findings for HTTP flows; ids maps flow.id to the UI id. Grouped by check, host and detail."""
    found = {}
    now = time.time()

    def add(key, f, detail=""):
        host = f.request.pretty_host
        entry = found.setdefault((key, host, detail), {"check": key, "host": host, "detail": detail, "ids": []})
        if ids[f.id] not in entry["ids"]:
            entry["ids"].append(ids[f.id])
        entry["first"] = min(entry.get("first", f.request.timestamp_start), f.request.timestamp_start)
        entry["last"] = max(entry.get("last", 0), f.request.timestamp_start)

    for f in flows:
        if f.type != "http" or f.id not in ids:
            continue
        req, resp = f.request, f.response
        local = req.pretty_host in LOCAL
        if req.scheme == "http" and not f.websocket:
            add("plain-http-local" if local else "plain-http-lan" if lan(req.pretty_host) else "plain-http", f)
            if not local and any(STRONG.search(k) for k in body_keys(req)):
                add("password-over-http", f)
        sent = list(req.query.items(multi=True)) + body_pairs(req)
        for k, v in sent:
            if EMAIL.search(v):
                add("pii-email", f)
            if any(luhn(d) for m in CARD.findall(v) if 13 <= len(d := re.sub(r"\D", "", m)) <= 19):
                add("pii-card", f)
        ident = sorted({k for k, v in sent if ID_KEY.fullmatch(re.sub(r"[-_ ]", "", k)) and v})
        if ident:
            add("identifier-sent", f, ", ".join(ident))
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
        if sc and sc.certificate_list:
            leaf = sc.certificate_list[0]
            left = leaf.notafter.timestamp() - now
            if left < 0:
                add("cert-expired", f)
            elif left < 30 * 86400:
                add("cert-expiring", f, f"{int(left // 86400)} days left")
            if leaf.issuer == leaf.subject and len(sc.certificate_list) == 1:
                add("cert-self-signed", f)
            names = [str(n.value).lower() for n in leaf.altnames] or [(leaf.cn or "").lower()]
            if not any(name_matches(n, req.pretty_host.lower()) for n in names) and not lan(req.pretty_host):
                add("cert-name-mismatch", f, ", ".join(names[:3]))
            kind, bits = leaf.keyinfo
            if kind == "RSA" and bits < 2048:
                add("cert-weak-key", f, f"RSA {bits}")
        if sc and sc.cipher:
            if WEAK_CIPHER.search(sc.cipher):
                add("weak-cipher", f, sc.cipher)
            elif sc.tls_version != "TLSv1.3" and not sc.cipher.upper().startswith(("ECDHE", "DHE", "EDH", "TLS_ECDHE", "TLS_DHE")):
                add("no-forward-secrecy", f, sc.cipher)
        if req.scheme == "https" and not local and not lan(req.pretty_host) and _is_ip(req.pretty_host):
            add("ip-literal", f, req.pretty_host)
        if not resp:
            continue
        h = h_ = resp.headers
        if resp.status_code in (401, 403):
            sent = [n for n in ("authorization", "cookie", "x-api-key") if n in req.headers]
            add("refused", f, f"{resp.status_code}, " + (f"sent {', '.join(sent)}" if sent else "no credentials sent"))
        if req.method == "OPTIONS" and "access-control-request-method" in req.headers:
            allowed = {x.strip().lower() for x in h_.get("access-control-allow-headers", "").split(",")}
            asked = {x.strip().lower() for x in req.headers.get("access-control-request-headers", "").split(",") if x.strip()}
            methods = h_.get("access-control-allow-methods", "")
            blocked = [] if "*" in allowed else sorted(asked - allowed)
            if resp.status_code >= 400:
                add("cors-preflight", f, f"status {resp.status_code}")
            elif blocked:
                add("cors-preflight", f, "headers not allowed: " + ", ".join(blocked))
            elif methods and "*" not in methods and req.headers["access-control-request-method"].upper() not in methods.upper():
                add("cors-preflight", f, "method not allowed: " + req.headers["access-control-request-method"])
        if resp.status_code == 429:
            add("rate-limited", f, "Retry-After: " + resp.headers.get("retry-after", "not sent"))
        elif resp.status_code == 407:
            add("proxy-auth", f)
        if "text/html" in resp.headers.get("content-type", "") and resp.status_code == 200:
            missing = [label for label, ok in (("Content-Security-Policy", "content-security-policy" in resp.headers),
                                               ("X-Content-Type-Options", "x-content-type-options" in resp.headers),
                                               ("frame protection", "x-frame-options" in resp.headers
                                                or "frame-ancestors" in resp.headers.get("content-security-policy", ""))) if not ok]
            if missing:
                add("security-headers", f, "missing " + ", ".join(missing))
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
    for e in [*found.values(), *beacons(flows, ids), *retries(flows, ids)]:
        severity, title, why = CHECKS[e["check"]]
        out.append({**e, "count": len(e["ids"]), "severity": severity, "title": title, "why": why})
    return sorted(out, key=lambda e: (ORDER[e["severity"]], e["check"], e["host"], e["detail"]))
