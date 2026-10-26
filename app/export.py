"""Credential masking and HAR / Postman export of mitmproxy flows."""
import json
import re
import time
from collections import Counter
from urllib.parse import parse_qsl, urlencode

from mitmproxy.addons.savehar import SaveHar
from mitmproxy.utils import strutils

from version import VERSION

MASK = "***"

# Field names are split into words ("X-Api-Key" -> x, api, key; "accessToken" ->
# access, token). A field is masked when a word is in SECRET_WORDS, or two neighbouring words
# are in SECRET_PAIRS. "Tokens" counts as "token". Plain "user", "code", "key" inside other
# names ("statusCode", "sort_key", "user") are ordinary data and stay visible.
SECRET_WORDS = {
    "auth", "authorization", "authentication", "bearer", "cookie", "cookies", "token", "jwt",
    "pass", "passwd", "password", "pwd", "passphrase", "secret", "apikey", "sessionid", "sid",
    "jsessionid", "phpsessid", "username", "sig", "signature", "credential", "credentials",
    "csrf", "xsrf",
}
SECRET_PAIRS = {("user", "name"), ("session", "id"), ("api", "key"), ("access", "key"), ("secret", "key"),
                ("private", "key"), ("auth", "key"), ("client", "key"), ("signing", "key"), ("license", "key")}
ONLY_ALONE = {"key", "pin", "otp"}  # secret only when this is the whole field name
NOT_SECRET = {"user-agent"}
NOT_SECRET_PREFIX = ("access-control-", "sec-")
WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
# Secrets recognised by their value, wherever they appear: JWTs, bearer tokens, well-known key formats.
SECRET_VALUE = re.compile(
    r"eyJ[\w-]{4,}\.eyJ[\w-]{4,}\.[\w-]*|(?<=[Bb]earer )[\w~+/.=-]+"
    r"|(?:sk|pk|rk)_(?:live|test)_\w{8,}|gh[pousr]_\w{20,}|github_pat_\w{20,}|xox[abpr]-[\w-]{10,}"
    r"|AKIA[0-9A-Z]{16}|AIza[\w-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----")
PATH_HINTS = {"reset", "verify", "confirm", "activate", "invite", "unsubscribe", "magic", "token", "tokens", "key", "keys", "secret", "auth"}


def scrub(text):
    return SECRET_VALUE.sub(MASK, text)


def is_secret(name):
    low = name.lower()
    if low in NOT_SECRET or low.startswith(NOT_SECRET_PREFIX):
        return False
    words = [w.lower() for w in WORD.findall(name)]
    words = [w[:-1] if w.endswith("s") and w[:-1] in SECRET_WORDS | ONLY_ALONE else w for w in words]
    if len(words) == 1 and words[0] in ONLY_ALONE:
        return True
    return any(w in SECRET_WORDS for w in words) or any(p in SECRET_PAIRS for p in zip(words, words[1:]))


def secret_path_segments(path):
    """Indexes of the segments of a URL path that look like a secret: a known key format, or a long
    mixed letter/digit token after a word such as reset, token or key."""
    segs = path.split("?")[0].split("/")
    out = []
    for i, seg in enumerate(segs):
        if SECRET_VALUE.search(seg):
            out.append(i)
        elif i and len(seg) >= 16 and re.search(r"\d", seg) and re.search(r"[A-Za-z]", seg)                 and (segs[i - 1].lower() in PATH_HINTS or is_secret(segs[i - 1])):
            out.append(i)
    return out


def hit(hits, name):
    if hits is not None:
        hits[name.lower()] += 1
    return MASK


def mask_json(obj, hits=None):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if not is_secret(k) or v is None:
                out[k] = mask_json(v, hits)
            elif isinstance(v, dict):
                out[k] = mask_json(v, hits)  # an object named "user" or "credentials": its own fields decide
            elif isinstance(v, list):
                out[k] = [mask_json(x, hits) if isinstance(x, (dict, list)) else hit(hits, k) for x in v]
            else:
                out[k] = hit(hits, k)
        return out
    if isinstance(obj, list):
        return [mask_json(v, hits) for v in obj]
    if isinstance(obj, str) and obj[:1] in "{[":  # JSON inside a string (echo endpoints, log fields)
        try:
            return json.dumps(mask_json(json.loads(obj), hits))
        except ValueError:
            pass
    return obj


def mask_cookie_header(name, values, hits):
    """Cookie and Set-Cookie: names and attributes (Secure, HttpOnly, Path, ...) stay, values go."""
    out = []
    for raw in values:
        head, sep, attrs = raw.partition(";") if name == "set-cookie" else (raw, "", "")
        parts = [head] if name == "set-cookie" else raw.split(";")
        masked = []
        for part in parts:
            key, eq, val = part.partition("=")
            masked.append(f"{key}={hit(hits, key.strip())}" if eq else part)
        out.append(";".join(masked) + sep + attrs)
    return out


def mask_text(text, ctype, hits):
    """Bodies that are neither JSON nor a form: XML elements, and key=value text."""
    if "xml" in ctype or text.lstrip().startswith("<"):
        return re.sub(r"(<([A-Za-z_][\w:.-]*)[^>]*>)([^<>]+)(</>)",
                      lambda m: m[1] + hit(hits, m[2]) + m[4] if is_secret(m[2]) else m[0], text)
    if ctype.startswith("text/plain") or not ctype:
        pairs = parse_qsl(text, keep_blank_values=True)
        if pairs and "=" in text and all(re.fullmatch(r"[\w.\-\[\]]+", k) for k, _ in pairs):
            return urlencode([(k, hit(hits, k) if is_secret(k) else v) for k, v in pairs])
    return text


def mask_message(msg, hits=None):
    for name in set(msg.headers):
        values = msg.headers.get_all(name)
        if name.lower() in ("cookie", "set-cookie"):
            msg.headers.set_all(name, mask_cookie_header(name.lower(), values, hits))
        else:
            msg.headers.set_all(name, [hit(hits, name) if is_secret(name) else scrub(v) for v in values])
    ctype = msg.headers.get("content-type", "")
    if not msg.raw_content:
        return
    if "json" in ctype:
        try:
            msg.text = json.dumps(mask_json(json.loads(msg.text), hits))
        except ValueError:
            pass
    elif "x-www-form-urlencoded" in ctype:
        pairs = parse_qsl(msg.text, keep_blank_values=True)
        msg.text = urlencode([(k, hit(hits, k) if is_secret(k) else v) for k, v in pairs])
    else:
        text = body_text(msg)
        if text:
            msg.text = mask_text(text, ctype, hits)
    text = body_text(msg)
    if text and scrub(text) != text:
        hit(hits, "secret value")
        msg.text = scrub(text)


def redact(flow, hits=None):
    """Mask a copy of a flow in place. hits (a Counter) collects the field names that were masked."""
    req = flow.request
    path, q, rest = req.path.partition("?")
    segs = path.split("/")
    for i in secret_path_segments(path):
        segs[i] = hit(hits, "path segment")
    req.path = "/".join(segs) + q + rest
    req.query = [(k, hit(hits, k) if is_secret(k) else scrub(v)) for k, v in req.query.items(multi=True)]
    mask_message(req, hits)
    if flow.response:
        mask_message(flow.response, hits)


def body_text(msg):
    """Decoded body, or None for binary. Streamed bodies are not stored."""
    if msg is None or not msg.raw_content:
        return ""
    content = msg.get_content(strict=False) or b""
    if strutils.is_mostly_bin(content[:2048]):
        return None
    return msg.get_text(strict=False)


def mask_note(hits, mask):
    """What the export did to the data, in words, so a reader of the file knows."""
    if not mask:
        return f"tls-peek {VERSION}: not masked, credentials are in clear text"
    top = ", ".join(f"{name} x{n}" for name, n in hits.most_common(8))
    return f"tls-peek {VERSION}: masked {sum(hits.values())} values" + (f" ({top})" if top else "") + "; field names and cookie attributes stay"


def make_har(flows, mask=True):
    """HAR of the given flows (copies are masked, the originals stay intact); notes become entry comments.
    Flows without a response (failed, still pending) are kept with status 0 and say why."""
    flows = [f.copy() for f in flows]
    hits = Counter()
    if mask:
        for f in flows:
            redact(f, hits)
    har = SaveHar().make_har(flows)
    har["log"]["comment"] = mask_note(hits, mask)
    for entry, f in zip(har["log"]["entries"], flows):
        notes = [f.comment] if f.comment else []
        if not f.response:
            notes.append("no response: " + (f.error.msg if f.error else "still pending"))
        if notes:
            entry["comment"] = "; ".join(notes)
    return har


def make_postman(flows, mask=True):
    """Postman v2.1 collection, one folder per host; notes become request descriptions."""
    folders = {}
    hits = Counter()
    for f in flows:
        f = f.copy()
        if mask:
            redact(f, hits)
        r = f.request
        path = r.path.split("?")[0]
        url = {"raw": r.pretty_url, "protocol": r.scheme, "host": r.pretty_host.split("."),
               "path": [p for p in path.split("/") if p],
               "query": [{"key": k, "value": v} for k, v in r.query.items(multi=True)]}
        if r.port != {"http": 80, "https": 443}.get(r.scheme):
            url["port"] = str(r.port)
        req = {"method": r.method, "url": url,
               "header": [{"key": k, "value": v} for k, v in r.headers.items(multi=True)
                          if k.lower() not in ("content-length", "host") and not k.startswith(":")]}
        text = body_text(r)
        if text:
            lang = "json" if "json" in r.headers.get("content-type", "") else "text"
            req["body"] = {"mode": "raw", "raw": text, "options": {"raw": {"language": lang}}}
        if f.comment:
            req["description"] = f.comment
        folders.setdefault(r.pretty_host, []).append({"name": f"{r.method} {path}", "request": req})
    return {
        "info": {"name": f"tls-peek {time.strftime('%Y-%m-%d %H:%M')}", "description": mask_note(hits, mask),
                 "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [{"name": host, "item": items} for host, items in folders.items()],
    }
