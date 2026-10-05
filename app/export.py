"""Credential masking and HAR / Postman export of mitmproxy flows."""
import json
import re
import time
from urllib.parse import parse_qsl, urlencode

from mitmproxy.addons.savehar import SaveHar
from mitmproxy.utils import strutils

MASK = "***"

# Field names are split into words ("X-Api-Key" -> x, api, key; "accessToken" ->
# access, token). A field is masked when one of its words is in SECRET_WORDS.
SECRET_WORDS = {
    "auth", "authorization", "authentication", "bearer", "cookie", "cookies", "token", "jwt",
    "pass", "passwd", "password", "pwd", "passphrase", "secret", "key", "apikey", "session",
    "sessionid", "sid", "user", "username", "userid", "login", "code", "otp", "pin", "sig",
    "signature", "credential", "credentials", "csrf", "xsrf",
}
NOT_SECRET = {"user-agent"}
WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
# Secrets recognised by their value, wherever they appear: JWTs and bearer tokens.
SECRET_VALUE = re.compile(r"eyJ[\w-]{4,}\.eyJ[\w-]{4,}\.[\w-]*|(?<=[Bb]earer )[\w~+/.=-]+")


def scrub(text):
    return SECRET_VALUE.sub(MASK, text)


def is_secret(name):
    if name.lower() in NOT_SECRET:
        return False
    return any(w.lower() in SECRET_WORDS for w in WORD.findall(name))


def mask_json(obj):
    if isinstance(obj, dict):
        return {k: MASK if is_secret(k) else mask_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_json(v) for v in obj]
    return obj


def mask_message(msg):
    for name in set(msg.headers):
        values = msg.headers.get_all(name)
        msg.headers.set_all(name, [MASK if is_secret(name) else scrub(v) for v in values])
    ctype = msg.headers.get("content-type", "")
    if not msg.raw_content:
        return
    if "json" in ctype:
        try:
            msg.text = json.dumps(mask_json(json.loads(msg.text)))
        except ValueError:
            pass
    elif "x-www-form-urlencoded" in ctype:
        pairs = parse_qsl(msg.text, keep_blank_values=True)
        msg.text = urlencode([(k, MASK if is_secret(k) else v) for k, v in pairs])
    text = body_text(msg)
    if text and scrub(text) != text:
        msg.text = scrub(text)


def redact(flow):
    req = flow.request
    req.query = [(k, MASK if is_secret(k) else scrub(v)) for k, v in req.query.items(multi=True)]
    mask_message(req)
    if flow.response:
        mask_message(flow.response)


def body_text(msg):
    """Decoded body, or None for binary. Streamed bodies are not stored."""
    if msg is None or not msg.raw_content:
        return ""
    content = msg.get_content(strict=False) or b""
    if strutils.is_mostly_bin(content[:2048]):
        return None
    return msg.get_text(strict=False)


def make_har(flows, mask=True):
    """HAR of the given flows (copies are masked, the originals stay intact); notes become entry comments."""
    flows = [f.copy() for f in flows]
    if mask:
        for f in flows:
            redact(f)
    har = SaveHar().make_har(flows)
    for entry, f in zip(har["log"]["entries"], flows):
        if f.comment:
            entry["comment"] = f.comment
    return har


def make_postman(flows, mask=True):
    """Postman v2.1 collection, one folder per host; notes become request descriptions."""
    folders = {}
    for f in flows:
        f = f.copy()
        if mask:
            redact(f)
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
        "info": {"name": f"tls-peek {time.strftime('%Y-%m-%d %H:%M')}",
                 "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [{"name": host, "item": items} for host, items in folders.items()],
    }
