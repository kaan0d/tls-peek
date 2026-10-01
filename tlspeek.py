"""mitmproxy addon for tls-peek.

Live capture: warns in the console when the monitored program rejects the
mitmproxy certificate (certificate pinning).

Export (option redact=true): masks credentials in every flow before the HAR is
written, e.g.
  mitmdump -nr capture.mitm -s tlspeek.py --set redact=true --set hardump=out.har
"""
import json
import logging
import re
from urllib.parse import parse_qsl, urlencode

from mitmproxy import ctx

# Header, query, form and JSON key names whose values get masked.
SECRET = re.compile(r"auth|cookie|token|pass|secret|key|session|user|login|code|sig", re.I)
MASK = "***"


def mask_json(obj):
    if isinstance(obj, dict):
        return {k: MASK if SECRET.search(k) else mask_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_json(v) for v in obj]
    return obj


def mask_message(msg):
    for name in list(msg.headers):
        if SECRET.search(name):
            msg.headers[name] = MASK
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
        msg.text = urlencode([(k, MASK if SECRET.search(k) else v) for k, v in pairs])


class TlsPeek:
    def load(self, loader):
        loader.add_option("redact", bool, False, "Mask credentials in flows (for HAR export).")

    def tls_failed_client(self, data):
        sni = data.conn.sni or "unknown host"
        logging.warning(
            f"[tls-peek] Program rejected the mitmproxy certificate for {sni}: "
            "probably certificate pinning. Traffic to this host cannot be decrypted."
        )

    def response(self, flow):
        if not ctx.options.redact:
            return
        req = flow.request
        req.query = [(k, MASK if SECRET.search(k) else v) for k, v in req.query.items(multi=True)]
        mask_message(req)
        mask_message(flow.response)


addons = [TlsPeek()]
