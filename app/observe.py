"""Connection, TLS and timing details of mitmproxy flows, for the Connection tab and the waterfall."""


def ms(a, b):
    """Milliseconds from a to b, or None when either timestamp is missing."""
    return round((b - a) * 1000, 1) if a and b and b >= a else None


def text(v):
    return v.decode(errors="replace") if isinstance(v, bytes) else v


def address(addr):
    return f"{addr[0]}:{addr[1]}" if addr and addr[0] else None


def timing(f, opened_here):
    """Phases in ms. connect and tls only for the flow that opened the server connection."""
    req, resp, sc = f.request, f.response, f.server_conn
    return {
        "connect": ms(sc.timestamp_start, sc.timestamp_tcp_setup) if opened_here else None,
        "tls": ms(sc.timestamp_tcp_setup, sc.timestamp_tls_setup) if opened_here else None,
        "send": ms(req.timestamp_start, req.timestamp_end),
        "wait": ms(req.timestamp_end, resp.timestamp_start) if resp else None,
        "receive": ms(resp.timestamp_start, resp.timestamp_end) if resp else None,
    }


def cert_info(c):
    return {
        "subject": c.cn or "",
        "organization": c.organization or "",
        "issuer": ", ".join(f"{k}={v}" for k, v in c.issuer),
        "not_before": c.notbefore.timestamp(),
        "not_after": c.notafter.timestamp(),
        "expired": c.has_expired(),
        "names": [str(n.value) for n in c.altnames],
        "key": "{} {}".format(*c.keyinfo),
        "serial": format(c.serial, "x"),
        "sha256": c.fingerprint().hex(":"),
        "ca": c.is_ca,
    }


def side(conn):
    """TLS facts of one connection: the program to tls-peek, or tls-peek to the server."""
    return {
        "peer": address(conn.peername),
        "local": address(conn.sockname),
        "tls": conn.tls_version,
        "cipher": conn.cipher,
        "alpn": text(conn.alpn),
        "alpn_offers": [text(a) for a in conn.alpn_offers],
        "sni": conn.sni,
    }


def connection(f, opened_here):
    server = side(f.server_conn)
    server.update(address=address(f.server_conn.address), reused=not opened_here,
                  certs=[cert_info(c) for c in f.server_conn.certificate_list])
    http = f.type == "http"
    return {"client": side(f.client_conn), "server": server, "http": f.request.http_version if http else f.type.upper(),
            "timing": timing(f, opened_here) if http else None}


# --- non-HTTP flows (TCP, UDP, DNS) and HTTP as on the wire ---

MAX_MESSAGES = 1000
MAX_HEX = 4096   # bytes of each message shown as a hex dump
MAX_TEXT = 65536


def raw_fields(f):
    """List-row fields of a TCP, UDP or DNS flow (the HTTP ones come from TlsPeek.summary)."""
    addr = f.server_conn.address
    host = f.server_conn.sni or (addr[0] if addr else "?")
    if f.type == "dns":
        q = f.request.questions[0] if f.request.questions else None
        name = f"{q.name} {to_json_type(f.request)}" if q else "?"
        resp = f.response
        answers = [a["data"] for a in resp.to_json()["answers"]] if resp else []
        info = f"{name}" + (f" → {', '.join(answers[:3])}" + (f" +{len(answers) - 3}" if len(answers) > 3 else "") if answers else "")
        return {"method": "DNS", "info": info, "url": f"dns://{name}", "host": q.name if q else host, "label": resp.to_json()["response_code"] if resp else None,
                "state": "error" if f.error else "done" if resp else "pending",
                "size": len(resp.packed) if resp else 0, "type": "dns", "msgs": len(resp.answers) if resp else None,
                "time": f.request.timestamp, "ms": ms(f.request.timestamp, resp.timestamp) if resp else None}
    sent = sum(len(m.content) for m in f.messages if m.from_client)
    got = sum(len(m.content) for m in f.messages if not m.from_client)
    last = f.messages[-1].timestamp if f.messages else None
    info = f"{len(f.messages)} messages, {sent} B sent, {got} B received"
    return {"method": f.type.upper(), "info": info, "url": f"{f.type}://{host}:{addr[1] if addr else '?'}", "host": host,
            "label": "open" if f.live else "closed", "state": "error" if f.error else "pending" if f.live else "done",
            "size": sent + got, "type": f.type, "msgs": len(f.messages), "time": f.timestamp_start,
            "ms": ms(f.timestamp_start, last) if last else None, "sent": sent}


def to_json_type(msg):
    return msg.to_json()["questions"][0]["type"]


def hexdump(data):
    from mitmproxy.utils import strutils
    lines = [f"{off[-6:]}  {hx}  {txt}" for off, hx, txt in strutils.hexdump(data[:MAX_HEX])]
    if len(data) > MAX_HEX:
        lines.append(f"… {len(data) - MAX_HEX} more bytes")
    return "\n".join(lines)


def raw_detail(f):
    if f.type == "dns":
        return {"dns": {"query": f.request.to_json(), "response": f.response.to_json() if f.response else None}}
    from mitmproxy.utils import strutils
    out = []
    for m in f.messages[-MAX_MESSAGES:]:
        text = None if strutils.is_mostly_bin(m.content[:2048]) else m.content[:MAX_TEXT].decode("utf-8", "replace")
        out.append({"from_client": m.from_client, "time": m.timestamp, "size": len(m.content),
                    "text": text, "hex": hexdump(m.content)})
    return {"raw_messages": out, "dropped_messages": max(0, len(f.messages) - MAX_MESSAGES)}


def wire(f):
    """Request and response as HTTP/1 text with byte counts. HTTP/2 and 3 are binary frames on the
    wire; their headers are shown the same way."""
    from mitmproxy.net.http.http1 import assemble
    from mitmproxy.utils import strutils

    def part(msg, head):
        if msg is None:
            return None
        raw = msg.raw_content
        body = msg.get_content(strict=False) if raw else b""
        if raw is None:
            text = "<body streamed, not stored>"
        elif not body:
            text = ""
        elif strutils.is_mostly_bin(body[:2048]):
            text = hexdump(body)
        else:
            text = body[:MAX_TEXT].decode("utf-8", "replace") + (f"\n… {len(body) - MAX_TEXT} more bytes" if len(body) > MAX_TEXT else "")
        h = head(msg)
        return {"head": h.decode("utf-8", "replace"), "head_size": len(h), "body": text,
                "body_size": len(raw or b""), "decoded_size": len(body or b""),
                "encoding": msg.headers.get("content-encoding", "")}

    return {"http": f.request.http_version, "request": part(f.request, assemble.assemble_request_head),
            "response": part(f.response, assemble.assemble_response_head)}
