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
    return {"client": side(f.client_conn), "server": server, "http": f.request.http_version,
            "timing": timing(f, opened_here)}
