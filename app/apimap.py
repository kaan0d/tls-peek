"""API map: requests grouped into endpoints (/users/123 -> /users/{id}) with stats and JSON shapes,
and an OpenAPI 3 skeleton of one host's endpoints."""
import json
import re
from statistics import median
from urllib.parse import parse_qsl

from export import body_text

SEGMENTS = [  # (pattern, placeholder) for path segments that vary between calls
    (re.compile(r"\d+"), "id"),
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "uuid"),
    (re.compile(r"[0-9a-fA-F]{16,}"), "hash"),
    (re.compile(r"(?=.*\d)(?=.*[A-Za-z])[\w-]{20,}"), "token"),
    (re.compile(r"\d{4}-\d{2}-\d{2}"), "date"),
]
PAGE_QUERY = {"page": "page number", "page_number": "page number", "pagenumber": "page number", "offset": "offset", "skip": "offset",
              "start": "offset", "cursor": "cursor", "after": "cursor", "before": "cursor", "page_token": "cursor", "pagetoken": "cursor",
              "starting_after": "cursor", "ending_before": "cursor"}
PAGE_BODY = {"next", "next_cursor", "nextcursor", "next_page", "nextpage", "next_page_token", "nextpagetoken", "has_more", "hasmore",
             "cursor", "end_cursor", "endcursor", "page_info", "pageinfo", "pagination", "total_pages", "totalpages"}
OAUTH_REQUEST = ("grant_type", "response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method")
OAUTH_RESPONSE = ("access_token", "refresh_token", "id_token", "expires_in", "token_type", "scope")
MAX_SAMPLES = 20       # bodies per endpoint used for the JSON shapes
MAX_BODY = 200_000


def unique(base, taken):
    """base, or base2, base3, ... when taken already has it."""
    n = sum(t.rstrip("0123456789") == base for t in taken)
    return f"{base}{n + 1}" if n else base


def template(path):
    """Path without query, varying segments replaced; returns (template, parameter names)."""
    out, params = [], []
    for seg in path.split("?")[0].split("/"):
        name = next((n for rx, n in SEGMENTS if rx.fullmatch(seg)), None)
        if name == "token" and len(parts := re.split(r"[-_]", seg)) >= 3 and max(map(len, parts)) <= 10:
            name = None  # a slug such as app-config-settings-v2-final is a name, not a token
        if name:
            name = unique(name, params)
            params.append(name)
            seg = "{" + name + "}"
        out.append(seg)
    return "/".join(out) or "/", params


def shape(value, depth=0):
    """JSON Schema of one value (types and keys only, no values)."""
    if depth > 8:
        return {}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        items = {}
        for v in value[:20]:
            items = merge(items, shape(v, depth + 1))
        return {"type": "array", "items": items}
    if isinstance(value, dict):
        return {"type": "object", "properties": {k: shape(v, depth + 1) for k, v in value.items()}}
    return {"nullable": True}


def merge(a, b):
    """One schema covering both: object keys are united, arrays merge their items, null makes a field nullable, other type clashes become oneOf."""
    if not a:
        return b
    if not b or a == b:
        return a
    if b.keys() == {"nullable"}:
        return {**a, "nullable": True}
    if a.keys() == {"nullable"}:
        return {**b, "nullable": True}
    if "oneOf" in a or "oneOf" in b:
        variants = list(a.get("oneOf", [a]))
        for v in b.get("oneOf", [b]):
            for i, w in enumerate(variants):
                if w.get("type") == v.get("type"):
                    variants[i] = merge(w, v)
                    break
            else:
                variants.append(v)
        return {"oneOf": variants}
    if a.get("type") == b.get("type") == "object":
        props = dict(a["properties"])
        for k, v in b["properties"].items():
            props[k] = merge(props.get(k, {}), v)
        return {**a, "properties": props}
    if a.get("type") == b.get("type") == "array":
        return {**a, "items": merge(a["items"], b["items"])}
    if {a.get("type"), b.get("type")} == {"integer", "number"}:
        return {**a, "type": "number"}
    return {"oneOf": [a, b]}  # different types (an array of 1, 2 and an object): keep every one seen


def json_shape(msg):
    if msg is None or "json" not in msg.headers.get("content-type", "") or not msg.raw_content or len(msg.raw_content) > MAX_BODY:
        return None
    try:
        return shape(json.loads(body_text(msg) or ""))
    except ValueError:
        return None


def note_oauth(g, r, resp):
    """OAuth 2 traffic: what the request asks for (flow, PKCE, state) and what the token answer carries."""
    seen = {k: v for k, v in list(r.query.items(multi=True)) + form_pairs(r) if k in OAUTH_REQUEST}
    if resp:
        try:
            body = json.loads(body_text(resp) or "") if "json" in resp.headers.get("content-type", "") else {}
        except ValueError:
            body = {}
        if isinstance(body, dict):
            keys = [k for k in OAUTH_RESPONSE if k in body]
            if keys and ("access_token" in keys or "id_token" in keys):
                g["oauth"]["answers"] = sorted(set(g["oauth"].get("answers", [])) | set(keys))
                if isinstance(body.get("expires_in"), (int, float)):
                    g["oauth"]["expires_in"] = body["expires_in"]
            for k in PAGE_BODY & {x.lower() for x in body}:
                if "cursor in body" not in g["paging"]:
                    g["paging"].append("cursor in body")
    if seen:
        o = g["oauth"]
        o["flow"] = seen.get("grant_type") or seen.get("response_type") or o.get("flow", "")
        o["pkce"] = o.get("pkce", False) or "code_challenge" in seen
        o["state"] = o.get("state", False) or "state" in seen
        if "scope" in seen:
            o["scope"] = seen["scope"]


def form_pairs(r):
    if "x-www-form-urlencoded" not in r.headers.get("content-type", ""):
        return []
    return list(parse_qsl(body_text(r) or ""))


def endpoints(flows, ids):
    groups = {}
    for f in flows:
        if f.type != "http" or f.id not in ids or f.is_replay:
            continue
        r = f.request
        path, params = template(r.path)
        g = groups.setdefault((r.pretty_host, r.method, path), {
            "host": r.pretty_host, "method": r.method, "path": path, "params": params, "scheme": r.scheme,
            "ids": [], "statuses": {}, "ms": [], "query": [], "request": {}, "responses": {}, "samples": 0, "last_error": None,
            "paging": [], "oauth": {}})
        g["ids"].append(ids[f.id])
        for k in r.query.keys():
            if k not in g["query"]:
                g["query"].append(k)
        resp = f.response
        for k in r.query.keys():
            if k.lower() in PAGE_QUERY and PAGE_QUERY[k.lower()] not in g["paging"]:
                g["paging"].append(PAGE_QUERY[k.lower()])
        note_oauth(g, r, resp)
        if resp and 'rel="next"' in resp.headers.get("link", "") and "Link header" not in g["paging"]:
            g["paging"].append("Link header")
        if resp:
            g["statuses"][resp.status_code] = g["statuses"].get(resp.status_code, 0) + 1
            if resp.status_code >= 400:  # the newest failure, with what the server said about it
                g["last_error"] = {"id": ids[f.id], "status": resp.status_code, "text": (body_text(resp) or "")[:300]}
            if resp.timestamp_end:
                g["ms"].append((resp.timestamp_end - r.timestamp_start) * 1000)
        if g["samples"] < MAX_SAMPLES:
            g["samples"] += 1
            req_shape = json_shape(r)
            if req_shape:
                g["request"] = merge(g["request"], req_shape)
            resp_shape = json_shape(resp)
            if resp_shape:
                key = str(resp.status_code)
                g["responses"][key] = merge(g["responses"].get(key, {}), resp_shape)
    groups = merge_named(groups.values())
    for g in groups:
        g["count"] = len(g["ids"])
        g["median_ms"] = round(median(g.pop("ms"))) if g["ms"] else None
        del g["samples"]
    return sorted(groups, key=lambda g: (g["host"], g["path"], g["method"]))


def merge_named(groups):
    """Folds paths that differ only in name-like segments (/users/octocat, /users/torvalds) into one
    endpoint (/users/{name}) when they answer with the same JSON object keys."""
    clusters = {}
    for g in groups:
        segs = g["path"].split("/")
        body = g["responses"].get("200", {})
        keys = tuple(sorted(body.get("properties", {}))) if body.get("type") == "object" else None
        clusters.setdefault((g["host"], g["method"], len(segs), segs[1] if len(segs) > 1 else "", keys) if keys else id(g), []).append(g)
    out = []
    for members in clusters.values():
        if len(members) == 1:
            out.extend(members)
            continue
        cols = list(zip(*(m["path"].split("/") for m in members)))
        segs, params = [], list(members[0]["params"])
        for col in cols:
            if len(set(col)) == 1:
                segs.append(col[0])
            else:
                name = unique("name", params)
                params.append(name)
                segs.append("{" + name + "}")
        g = {**members[0], "path": "/".join(segs), "params": params, "ids": [], "statuses": {}, "ms": [], "query": [],
             "paging": sorted({p for m in members for p in m["paging"]}), "oauth": next((m["oauth"] for m in members if m["oauth"]), {}),
             "last_error": max((m["last_error"] for m in members if m["last_error"]), key=lambda e: e["id"], default=None)}
        for m in members:
            g["ids"] += m["ids"]
            g["ms"] += m["ms"]
            g["query"] += [q for q in m["query"] if q not in g["query"]]
            for code, n in m["statuses"].items():
                g["statuses"][code] = g["statuses"].get(code, 0) + n
            g["request"] = merge(g["request"], m["request"]) if m is not members[0] else g["request"]
            for code, s in m["responses"].items():
                if m is not members[0]:
                    g["responses"][code] = merge(g["responses"].get(code, {}), s)
        out.append(g)
    return out


def openapi(eps, host):
    paths = {}
    for e in (e for e in eps if e["host"] == host):
        op = {"summary": f'{e["method"]} {e["path"]}', "description": f'Seen {e["count"]} times.',
              "parameters": [{"name": p, "in": "path", "required": True, "schema": {"type": "string"}} for p in e["params"]]
              + [{"name": q, "in": "query", "schema": {"type": "string"}} for q in e["query"]],
              "responses": {}}
        if e["request"]:
            op["requestBody"] = {"content": {"application/json": {"schema": e["request"]}}}
        for status in sorted(e["statuses"]):
            schema = e["responses"].get(str(status))
            op["responses"][str(status)] = {"description": "", **({"content": {"application/json": {"schema": schema}}} if schema else {})}
        if not op["responses"]:
            op["responses"]["default"] = {"description": "No response captured"}
        paths.setdefault(e["path"], {})[e["method"].lower()] = op
    scheme = next((e["scheme"] for e in eps if e["host"] == host), "https")
    return {"openapi": "3.0.3", "info": {"title": f"{host} (captured by tls-peek)", "version": "0"},
            "servers": [{"url": f"{scheme}://{host}"}], "paths": dict(sorted(paths.items()))}
