"""Who the program talks to: hosts grouped by registrable domain, what identifiers they received,
and how each host rate limits."""
import ipaddress
import re

from findings import CARD, EMAIL, ID_KEY, body_pairs, luhn

# Well-known analytics, advertising and crash-reporting domains. A hint for the reader, not a verdict:
# the program may use them for good reasons, and the list is far from complete.
KNOWN = {
    "google-analytics.com": "analytics", "googletagmanager.com": "analytics", "doubleclick.net": "ads", "googlesyndication.com": "ads",
    "app-measurement.com": "analytics", "firebaselogging-pa.googleapis.com": "analytics", "crashlytics.com": "crash reports",
    "facebook.net": "ads", "facebook.com": "social", "fbcdn.net": "social", "hotjar.com": "analytics", "mixpanel.com": "analytics",
    "segment.io": "analytics", "segment.com": "analytics", "amplitude.com": "analytics", "sentry.io": "crash reports",
    "bugsnag.com": "crash reports", "datadoghq.com": "monitoring", "newrelic.com": "monitoring", "nr-data.net": "monitoring",
    "appsflyer.com": "attribution", "adjust.com": "attribution", "branch.io": "attribution", "kochava.com": "attribution",
    "braze.com": "marketing", "onesignal.com": "push", "intercom.io": "support chat", "clarity.ms": "analytics",
    "scorecardresearch.com": "ads", "criteo.com": "ads", "taboola.com": "ads", "outbrain.com": "ads", "adnxs.com": "ads",
    "applovin.com": "ads", "unity3d.com": "ads", "unityads.unity3d.com": "ads", "tiktokv.com": "social", "bytedance.com": "social",
}
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"}
LIMIT_HEADERS = ("x-ratelimit-remaining", "ratelimit-remaining", "x-rate-limit-remaining")


def registrable(host):
    """example.co.uk for api.example.co.uk, example.com for a.b.example.com; IP addresses unchanged."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.lower().split(".")
    if len(parts) <= 2:
        return host.lower()
    keep = 3 if len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL else 2
    return ".".join(parts[-keep:])


def category(domain, host):
    for name in (host.lower(), domain):
        if name in KNOWN:
            return KNOWN[name]
    return ""


def hosts(flows, ids):
    domains, limits = {}, {}
    for f in flows:
        if f.type != "http" or f.id not in ids:
            continue
        r, resp = f.request, f.response
        host = r.pretty_host
        d = domains.setdefault(registrable(host), {"domain": registrable(host), "category": "", "hosts": set(), "requests": 0,
                                                   "sent": 0, "identifiers": set(), "personal": set(), "cookies": set()})
        d["hosts"].add(host)
        d["category"] = d["category"] or category(d["domain"], host)
        d["requests"] += 1
        d["sent"] += len(r.raw_content or b"")
        pairs = list(r.query.items(multi=True)) + body_pairs(r)
        d["identifiers"].update(k for k, v in pairs if v and ID_KEY.fullmatch(re.sub(r"[-_ ]", "", k)))
        if any(EMAIL.search(v) for _, v in pairs):
            d["personal"].add("email")
        if any(luhn(x) for _, v in pairs for c in CARD.findall(v) if 13 <= len(x := re.sub(r"\D", "", c)) <= 19):
            d["personal"].add("card number")
        if resp:
            d["cookies"].update(c.split("=", 1)[0].strip() for c in resp.headers.get_all("set-cookie"))
            lim = limits.setdefault(host, {"host": host, "limited": 0, "retry_after": set(), "remaining": None, "calls": 0})
            lim["calls"] += 1
            if resp.status_code == 429:
                lim["limited"] += 1
                lim["retry_after"].add(resp.headers.get("retry-after", "not sent"))
            for name in LIMIT_HEADERS:
                v = resp.headers.get(name, "")
                if v.isdigit():
                    lim["remaining"] = int(v) if lim["remaining"] is None else min(lim["remaining"], int(v))
    out = []
    for d in domains.values():
        out.append({**d, "hosts": sorted(d["hosts"]), "identifiers": sorted(d["identifiers"]), "personal": sorted(d["personal"]),
                    "cookies": sorted(d["cookies"])})
    rate = [{**x, "retry_after": sorted(x["retry_after"])} for x in limits.values() if x["limited"] or x["remaining"] is not None]
    return {"domains": sorted(out, key=lambda d: -d["requests"]), "rate_limits": sorted(rate, key=lambda x: -x["limited"])}
