// Stats panel for the requests currently shown.
import { $, S, api, countUp, esc, fmtMs, fmtSize, kv, refusal } from "./core.js";
import { closeDetail } from "./detail.js";
import { TYPES, filter, render, typeOf, visible } from "./list.js";

const quantile = (xs, p) => xs.length ? [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(p * xs.length))] : null;
const show = (v) => v == null ? "–" : fmtMs(Math.round(v));

// Domains and rate limits come from the server (all captured requests, not just those shown).
let hostData = null, hostSeq = -1;
function loadHosts() {
  if (hostSeq === S.seq) return;
  hostSeq = S.seq;
  api("/api/hosts").then((d) => { hostData = d; if (S.panel === "stats") renderStats(); }).catch(() => {});
}

function domainsHtml() {
  if (!hostData) return "";
  const { domains, rate_limits: limits } = hostData;
  const list = (xs) => xs.length ? esc(xs.slice(0, 4).join(", ")) + (xs.length > 4 ? ` +${xs.length - 4}` : "") : `<span class="muted">–</span>`;
  const rows = domains.map((d) => `<tr><td>${esc(d.domain)}${d.hosts.length > 1 ? ` <span class="muted" title="${esc(d.hosts.join(", "))}">${d.hosts.length} hosts</span>` : ""}</td>
    <td>${d.category ? `<span class="tag">${esc(d.category)}</span>` : ""}</td><td class="num">${d.requests}</td><td class="num">${fmtSize(d.sent)}</td>
    <td class="mono">${list(d.identifiers)}</td><td>${list(d.personal)}</td><td class="mono" title="${esc(d.cookies.join(", "))}">${d.cookies.length ? d.cookies.length : "–"}</td></tr>`).join("");
  return `<h3>Who received data <small>all captured requests, grouped by domain; categories are hints from a short built-in list</small></h3>
    <div class="scroll-x"><table class="stats"><thead><tr><th>Domain</th><th>Category</th><th class="num">Requests</th><th class="num">Sent</th>
    <th>Identifiers sent</th><th>Personal data</th><th class="num">Cookies set</th></tr></thead><tbody>${rows}</tbody></table></div>
    ${limits.length ? `<h3>Rate limits</h3><div class="scroll-x"><table class="stats"><thead><tr><th>Host</th><th class="num">429 answers</th><th>Retry-After</th><th class="num">Lowest remaining</th></tr></thead>
    <tbody>${limits.map((x) => `<tr><td>${esc(x.host)}</td><td class="num ${x.limited ? "err" : ""}">${x.limited}</td><td class="mono">${list(x.retry_after)}</td>
      <td class="num">${x.remaining ?? "–"}</td></tr>`).join("")}</tbody></table></div>` : ""}`;
}

export function renderStats() {
  loadHosts();
  const list = visible();
  const done = list.filter((f) => f.ms != null).map((f) => f.ms).sort((a, b) => a - b);
  const pct = (p) => done.length ? fmtMs(done[Math.min(done.length - 1, Math.floor(p * done.length))]) : "–";
  const isErr = (f) => f.state === "error" || f.status >= 400;
  const bytes = list.reduce((n, f) => n + f.size, 0);
  const groups = { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, Pending: 0, Error: 0 };
  for (const f of list) {
    if (f.state === "error") groups.Error++;
    else if (f.state === "pending") groups.Pending++;
    else if (`${String(f.status)[0]}xx` in groups) groups[`${String(f.status)[0]}xx`]++;
  }
  const hosts = new Map();
  for (const f of list) {
    const h = hosts.get(f.host) || { host: f.host, n: 0, err: 0, bytes: 0, ms: [], wait: [], ips: new Set(), tls: new Set(), http: new Set() };
    h.n++; h.err += isErr(f); h.bytes += f.size;
    if (f.ip) h.ips.add(f.ip);
    if (f.tls) h.tls.add(f.tls.replace("TLSv", ""));
    if (f.http) h.http.add(f.http.replace("HTTP/", ""));
    if (f.ms != null) h.ms.push(f.ms);
    if (f.phases?.wait != null) h.wait.push(f.phases.wait);
    hosts.set(f.host, h);
  }
  const types = new Map();
  for (const f of list) types.set(typeOf(f), (types.get(typeOf(f)) || 0) + 1);
  const tile = (label, value) => `<div class="tile"><span>${label}</span><b>${value}</b></div>`;
  $("#detail").innerHTML = `
    <div class="bar"><b>Stats</b><span class="muted">${list.length === S.flows.size ? "all requests" : "requests matching the filters"}</span>
      <span class="spacer"></span><button type="button" id="stats-close">Close</button></div>
    <div class="tiles">
      ${tile("Requests", list.length)}${tile("Errors", list.filter(isErr).length)}${tile("Received", fmtSize(bytes))}
      ${tile("Median time", pct(0.5))}${tile("95th pct", pct(0.95))}${tile("Hosts", hosts.size)}
    </div>
    <h3>Status</h3><div class="headers">${kv(Object.entries(groups).filter(([, n]) => n).map(([k, n]) => [k, String(n)])) || "<i>none</i>"}</div>
    <h3>Types</h3><div class="headers">${kv([...types].sort((a, b) => b[1] - a[1]).map(([k, n]) => [TYPES.find(([v]) => v === k)[1], String(n)]))}</div>
    <h3>Hosts</h3>
    <div class="scroll-x"><table class="stats"><thead><tr><th>Host</th><th class="num">Requests</th><th class="num">Errors</th><th class="num">Received</th><th class="num" title="Median request time">Median</th><th class="num" title="95th percentile request time">p95</th><th class="num" title="Median time to first byte: how long the server thought about it">Wait</th><th>IP</th><th>TLS</th><th>HTTP</th></tr></thead>
    <tbody>${[...hosts.values()].sort((a, b) => b.n - a.n).map((h) => `<tr data-host="${esc(h.host)}" title="Show only this host">
      <td>${esc(h.host)}</td><td class="num">${h.n}</td><td class="num ${h.err ? "err" : ""}">${h.err}</td>
      <td class="num">${fmtSize(h.bytes)}</td><td class="num">${show(quantile(h.ms, 0.5))}</td><td class="num">${show(quantile(h.ms, 0.95))}</td><td class="num">${show(quantile(h.wait, 0.5))}</td>
      <td class="mono" title="${esc([...h.ips].join(", "))}">${esc([...h.ips][0] || "")}${h.ips.size > 1 ? ` +${h.ips.size - 1}` : ""}</td>
      <td>${esc([...h.tls].join(", "))}</td><td>${esc([...h.http].join(", "))}</td></tr>`).join("")}
    ${S.rejected.filter((r) => !hosts.has(r.host)).map((r) => `<tr class="rejected" title="No traffic decrypted: the program refused the capture certificate">
      <td>${esc(r.host)}</td><td colspan="9" class="err">${refusal(r)} (pinned, or started before the capture)${r.passed ? `; passed through undecrypted ×${r.passed}` : ""}</td></tr>`).join("")}</tbody></table></div>${domainsHtml()}`;
  countUp($("#detail"), "stats");
  $("#stats-close").addEventListener("click", closeDetail);
  $("#detail").querySelectorAll("tr[data-host]").forEach((tr) => tr.addEventListener("click", () => {
    filter.host = tr.dataset.host;
    $("#host-pick").value = filter.host;
    render();
  }));
}
$("#stats-btn").addEventListener("click", () => { S.panel = "stats"; S.selected = null; render(); });
