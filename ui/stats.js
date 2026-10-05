// Stats panel for the requests currently shown.
import { $, S, esc, fmtMs, fmtSize, kv } from "./core.js";
import { closeDetail } from "./detail.js";
import { TYPES, filter, render, typeOf, visible } from "./list.js";

export function renderStats() {
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
    const h = hosts.get(f.host) || { host: f.host, n: 0, err: 0, bytes: 0, ms: 0, timed: 0, ips: new Set(), tls: new Set(), http: new Set() };
    h.n++; h.err += isErr(f); h.bytes += f.size;
    if (f.ip) h.ips.add(f.ip);
    if (f.tls) h.tls.add(f.tls.replace("TLSv", ""));
    if (f.http) h.http.add(f.http.replace("HTTP/", ""));
    if (f.ms != null) { h.ms += f.ms; h.timed++; }
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
    <table class="stats"><thead><tr><th>Host</th><th class="num">Requests</th><th class="num">Errors</th><th class="num">Received</th><th class="num">Avg time</th><th>IP</th><th>TLS</th><th>HTTP</th></tr></thead>
    <tbody>${[...hosts.values()].sort((a, b) => b.n - a.n).map((h) => `<tr data-host="${esc(h.host)}" title="Show only this host">
      <td>${esc(h.host)}</td><td class="num">${h.n}</td><td class="num ${h.err ? "err" : ""}">${h.err}</td>
      <td class="num">${fmtSize(h.bytes)}</td><td class="num">${h.timed ? fmtMs(Math.round(h.ms / h.timed)) : "–"}</td>
      <td class="mono" title="${esc([...h.ips].join(", "))}">${esc([...h.ips][0] || "")}${h.ips.size > 1 ? ` +${h.ips.size - 1}` : ""}</td>
      <td>${esc([...h.tls].join(", "))}</td><td>${esc([...h.http].join(", "))}</td></tr>`).join("")}
    ${S.rejected.filter((r) => !hosts.has(r.host)).map((r) => `<tr class="rejected" title="No traffic decrypted: the program refused the capture certificate">
      <td>${esc(r.host)}</td><td colspan="7" class="err">${r.reason === "rejected" ? "certificate rejected" : "closed during handshake"} ×${r.count} (pinned, or started before the capture)</td></tr>`).join("")}</tbody></table>`;
  $("#stats-close").addEventListener("click", closeDetail);
  $("#detail").querySelectorAll("tr[data-host]").forEach((tr) => tr.addEventListener("click", () => {
    filter.host = tr.dataset.host;
    $("#host-pick").value = filter.host;
    render();
  }));
}
$("#stats-btn").addEventListener("click", () => { S.statsOpen = true; S.selected = null; render(); });
