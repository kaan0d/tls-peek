// API map panel: endpoints grouped from the captured requests, their JSON shapes and an OpenAPI download.
import { $, S, api, esc, fmtMs } from "./core.js";
import { closeDetail, select } from "./detail.js";
import { render } from "./list.js";

let data = [], error = "", loadedSeq = -1, loading = false, host = "";
const open = new Set();  // endpoints shown expanded, by key
const key = (e) => `${e.host} ${e.method} ${e.path}`;

// JSON Schema as a short type sketch: { name: string, tags: string[] }
function sketch(s, pad = "") {
  if (!s || !s.type) return s?.nullable ? "null" : "unknown";
  const t = s.type === "object"
    ? (Object.keys(s.properties).length ? `{\n${Object.entries(s.properties).map(([k, v]) => `${pad}  ${k}: ${sketch(v, pad + "  ")}`).join(",\n")}\n${pad}}` : "{}")
    : s.type === "array" ? `${sketch(s.items, pad)}[]` : s.type;
  return s.nullable ? `${t} | null` : t;
}

export async function renderApiMap() {
  if (loadedSeq !== S.seq && !loading) {
    loading = true;
    try { data = await api("/api/endpoints"); error = ""; loadedSeq = S.seq; }
    catch (err) { error = err.message; }
    loading = false;
    if (S.panel !== "api") return;
  }
  const hosts = [...new Set(data.map((e) => e.host))];
  if (!hosts.includes(host)) host = hosts[0] || "";
  const eps = data.filter((e) => e.host === host);
  const statuses = (e) => Object.entries(e.statuses).map(([c, n]) => `<span class="s${c[0]}">${c}</span>${n > 1 ? `×${n}` : ""}`).join(" ");
  const details = (e) => `<tr class="ep-detail"><td colspan="5">
    ${e.params.length ? `<div class="muted">Path parameters: <span class="mono">${e.params.map(esc).join(", ")}</span></div>` : ""}
    ${e.query.length ? `<div class="muted">Query: <span class="mono">${e.query.map(esc).join(", ")}</span></div>` : ""}
    ${Object.keys(e.request).length ? `<div class="muted">Request body</div><pre>${esc(sketch(e.request))}</pre>` : ""}
    ${Object.entries(e.responses).map(([c, s]) => `<div class="muted">Response ${esc(c)}</div><pre>${esc(sketch(s))}</pre>`).join("")}
    <div class="f-ids">${e.ids.slice(-12).map((id) => `<button type="button" data-id="${id}">#${id}</button>`).join("")}</div></td></tr>`;
  $("#detail").innerHTML = `
    <div class="bar"><b>API map</b>
      <select id="ep-host" aria-label="Host">${hosts.map((h) => `<option${h === host ? " selected" : ""}>${esc(h)}</option>`).join("")}</select>
      <span class="spacer"></span>
      <a class="button" id="ep-openapi" href="/api/openapi?host=${encodeURIComponent(host)}" title="OpenAPI 3 skeleton of this host's endpoints" ${host ? "" : "hidden"}>OpenAPI</a>
      <button type="button" id="ep-close">Close</button></div>
    ${error ? `<p class="hint err">${esc(error)}</p>` : ""}
    <p class="hint">Requests grouped by method and path; numbers, UUIDs, hashes and long tokens in the path become parameters. Click a row for its JSON shapes.</p>
    ${eps.length ? `<table class="stats endpoints"><thead><tr><th>Method</th><th>Endpoint</th><th class="num">Calls</th><th>Status</th><th class="num">Median</th></tr></thead>
    <tbody>${eps.map((e) => `<tr data-key="${esc(key(e))}"><td class="mono">${esc(e.method)}</td><td class="mono">${esc(e.path)}</td>
      <td class="num">${e.count}</td><td class="mono">${statuses(e)}</td><td class="num">${e.median_ms == null ? "–" : fmtMs(e.median_ms)}</td></tr>
      ${open.has(key(e)) ? details(e) : ""}`).join("")}</tbody></table>` : `<div class="empty">No requests yet.</div>`}`;
  $("#ep-close").addEventListener("click", closeDetail);
  $("#ep-host").addEventListener("change", (e) => { host = e.target.value; renderApiMap(); });
  $("#detail").querySelectorAll("tr[data-key]").forEach((tr) => tr.addEventListener("click", () => {
    open.has(tr.dataset.key) ? open.delete(tr.dataset.key) : open.add(tr.dataset.key);
    renderApiMap();
  }));
  $("#detail").querySelectorAll(".f-ids button").forEach((b) => b.addEventListener("click", () => select(Number(b.dataset.id))));
}
$("#api-btn").addEventListener("click", () => { S.panel = "api"; S.selected = null; render(); });
