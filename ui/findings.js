// Findings panel: passive checks over the captured traffic (nothing is sent).
import { $, S, api, esc, post } from "./core.js";
import { closeDetail, select } from "./detail.js";
import { render } from "./list.js";

const SEVERITIES = ["high", "medium", "low", "info"];
let data = [], error = "", loadedSeq = -1, loading = false;
const expanded = new Set(), when = (t) => new Date(t * 1000).toLocaleTimeString();

export async function renderFindings() {
  if (loadedSeq !== S.seq && !loading) {
    loading = true;
    try { data = await api("/api/findings"); error = ""; loadedSeq = S.seq; }
    catch (err) { error = err.message; }
    loading = false;
    if (S.panel !== "findings") return;
  }
  const active = data.filter((f) => !f.dismissed), muted = data.filter((f) => f.dismissed);
  const count = (sev) => active.filter((f) => f.severity === sev).length;
  const card = (f) => {
    const k = `${f.check}|${f.host}|${f.detail}`, all = expanded.has(k), ids = all ? f.ids : f.ids.slice(0, 12);
    return `<div class="finding sev-${f.severity}${f.dismissed ? " dismissed" : ""}" data-check="${esc(f.check)}" data-host="${esc(f.host)}">
      <div class="f-head"><span class="sev">${f.severity}</span><b>${esc(f.title)}</b><span class="muted">${esc(f.host)}</span>
        <span class="spacer"></span><button type="button" class="dismiss">${f.dismissed ? "Show again" : "Dismiss for this host"}</button></div>
      ${f.detail ? `<div class="mono">${esc(f.detail)}</div>` : ""}
      <p>${esc(f.why)}</p>
      <div class="muted">${f.count} request${f.count === 1 ? "" : "s"}, ${when(f.first)}${f.last > f.first ? ` to ${when(f.last)}` : ""}</div>
      <div class="f-ids">${ids.map((id) => `<button type="button" data-id="${id}" title="Show this request">#${id}</button>`).join("")}
        ${f.ids.length > 12 ? `<button type="button" class="more" data-key="${esc(k)}">${all ? "show fewer" : `show all ${f.ids.length}`}</button>` : ""}</div>
    </div>`;
  };
  const tile = (sev) => `<div class="tile sev-${sev}"><span>${sev}</span><b>${count(sev)}</b></div>`;
  $("#detail").innerHTML = `
    <div class="bar"><b>Findings</b><span class="muted">passive checks on all captured requests; nothing is sent</span>
      <span class="spacer"></span><button type="button" id="findings-save" title="Findings as JSON: check, host, detail, request ids, times. No secret values.">Download JSON</button>
      <button type="button" id="findings-close">Close</button></div>
    <div class="tiles">${SEVERITIES.map(tile).join("")}</div>
    ${error ? `<p class="hint err">${esc(error)}</p>` : ""}
    ${active.map(card).join("") || `<div class="empty">Nothing found in ${S.flows.size} requests.</div>`}
    ${muted.length ? `<h3>Dismissed (${muted.length}) <small>still checked, not counted above</small></h3>${muted.map(card).join("")}` : ""}`;
  $("#findings-close").addEventListener("click", closeDetail);
  $("#detail").querySelectorAll(".f-ids button[data-id]").forEach((b) => b.addEventListener("click", () => select(Number(b.dataset.id))));
  $("#detail").querySelectorAll(".more").forEach((b) => b.addEventListener("click", () => {
    expanded.has(b.dataset.key) ? expanded.delete(b.dataset.key) : expanded.add(b.dataset.key);
    renderFindings();
  }));
  $("#detail").querySelectorAll(".dismiss").forEach((b) => b.addEventListener("click", async () => {
    const f = b.closest(".finding").dataset;
    await post("/api/dismiss", { check: f.check, host: f.host, undo: b.closest(".finding").classList.contains("dismissed") });
    loadedSeq = -1;
    renderFindings();
  }));
  $("#findings-save").addEventListener("click", () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
    a.download = `tlspeek-findings-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
}
$("#findings-btn").addEventListener("click", () => { S.panel = "findings"; S.selected = null; render(); });
