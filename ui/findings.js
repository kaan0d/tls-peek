// Findings panel: passive checks over the captured traffic (nothing is sent).
import { $, S, api, esc } from "./core.js";
import { closeDetail, select } from "./detail.js";
import { render } from "./list.js";

const SEVERITIES = ["high", "medium", "low", "info"];
let data = [], error = "", loadedSeq = -1, loading = false;

export async function renderFindings() {
  if (loadedSeq !== S.seq && !loading) {
    loading = true;
    try { data = await api("/api/findings"); error = ""; loadedSeq = S.seq; }
    catch (err) { error = err.message; }
    loading = false;
    if (S.panel !== "findings") return;
  }
  const count = (sev) => data.filter((f) => f.severity === sev).length;
  const tile = (sev) => `<div class="tile sev-${sev}"><span>${sev}</span><b>${count(sev)}</b></div>`;
  $("#detail").innerHTML = `
    <div class="bar"><b>Findings</b><span class="muted">passive checks on all captured requests; nothing is sent</span>
      <span class="spacer"></span><button type="button" id="findings-close">Close</button></div>
    <div class="tiles">${SEVERITIES.map(tile).join("")}</div>
    ${error ? `<p class="hint err">${esc(error)}</p>` : ""}
    ${data.map((f) => `<div class="finding sev-${f.severity}">
      <div class="f-head"><span class="sev">${f.severity}</span><b>${esc(f.title)}</b><span class="muted">${esc(f.host)}</span></div>
      ${f.detail ? `<div class="mono">${esc(f.detail)}</div>` : ""}
      <p>${esc(f.why)}</p>
      <div class="f-ids">${f.ids.slice(0, 12).map((id) => `<button type="button" data-id="${id}" title="Show this request">#${id}</button>`).join("")}
        ${f.ids.length > 12 ? `<span class="muted">+${f.ids.length - 12} more</span>` : ""}</div>
    </div>`).join("") || `<div class="empty">Nothing found in ${S.flows.size} requests.</div>`}`;
  $("#findings-close").addEventListener("click", closeDetail);
  $("#detail").querySelectorAll(".f-ids button").forEach((b) => b.addEventListener("click", () => select(Number(b.dataset.id))));
}
$("#findings-btn").addEventListener("click", () => { S.panel = "findings"; S.selected = null; render(); });
