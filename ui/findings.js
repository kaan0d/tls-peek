// Findings panel: passive checks over the captured traffic (nothing is sent).
import { $, S, api, esc, post } from "./core.js";
import { closeDetail, refreshChips, select } from "./detail.js";
import { render } from "./list.js";

const SEVERITIES = ["high", "medium", "low", "info"];
let error = "", loadedSeq = -1, loading = false;
const expanded = new Set(), shown = new Set();  // shown: severities picked in the tiles, empty = all
const sameDay = (d) => d.toDateString() === new Date().toDateString();
const when = (t) => { const d = new Date(t * 1000); return sameDay(d) ? d.toLocaleTimeString() : d.toLocaleString(); };

// One fetch feeds the panel, the badge on the button and the chips in the request detail.
async function pull() {
  if (loading) return;
  loading = true;
  try { S.findings = await api("/api/findings"); error = ""; loadedSeq = S.seq; }
  catch (err) { error = err.message; }
  loading = false;
  updateBadge();
  refreshChips();
}

function updateBadge() {
  const live = S.findings.filter((f) => !f.dismissed && f.severity !== "info");
  const top = SEVERITIES.find((s) => live.some((f) => f.severity === s));
  const badge = $("#findings-badge");
  badge.hidden = !top;
  if (!top) return;
  badge.textContent = live.length;
  badge.className = `badge sev-${top}`;
  const count = (s) => live.filter((f) => f.severity === s).length;
  $("#findings-btn").title = SEVERITIES.slice(0, 3).filter(count).map((s) => `${count(s)} ${s}`).join(", ") + ": passive security checks on the captured traffic";
}

setTimeout(pull, 800);
setInterval(() => { if (!document.hidden && S.seq !== loadedSeq) pull(); }, 3000);

export async function renderFindings() {
  if (loadedSeq !== S.seq) {
    await pull();
    if (S.panel !== "findings") return;
  }
  const data = S.findings;
  const visibleNow = (f) => !shown.size || shown.has(f.severity);
  const active = data.filter((f) => !f.dismissed), muted = data.filter((f) => f.dismissed);
  const count = (sev) => active.filter((f) => f.severity === sev).length;
  const tile = (sev) => `<button type="button" class="tile sev-${sev}" data-sev="${sev}" aria-pressed="${shown.has(sev)}" title="Show only ${sev}"><span>${sev}</span><b>${count(sev)}</b></button>`;
  const card = (f) => {
    const k = `${f.check}|${f.host}|${f.detail}`, all = expanded.has(k), ids = all ? f.ids : f.ids.slice(0, 12);
    return `<div class="finding sev-${f.severity}${f.dismissed ? " dismissed" : ""}" data-check="${esc(f.check)}" data-host="${esc(f.host)}">
      <div class="f-head"><span class="sev">${f.severity}</span><b>${esc(f.title)}</b><span class="muted">${esc(f.host)}</span>
        <button type="button" class="dismiss" title="Hide this check for this host from the counts; it stays listed below">${f.dismissed ? "Show again" : "Dismiss"}</button></div>
      ${f.detail ? `<div class="mono">${esc(f.detail)}</div>` : ""}
      <p>${esc(f.why)}</p>
      <div class="muted">${f.count} request${f.count === 1 ? "" : "s"}, ${when(f.first)}${f.last > f.first ? ` to ${when(f.last)}` : ""}</div>
      <div class="f-ids">${ids.map((id) => `<button type="button" data-id="${id}" title="Show this request">#${id}</button>`).join("")}
        ${f.ids.length > 12 ? `<button type="button" class="more" data-key="${esc(k)}">${all ? "show fewer" : `show all ${f.ids.length}`}</button>` : ""}</div>
    </div>`;
  };
  $("#detail").innerHTML = `
    <div class="bar"><b>Findings</b><span class="muted">passive checks on all captured requests; nothing is sent</span>
      <span class="spacer"></span><button type="button" id="findings-save" title="Findings as JSON: check, host, detail, request ids, times. No secret values.">Download JSON</button>
      <button type="button" id="findings-close">Close</button></div>
    <div class="tiles">${SEVERITIES.map(tile).join("")}</div>
    ${error ? `<p class="hint err">${esc(error)}</p>` : ""}
    ${active.filter(visibleNow).map(card).join("") || `<div class="empty">${shown.size ? "Nothing at this level." : `Nothing found in ${S.flows.size} requests.`}</div>`}
    ${muted.length ? `<h3>Dismissed (${muted.length}) <small>still checked, not counted above</small></h3>${muted.filter(visibleNow).map(card).join("")}` : ""}`;
  $("#findings-close").addEventListener("click", closeDetail);
  $("#detail").querySelectorAll(".f-ids button[data-id]").forEach((b) => b.addEventListener("click", () => select(Number(b.dataset.id))));
  $("#detail").querySelectorAll(".tile").forEach((b) => b.addEventListener("click", () => {
    shown.has(b.dataset.sev) ? shown.delete(b.dataset.sev) : shown.add(b.dataset.sev);
    renderFindings();
  }));
  $("#detail").querySelectorAll(".more").forEach((b) => b.addEventListener("click", () => {
    expanded.has(b.dataset.key) ? expanded.delete(b.dataset.key) : expanded.add(b.dataset.key);
    renderFindings();
  }));
  $("#detail").querySelectorAll(".dismiss").forEach((b) => b.addEventListener("click", async () => {
    const f = b.closest(".finding");
    await post("/api/dismiss", { check: f.dataset.check, host: f.dataset.host, undo: f.classList.contains("dismissed") });
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
