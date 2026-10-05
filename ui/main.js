// Entry point: header controls, polling, program picker, stop and the cert warning bar.
import { $, S, api, esc, post } from "./core.js";
import { render } from "./list.js";
import { loadDetail } from "./detail.js";
import { showIntercept } from "./intercept.js";
import "./stats.js";
import "./compare.js";
import "./export.js";

let program = "";
let paused = false;
let dismissedAt = 0;  // number of failed hosts when the warning was dismissed
let homeUrl = "";     // start page to return to (empty when started from the command line)
let fileMode = false;
let stopped = false;
let lastProgram = "";
let asked = false;    // the picker opens by itself once, when a capture starts without a program

export function showState(s) {
  program = s.program;
  lastProgram = s.last_program || "";
  if (!asked && !s.file && !s.program) { asked = true; openPicker(); }
  homeUrl = s.home || "";
  if (fileMode !== !!s.file) {
    fileMode = !!s.file;
    $("#stop").textContent = fileMode ? "Close session" : "Stop";
    $("#stop").title = fileMode ? "Close this saved session" : "Stop capturing, save the HAR and remove the certificate";
  }
  document.querySelectorAll(".live-only").forEach((el) => (el.hidden = !!s.file));
  document.querySelector(".file-only").hidden = !s.file;
  $("#file").textContent = s.file;
  $("#program-btn").innerHTML = s.program ? `<span>${esc(s.program)}</span>` : "<span>Pick program…</span>";
  if (document.activeElement !== $("#host")) $("#host").value = s.host_filter;
  paused = s.paused;
  showIntercept(s);
  $("#pause").textContent = paused ? "Resume" : "Pause";
  $("#pause").setAttribute("aria-pressed", paused);
  const n = s.rejected.length;
  $("#events").hidden = n === 0 || n <= dismissedAt;
  $("#ev-count").textContent = n === 1 ? "1 host" : n + " hosts";
  $("#ev-list").innerHTML = s.rejected.map((e) => `<li><span>${esc(e.host)}</span>
    <span>${e.reason === "rejected" ? "certificate rejected" : "closed during handshake"}</span><span>×${e.count}</span></li>`).join("");
  return s;
}

async function poll() {
  if (stopped) return;
  try {
    const [state, ch] = await Promise.all([api("/api/state"), api("/api/flows?since=" + S.seq)]);
    showState(state);
    if (ch.seq !== S.seq) {
      for (const id of S.flows.keys()) if (id < ch.dropped) S.flows.delete(id);
      for (const f of ch.flows) S.flows.set(f.id, f);
      S.seq = ch.seq;
      render();
      if (S.selected != null && ch.flows.some((f) => f.id === S.selected)) loadDetail();
    }
    $("#status").className = S.applyError ? "status off" : paused ? "status paused" : "status live";
    $("#status").textContent = S.applyError || (state.file ? "Saved session" : paused ? "Paused" : program ? "Capturing" : "No program");
  } catch {
    $("#status").className = "status off";
    $("#status").textContent = "Disconnected";
  }
  setTimeout(poll, 1000);
}

// --- config ---
async function applyConfig(newProgram) {
  try {
    showState(await post("/api/config", { program: newProgram ?? program, host_filter: $("#host").value }));
    S.applyError = "";
  } catch (err) {
    S.applyError = "Could not apply: " + err.message;
  }
}
$("#apply").addEventListener("click", () => applyConfig());
$("#host").addEventListener("keydown", (e) => { if (e.key === "Enter") applyConfig(); });
let stopTimer;
$("#stop").addEventListener("click", async (e) => {
  const b = e.currentTarget;
  if (!fileMode && !b.classList.contains("confirm")) {  // two clicks, so a stray click does not end the capture
    b.classList.add("confirm"); b.textContent = "Click to stop";
    stopTimer = setTimeout(() => { b.classList.remove("confirm"); b.textContent = "Stop"; }, 3000);
    return;
  }
  clearTimeout(stopTimer);
  try { await post("/api/stop", {}); } catch {}
  stopped = true;
  if (homeUrl) {
    $("#stopped-title").textContent = fileMode ? "Closed" : "Stopped";
    $("#stopped-text").textContent = fileMode ? "Back to the start page…"
      : "The session and its redacted HAR are saved and the certificate is removed. Back to the start page…";
    setTimeout(() => location.href = homeUrl, fileMode ? 300 : 1500);
  }
  $("#stopped").hidden = false;
  $("#status").className = "status off"; $("#status").textContent = "Stopped";
});
// Lets the app stop itself when the last tab closes (a refresh comes back within seconds).
addEventListener("pagehide", () => {
  if (!stopped) navigator.sendBeacon("/api/bye", new Blob(["{}"], { type: "application/json" }));
});
$("#pause").addEventListener("click", async () => {
  try { showState(await post("/api/pause", { paused: !paused })); S.applyError = ""; }
  catch (err) { S.applyError = "Could not pause: " + err.message; }
});
$("#ev-toggle").addEventListener("click", (e) => {
  const open = $("#ev-list").hidden;
  $("#ev-list").hidden = !open;
  e.target.textContent = open ? "Hide" : "Show";
  e.target.setAttribute("aria-expanded", open);
});
$("#ev-close").addEventListener("click", () => {
  dismissedAt = $("#ev-list").children.length;
  $("#events").hidden = true;
});

// --- program picker ---
let procs = [];
function renderProcs() {
  const q = $("#proc-search").value.trim().toLowerCase();
  $("#procs").innerHTML = procs.filter((p) => !q || (p.display + p.name).toLowerCase().includes(q)).map((p) =>
    `<button type="button" data-name="${esc(p.name)}"><img src="/api/icon?path=${encodeURIComponent(p.path)}" alt="" onerror="this.style.visibility='hidden'">
      <span>${esc(p.display)}<small>${esc(p.name)}</small></span></button>`).join("") || `<div class="empty">No match.</div>`;
}
async function loadProcs() {
  procs = await api("/api/processes" + ($("#proc-all").checked ? "?all=1" : ""));
  renderProcs();
}
async function openPicker() {
  asked = true;
  if ($("#picker").open) return;
  $("#proc-search").value = "";
  $("#proc-last").hidden = !lastProgram;
  $("#proc-last-name").textContent = lastProgram;
  $("#procs").innerHTML = `<div class="empty">Loading…</div>`;
  $("#picker").showModal();
  await loadProcs();
}
$("#program-btn").addEventListener("click", openPicker);
$("#proc-last-use").addEventListener("click", () => { $("#picker").close(); applyConfig(lastProgram); });
$("#proc-all").addEventListener("change", loadProcs);
$("#proc-search").addEventListener("input", renderProcs);
$("#proc-search").addEventListener("keydown", (e) => {
  const name = $("#proc-search").value.trim();
  if (e.key !== "Enter" || !/\.exe$/i.test(name)) return;
  e.preventDefault();
  $("#picker").close();
  applyConfig(name);
});
$("#proc-close").addEventListener("click", () => $("#picker").close());
$("#procs").addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  $("#picker").close();
  applyConfig(b.dataset.name);
});

poll();
