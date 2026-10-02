// Intercept: rule dialog, held badge, editor for a held request or response.
import { $, S, esc, headerLines, parseHeaders, post } from "./core.js";
import { loadDetail, select } from "./detail.js";
import { showState } from "./main.js";

let icpt = { enabled: false, url: "", method: "", request: true, response: false };
let heldCount = 0;
const heldSince = new Map();  // id -> when we first saw it held

export function showIntercept(s) {
  icpt = s.intercept || icpt;
  heldCount = s.held || 0;
  $("#icpt-btn").setAttribute("aria-pressed", icpt.enabled);
  $("#icpt-btn").textContent = icpt.enabled ? "Intercept: on" : "Intercept";
  $("#held-btn").hidden = $("#release-all").hidden = heldCount === 0;
  $("#held-btn").textContent = `⏸ ${heldCount} held`;
  document.title = heldCount ? `(${heldCount} held) tls-peek` : "tls-peek";
}

function openRule() {
  $("#ic-on").checked = icpt.enabled || !icpt.url;  // opening it usually means "turn it on"
  $("#ic-url").value = icpt.url;
  $("#ic-method").value = icpt.method;
  $("#ic-req").checked = icpt.request;
  $("#ic-resp").checked = icpt.response;
  $("#icpt-dlg").showModal();
}

// While intercept is on, the button turns it off (after asking): held traffic goes on unchanged.
$("#icpt-btn").addEventListener("click", () => {
  if (!icpt.enabled) return openRule();
  $("#io-text").textContent = heldCount
    ? `${heldCount} held ${heldCount === 1 ? "request is" : "requests are"} sent on unchanged, and nothing new will be held.`
    : "Nothing new will be held.";
  $("#icpt-off").showModal();
});
$("#io-cancel").addEventListener("click", () => $("#icpt-off").close());
$("#io-rule").addEventListener("click", () => { $("#icpt-off").close(); openRule(); });
$("#io-off").addEventListener("click", async () => {
  $("#icpt-off").close();
  try { showState(await post("/api/intercept", { ...icpt, enabled: false })); S.applyError = ""; }
  catch (err) { S.applyError = "Could not turn off intercept: " + err.message; }
});
$("#ic-cancel").addEventListener("click", () => $("#icpt-dlg").close());
$("#ic-save").addEventListener("click", async () => {
  try {
    showState(await post("/api/intercept", { enabled: $("#ic-on").checked, url: $("#ic-url").value,
      method: $("#ic-method").value, request: $("#ic-req").checked, response: $("#ic-resp").checked }));
    S.applyError = "";
  } catch (err) { S.applyError = "Could not set intercept: " + err.message; }
  $("#icpt-dlg").close();
});
$("#held-btn").addEventListener("click", () => {
  const first = [...S.flows.values()].find((f) => f.state === "held");
  if (first) { select(first.id); document.querySelector(`tr[data-id="${first.id}"]`)?.scrollIntoView({ block: "nearest" }); }
});
$("#release-all").addEventListener("click", () => post("/api/release-all", {}).catch(() => {}));

export function holdHtml(s) {
  const phase = s.held, msg = S.current[phase];
  if (!heldSince.has(s.id)) heldSince.set(s.id, Date.now());
  const first = phase === "request"
    ? `<div class="row"><input id="hd-method" value="${esc(s.method)}" aria-label="Method" style="flex: 0 0 90px"><input id="hd-url" value="${esc(s.url)}" aria-label="URL"></div>`
    : `<div class="row"><input id="hd-status" value="${esc(s.status)}" aria-label="Status code" inputmode="numeric" style="flex: 0 0 90px"></div>`;
  return `<div class="hold-box" data-phase="${phase}" data-id="${s.id}">
    <p><b>${phase === "request" ? "Request held" : "Response held"}</b>, the program is waiting
      <span class="muted" id="hd-age"></span>. Edit it, then continue, or drop it.</p>
    ${first}
    <label for="hd-headers">Headers (one "Name: value" per line)</label>
    <textarea id="hd-headers" rows="6">${esc(headerLines(msg))}</textarea>
    <label for="hd-body">Body${msg.editable ? "" : " (binary or too large to edit here: it is sent unchanged)"}</label>
    <textarea id="hd-body" rows="6" ${msg.editable ? "" : "disabled"}>${esc(msg.editable ? msg.body : "")}</textarea>
    <div class="actions">
      <button type="button" class="primary" id="hd-go">Continue</button>
      <button type="button" id="hd-plain" title="Ignore the edits above">Continue unchanged</button>
      <span class="spacer"></span>
      <button type="button" class="danger" id="hd-drop" title="The program gets an error instead">Drop</button>
    </div></div>`;
}

export function wireHold(s) {
  const phase = s.held, editable = S.current[phase].editable;
  const tick = () => {
    const el = $("#hd-age");
    if (!el) return clearInterval(timer);
    el.textContent = `(${Math.round((Date.now() - heldSince.get(s.id)) / 1000)} s)`;
  };
  const timer = setInterval(tick, 1000);
  tick();
  const release = async (extra) => {
    try { await post("/api/release", { id: s.id, ...extra }); }
    catch (err) { S.applyError = err.message; }
    loadDetail();
  };
  $("#hd-go").addEventListener("click", () => {
    const edits = { headers: parseHeaders($("#hd-headers").value), body: editable ? $("#hd-body").value : null };
    if (phase === "request") Object.assign(edits, { method: $("#hd-method").value.trim(), url: $("#hd-url").value.trim() });
    else edits.status = Number($("#hd-status").value);
    release({ [phase]: edits });
  });
  $("#hd-plain").addEventListener("click", () => release({}));
  $("#hd-drop").addEventListener("click", () => release({ drop: true }));
}
