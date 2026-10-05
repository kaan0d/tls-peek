// Rewrite rules: change matching traffic automatically (set a header, find and replace, answer with a fixed response).
import { $, S, esc, post } from "./core.js";
import { showState } from "./main.js";

let rules = [];   // as saved on the server
let draft = [];   // being edited in the dialog
const METHODS = ["", "GET", "POST", "PUT", "PATCH", "DELETE"];
const blank = () => ({ enabled: true, action: "header", phase: "request", method: "", url: "", name: "", value: "",
  find: "", replace: "", status: 200, type: "application/json", body: "" });

export function showRules(s) {
  rules = s.rules || [];
  const on = rules.filter((r) => r.enabled).length;
  $("#rules-btn").textContent = on ? `Rules: ${on}` : "Rules";
  $("#rules-btn").setAttribute("aria-pressed", on > 0);
}

const opt = (value, label, current) => `<option value="${esc(value)}" ${value === current ? "selected" : ""}>${esc(label)}</option>`;

function fields(r) {
  if (r.action === "header") return `<div class="row">
      <input data-k="name" value="${esc(r.name)}" placeholder="Header name, e.g. User-Agent" aria-label="Header name">
      <input data-k="value" value="${esc(r.value)}" placeholder="Value (empty = remove the header)" aria-label="Header value"></div>`;
  if (r.action === "replace") return `<div class="row">
      <input data-k="find" value="${esc(r.find)}" placeholder="Find (exact text)" aria-label="Find">
      <input data-k="replace" value="${esc(r.replace)}" placeholder="Replace with" aria-label="Replace with"></div>
    <small>${r.phase === "request" ? "Replaced in the URL and the body." : "Replaced in the body."} Binary bodies are left alone.</small>`;
  return `<div class="row">
      <input data-k="status" value="${esc(r.status)}" inputmode="numeric" aria-label="Status code" style="flex: 0 0 70px">
      <input data-k="type" value="${esc(r.type)}" placeholder="Content-Type" aria-label="Content-Type"></div>
    <textarea data-k="body" rows="4" placeholder="Response body" aria-label="Response body">${esc(r.body)}</textarea>
    <small>The server is not contacted; the program gets this answer.</small>`;
}

function render() {
  $("#rule-list").innerHTML = draft.map((r, i) => `<div class="rule${r.enabled ? "" : " off"}" data-i="${i}">
    <div class="row">
      <input type="checkbox" data-k="enabled" ${r.enabled ? "checked" : ""} aria-label="Rule on" title="Rule on">
      <select data-k="action" aria-label="Action">${opt("header", "Set header", r.action)}${opt("replace", "Find and replace", r.action)}${opt("respond", "Answer with a fixed response", r.action)}</select>
      ${r.action === "respond" ? "" : `<select data-k="phase" aria-label="Apply to">${opt("request", "on requests", r.phase)}${opt("response", "on responses", r.phase)}</select>`}
      <span class="spacer"></span>
      <button type="button" class="del" aria-label="Delete rule" title="Delete rule">×</button>
    </div>
    <div class="row">
      <select data-k="method" aria-label="Method">${METHODS.map((m) => opt(m, m || "Any method", r.method)).join("")}</select>
      <input data-k="url" value="${esc(r.url)}" placeholder="URL contains (empty = every request)" aria-label="URL contains">
    </div>
    ${fields(r)}</div>`).join("") || `<p class="empty">No rules yet. Add one to change traffic without holding it.</p>`;
}

function readDom() {
  document.querySelectorAll("#rule-list .rule").forEach((el) => {
    const r = draft[el.dataset.i];
    el.querySelectorAll("[data-k]").forEach((f) => { r[f.dataset.k] = f.type === "checkbox" ? f.checked : f.value; });
  });
}

// Opens the dialog; with a request, adds a new rule for it at the end.
export function openRules(from) {
  draft = rules.map((r) => ({ ...r }));
  if (from) draft.push(ruleFor(from));
  $("#rules-error").textContent = "";
  render();
  $("#rules-dlg").showModal();
  if (from) $("#rule-list .rule:last-child")?.scrollIntoView({ block: "nearest" });
}
$("#rules-btn").addEventListener("click", () => openRules());

// A rule matching this request's host and path; its fixed response starts as the captured one.
function ruleFor({ summary: s, response }) {
  const u = new URL(s.url), r = blank();
  r.url = u.host + u.pathname;
  r.method = METHODS.includes(s.method) ? s.method : "";
  if (response && s.status) {
    r.status = s.status;
    r.type = (response.headers.find(([k]) => k.toLowerCase() === "content-type") || [])[1] || r.type;
    r.body = response.editable ? response.body : "";
  }
  return r;
}
$("#rule-list").addEventListener("change", (e) => {
  if (["action", "phase", "enabled"].includes(e.target.dataset.k)) { readDom(); render(); }
});
$("#rule-list").addEventListener("click", (e) => {
  const del = e.target.closest(".del");
  if (!del) return;
  readDom();
  draft.splice(del.closest(".rule").dataset.i, 1);
  render();
});
$("#rule-add").addEventListener("click", () => {
  readDom();
  draft.push(blank());
  render();
  $("#rule-list .rule:last-child [data-k=name]")?.focus();
});
$("#rules-cancel").addEventListener("click", () => $("#rules-dlg").close());
$("#rules-save").addEventListener("click", async () => {
  readDom();
  try {
    showState(await post("/api/rules", { rules: draft }));
    S.applyError = "";
    $("#rules-dlg").close();
  } catch (err) { $("#rules-error").textContent = err.message; }
});
