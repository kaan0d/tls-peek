// Request editor (edit and resend, new request, paste cURL) and the saved requests menu.
import { $, api, esc, parseHeaders, post } from "./core.js";
import { parseCurl } from "./curl.js";
import { select } from "./detail.js";
import { showAllStatuses } from "./list.js";

let editing = { id: null, saved: null, keepBody: false };  // source flow, index in the saved list

// Opens the editor. id: the captured flow it copies (null for a new request); saved: index of a saved request.
export function openEditor({ id = null, saved = null, method = "GET", url = "", headers = "", body = "", keepBody = false, name = "" } = {}) {
  editing = { id, saved, keepBody };
  $("#rs-title").textContent = id != null ? "Edit and resend" : saved != null ? "Saved request" : "New request";
  $("#rs-method").value = method;
  $("#rs-url").value = url;
  $("#rs-headers").value = headers;
  $("#rs-body").value = keepBody ? "" : body;
  $("#rs-body").disabled = keepBody;
  $("#rs-body").placeholder = keepBody ? "Binary or very large body: sent unchanged" : "";
  $("#rs-save").checked = saved != null;
  $("#rs-name").value = name;
  $("#rs-curl").value = "";
  $("#rs-curl-box").open = id == null && saved == null;
  showSave();
  $("#resend-error").textContent = "";
  $("#resend").showModal();
}

function showSave() {
  $("#rs-name").hidden = $("#rs-save-only").hidden = !$("#rs-save").checked;
}

const fields = () => ({ method: $("#rs-method").value.trim().toUpperCase(), url: $("#rs-url").value.trim(),
  headers: parseHeaders($("#rs-headers").value), body: $("#rs-body").value });

async function save() {
  const items = await api("/api/saved");
  const item = { name: $("#rs-name").value.trim(), ...fields() };
  if (editing.saved != null && editing.saved < items.length) items[editing.saved] = item;
  else editing.saved = items.push(item) - 1;
  await post("/api/saved", { items });
}

export async function send(req) {
  const { id } = await post("/api/resend", req);
  showAllStatuses();
  select(id);
}

$("#rs-save").addEventListener("change", showSave);
$("#rs-cancel").addEventListener("click", () => $("#resend").close());
$("#rs-save-only").addEventListener("click", async () => {
  try { await save(); $("#resend").close(); if ($("#saved-dlg").open) showSaved(); }
  catch (err) { $("#resend-error").textContent = err.message; }
});
$("#rs-send").addEventListener("click", async () => {
  try {
    const f = fields();
    if (!f.method || !f.url) throw new Error("Method and URL are needed.");
    if ($("#rs-save").checked) {
      if (editing.keepBody) throw new Error("A binary body cannot be saved; untick Save.");
      await save();
    }
    await send({ id: editing.id, ...f, body: editing.keepBody ? null : f.body });
    $("#resend").close();
    $("#saved-dlg").close();
  } catch (err) { $("#resend-error").textContent = err.message; }
});
$("#rs-curl-go").addEventListener("click", () => {
  try {
    const c = parseCurl($("#rs-curl").value);
    openEditor({ ...editing, method: c.method, url: c.url, headers: c.headers.map(([k, v]) => `${k}: ${v}`).join("\n"),
      body: c.body ?? "", keepBody: false, name: $("#rs-name").value });
    $("#rs-save").checked = editing.saved != null || $("#rs-save").checked;
    $("#rs-curl-box").open = false;
  } catch (err) { $("#resend-error").textContent = err.message; }
});

// --- saved requests menu ---
async function showSaved() {
  let items;
  try { items = await api("/api/saved"); } catch (err) { $("#saved-list").innerHTML = `<div class="empty">${esc(err.message)}</div>`; return; }
  $("#saved-list").innerHTML = items.map((r, i) => `<div class="item" data-i="${i}">
      <span title="${esc(r.method)} ${esc(r.url)}">${r.name ? `<b>${esc(r.name)}</b>` : ""}${esc(r.method)} ${esc(r.url)}</span>
      <button type="button" data-act="send" class="primary">Send</button>
      <button type="button" data-act="edit">Edit</button>
      <button type="button" data-act="delete">Delete</button></div>`).join("")
    || `<div class="empty">Nothing saved yet. Tick "Save to captures" when you send a request.</div>`;
}

$("#compose-btn").addEventListener("click", () => { $("#saved-dlg").showModal(); showSaved(); });
$("#saved-close").addEventListener("click", () => $("#saved-dlg").close());
$("#saved-new").addEventListener("click", () => openEditor());
$("#saved-list").addEventListener("click", async (e) => {
  const b = e.target.closest("button[data-act]");
  if (!b) return;
  const i = +b.closest(".item").dataset.i;
  try {
    const items = await api("/api/saved"), r = items[i];
    if (!r) return showSaved();
    if (b.dataset.act === "send") {
      await send({ method: r.method, url: r.url, headers: r.headers, body: r.body });
      $("#saved-dlg").close();
    } else if (b.dataset.act === "edit") {
      openEditor({ saved: i, name: r.name, method: r.method, url: r.url, body: r.body, headers: r.headers.map(([k, v]) => `${k}: ${v}`).join("\n") });
    } else {
      items.splice(i, 1);
      await post("/api/saved", { items });
      showSaved();
    }
  } catch (err) { b.textContent = "Failed"; b.title = err.message; }
});
