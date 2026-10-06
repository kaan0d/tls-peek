// Detail panel: request/response/messages tabs, body decoders, notes, copy as, edit and resend.
import { $, PHASES, S, api, esc, fmtMs, fmtSize, header, headerLines, kv, parseHeaders, post, prettyBody } from "./core.js";
import { holdHtml, wireHold } from "./intercept.js";
import { openRules } from "./rules.js";
import { render, showAllStatuses, visible } from "./list.js";

let tab = "request";

export function closeDetail() {
  S.selected = null;
  S.current = null;
  S.panel = null;
  $("#detail").innerHTML = "";
  render();
}

export function select(id) {
  S.selected = id;
  S.panel = null;
  if (tab === "messages") tab = "request";
  $("#detail").scrollTop = 0;
  render();
  loadDetail();
}

export async function loadDetail() {
  const id = S.selected;
  try {
    const d = await api("/api/flow/" + id);
    if (id !== S.selected) return;
    S.current = d;
    if (tab === "stream" && appendStream(d)) return;
  } catch (err) {
    S.current = null;
    $("#detail").innerHTML = `<div class="empty">${esc(err.message)}</div>`;
    return;
  }
  // Don't close the copy menu, interrupt typing a note or a click, or wipe edits to a held request.
  if (document.querySelector("details.copy[open], #detail:active") || document.activeElement?.id === "note") return;
  const box = document.querySelector(".hold-box");
  if (box && S.current.summary.state === "held" && box.dataset.phase === S.current.summary.held
      && box.dataset.id === String(S.current.summary.id)) return;
  const top = $("#detail").scrollTop;
  renderDetail();
  $("#detail").scrollTop = top;
}

// An open TCP/UDP stream changes every second; only its Messages tab needs the new data.
export function refreshDetail(summary) {
  const label = document.querySelector('#detail .tab[data-tab="stream"]');
  if (label && tab !== "stream" && S.current?.summary.id === summary.id) label.textContent = `Messages ${summary.msgs}`;
  else loadDetail();
}

// --- decoders and previews ---
let bodyView = "pretty";  // kept while moving between requests
const VIEWS = ["pretty", "base64", "auto", "json", "protobuf", "grpc", "msgpack", "xml/html", "url-encoded",
  "multipart form", "query", "javascript", "css", "hex dump", "raw"];
const JWT = /eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*/g;

function b64decode(text) {
  const clean = text.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  const bin = atob(clean + "=".repeat((4 - clean.length % 4) % 4));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

function jwtHtml(texts) {
  const tokens = [...new Set(texts.flatMap((t) => String(t).match(JWT) || []))];
  if (!tokens.length) return "";
  return `<h3>JWT tokens</h3>` + tokens.map((tok) => {
    try {
      const [h, p] = tok.split(".").slice(0, 2).map((part) => JSON.parse(b64decode(part)));
      const when = (k) => p[k] ? `${k}: ${new Date(p[k] * 1000).toLocaleString()}` : "";
      const expired = p.exp && p.exp * 1000 < Date.now();
      return `<details class="jwt"><summary>${esc(h.alg || "?")} · ${esc(p.sub || p.email || p.iss || "token")}
        ${expired ? `<span class="bad">· expired</span>` : ""} · ${esc(tok.slice(0, 24))}…</summary>
        <pre>${esc([when("iat"), when("exp")].filter(Boolean).join("\n"))}</pre>
        <pre>${esc(JSON.stringify(h, null, 2))}</pre><pre>${esc(JSON.stringify(p, null, 2))}</pre></details>`;
    } catch { return ""; }
  }).join("");
}

function messageHtml(msg, pending, part) {
  const s = S.current.summary;
  if (!msg) return `<div class="empty">${pending ? "Waiting for the response…" : "No response" + (s.error ? ": " + esc(s.error) : "") + "."}</div>`;
  const ctype = header(msg, "content-type");
  const src = `/api/body/${s.id}?part=${part}&seq=${S.seq}`;
  let preview = "";
  if (ctype.startsWith("image/")) preview = `<img class="preview" src="${src}" alt="Image preview">`;
  else if (ctype.includes("html")) preview = `<button type="button" class="html-preview" data-src="${src}" style="margin: 0 12px 8px">Preview page</button>`;
  const texts = [...msg.headers.map(([, v]) => v), msg.body, part === "request" ? s.url : ""];
  return `<h3>Headers</h3><div class="headers">${kv(msg.headers) || "<i>none</i>"}</div>${jwtHtml(texts)}
    <h3>Body ${msg.body ? `<select class="view-pick" data-part="${part}" aria-label="Decode body as">
      ${VIEWS.map((v) => `<option${v === bodyView ? " selected" : ""}>${v}</option>`).join("")}</select>` : ""}</h3>
    ${preview}${msg.body ? `<pre class="body-out" data-part="${part}"></pre>` : `<div class="headers"><i>empty</i></div>`}`;
}

async function fillBody(pre) {
  const part = pre.dataset.part, msg = S.current[part], id = S.current.summary.id;
  if (bodyView === "pretty") { pre.textContent = prettyBody(msg); return; }
  if (bodyView === "base64") {
    try { pre.textContent = b64decode(msg.body); } catch { pre.textContent = "Not valid Base64."; }
    return;
  }
  pre.textContent = "Decoding…";
  try {
    const r = await api(`/api/view/${id}?part=${part}&view=${encodeURIComponent(bodyView)}`);
    if (S.current?.summary.id === id) pre.textContent = (r.text || "(empty)") + (r.truncated ? "\n… (truncated)" : "");
  } catch (err) { pre.textContent = err.message; }
}

// --- connection, TLS and timing ---
const date = (t) => new Date(t * 1000).toLocaleDateString();

function connHtml(c) {
  const t = c.timing, srv = c.server;
  const phases = PHASES.map(([k, label]) => {
    const v = t[k] == null && (k === "connect" || k === "tls") && srv.reused ? "reused connection" : t[k] == null ? "–" : fmtMs(t[k]);
    return `<div><b><i class="sw ph-${k}"></i>${label}</b><span>${v}</span></div>`;
  }).join("");
  const side = (x) => kv([["Server", x.address], ["Peer", x.peer], ["Local", x.local], ["TLS", x.tls], ["Cipher", x.cipher],
    ["ALPN", x.alpn], ["ALPN offered", (x.alpn_offers || []).join(", ")], ["SNI", x.sni]].filter(([, v]) => v)) || "<i>none</i>";
  const certs = srv.certs.map((ce, i) => `<details class="jwt"${i ? "" : " open"}><summary>${i === 0 ? "Server" : ce.ca ? "CA" : "Intermediate"} · ${esc(ce.subject || ce.organization || "?")}
      ${ce.expired ? `<span class="bad">· expired</span>` : ""} · until ${date(ce.not_after)}</summary>
    <div class="headers">${kv([["Subject", ce.subject], ["Organization", ce.organization], ["Issuer", ce.issuer],
      ["Valid", `${date(ce.not_before)} to ${date(ce.not_after)}`], ["Names", ce.names.join(", ")], ["Key", ce.key],
      ["Serial", ce.serial], ["SHA-256", ce.sha256]].filter(([, v]) => v))}</div></details>`).join("");
  return `<h3>Timing</h3>${phaseBar(t, "phase-bar")}<div class="headers phases">${phases}</div>
    <h3>tls-peek → server <small>${esc(c.http)}</small></h3><div class="headers">${side(srv)}</div>
    <h3>Server certificates</h3>${certs || `<div class="headers"><i>none (plain HTTP or not connected)</i></div>`}
    <h3>Program → tls-peek</h3><div class="headers">${side(c.client)}</div>
    <p class="hint">The program talks TLS with tls-peek, which uses its own certificate; tls-peek talks TLS with the real server.</p>`;
}

export function phaseBar(t, cls) {
  return `<div class="${cls}">${PHASES.map(([k, label]) => t[k] ? `<span class="ph-${k}" style="flex-grow:${t[k]}" title="${label}: ${fmtMs(t[k])}"></span>` : "").join("")}</div>`;
}

// --- raw views: HTTP as on the wire, TCP/UDP streams, DNS ---
async function fillWire(id) {
  let w;
  try { w = await api(`/api/raw/${id}`); } catch (err) { if ($("#wire-out")) $("#wire-out").textContent = err.message; return; }
  const el = $("#wire-out");
  if (!el || S.current?.summary.id !== id) return;
  const part = (p, label) => !p ? "" : `<h3>${label} <small>${p.head_size} B headers · ${p.body_size} B body${p.encoding
    ? ` (${esc(p.encoding)}, ${p.decoded_size} B decoded)` : ""}</small></h3><pre>${esc(p.head)}${esc(p.body)}</pre>`;
  el.className = "";
  el.innerHTML = (/^HTTP\/[23]/.test(w.http) ? `<p class="hint">${esc(w.http)} sends binary frames with compressed headers; they are shown here in HTTP/1 text form.</p>` : "")
    + part(w.request, "Request") + part(w.response, "Response");
}

const msgHtml = (m, n) => `<div class="msg ${m.from_client ? "out" : "in"}" data-n="${n}"><div class="meta">${m.from_client ? "→ sent" : "← received"} · ${new Date(m.time * 1000).toLocaleTimeString()} · ${fmtSize(m.size)}</div>
    <pre>${esc(m.text ?? m.hex)}</pre>${m.text != null ? `<details class="hexd"><summary>Hex</summary><pre>${esc(m.hex)}</pre></details>` : ""}</div>`;
const streamHead = (d) => `${d.raw_messages.length} messages${d.dropped_messages ? ` (the ${d.dropped_messages} oldest are not shown)` : ""}`;

function streamHtml(d) {
  const msgs = d.raw_messages;
  if (!msgs.length) return `<div class="empty">No data yet.</div>`;
  return `<h3 id="stream-head">${streamHead(d)}</h3><div id="stream" data-id="${d.summary.id}">${msgs.map((m, i) => msgHtml(m, d.dropped_messages + i)).join("")}</div>`;
}

// A live stream only gains messages: add the new ones and drop the oldest instead of redrawing,
// so open hex dumps, selected text and the scroll position stay.
function appendStream(d) {
  const box = $("#stream");
  if (!box || box.dataset.id !== String(d.summary.id)) return false;
  for (const el of [...box.children]) if (+el.dataset.n < d.dropped_messages) el.remove();
  const shown = Math.max(d.dropped_messages, box.lastElementChild ? +box.lastElementChild.dataset.n + 1 : 0);
  box.insertAdjacentHTML("beforeend", d.raw_messages.slice(shown - d.dropped_messages).map((m, i) => msgHtml(m, shown + i)).join(""));
  $("#stream-head").textContent = streamHead(d);
  document.querySelector('#detail .tab[data-tab="stream"]').textContent = `Messages ${d.summary.msgs}`;
  return true;
}

function dnsHtml(d) {
  const q = d.query, r = d.response;
  const rows = (list) => list.length ? `<table class="stats"><thead><tr><th>Name</th><th>Type</th><th class="num">TTL</th><th>Data</th></tr></thead><tbody>
    ${list.map((a) => `<tr><td class="mono">${esc(a.name)}</td><td>${esc(a.type)}</td><td class="num">${a.ttl ?? ""}</td><td class="mono">${esc(typeof a.data === "object" && a.data ? JSON.stringify(a.data) : a.data ?? "")}</td></tr>`).join("")}</tbody></table>` : `<div class="headers"><i>none</i></div>`;
  const flags = (m) => ["authoritative_answer", "truncation", "recursion_desired", "recursion_available"].filter((k) => m[k]).map((k) => k.replace(/_/g, " ")).join(", ");
  return `<h3>Question</h3><div class="headers">${kv(q.questions.map((x) => [x.type, x.name]))}${kv([["ID", String(q.id)], ["Flags", flags(q) || "none"]])}</div>
    ${r ? `<h3>Answer <small>${esc(r.response_code)}</small></h3>${rows(r.answers)}
    ${r.authorities.length ? `<h3>Authority</h3>${rows(r.authorities)}` : ""}${r.additionals.length ? `<h3>Additional</h3>${rows(r.additionals)}` : ""}
    <div class="headers">${kv([["Flags", flags(r) || "none"]])}</div>` : `<div class="empty">No answer yet.</div>`}`;
}

function wsHtml(msgs) {
  if (!msgs.length) return `<div class="empty">No messages yet.</div>`;
  return `<h3>${msgs.length} messages</h3>` + msgs.map((m) => {
    let text = m.text;
    try { text = JSON.stringify(JSON.parse(text), null, 2); } catch {}
    return `<div class="msg ${m.from_client ? "out" : "in"}"><div class="meta">${m.from_client ? "→ sent" : "← received"} · ${new Date(m.time * 1000).toLocaleTimeString()}</div><pre>${esc(text)}</pre></div>`;
  }).join("");
}

function renderDetail() {
  const current = S.current, s = current.summary;
  let params = [];
  try { params = [...new URL(s.url).searchParams]; } catch {}
  const http = s.kind === "http";
  const tabs = http
    ? [["request", "Request"], ["response", "Response" + (s.status ? " " + s.status : "")],
       ...(current.websocket ? [["messages", `Messages ${current.websocket.length}`]] : []), ["wire", "Raw"], ["connection", "Connection"]]
    : [s.kind === "dns" ? ["dns", "DNS"] : ["stream", `Messages ${s.msgs}`], ["connection", "Connection"]];
  if (!tabs.some(([k]) => k === tab)) tab = tabs[0][0];
  const body = tab === "request"
    ? (params.length ? `<h3>Query</h3><div class="headers">${kv(params)}</div>` : "") + messageHtml(current.request, false, "request")
    : tab === "response" ? messageHtml(current.response, s.state === "pending", "response")
    : tab === "connection" ? connHtml(current.connection)
    : tab === "wire" ? `<div id="wire-out" class="empty">Loading…</div>`
    : tab === "stream" ? streamHtml(current)
    : tab === "dns" ? dnsHtml(current.dns)
    : wsHtml(current.websocket || []);
  $("#detail").innerHTML = `
    <div class="bar" role="tablist">
      ${tabs.map(([k, label]) => `<button class="tab" role="tab" aria-selected="${tab === k}" data-tab="${k}">${esc(label)}</button>`).join("")}
      <span class="spacer"></span>
      ${http ? `<button id="resend-btn" type="button" ${current.websocket ? "disabled title='WebSocket flows cannot be resent'" : ""}>Edit &amp; resend</button>
      ${S.file || current.websocket ? "" : `<button id="rule-btn" type="button" title="New rewrite rule for this URL and method">New rule…</button>`}
      <details class="copy"><summary>Copy ▾</summary><div class="menu">
        <button type="button" data-copy="url">URL</button>
        <button type="button" data-copy="curl">cURL</button>
        <button type="button" data-copy="ps">PowerShell</button>
        <button type="button" data-copy="py">Python requests</button>
      </div></details>` : ""}
      <button id="close-detail" type="button" title="Close (Esc)">Close</button>
    </div>
    <div class="url">${esc(s.method)} ${esc(s.url)}</div>${s.state === "held" ? holdHtml(s) : ""}
    <textarea id="note" rows="1" placeholder="Note (saved with the session)…" aria-label="Note"></textarea>${body}`;
  $("#note").value = s.note;
  let noteTimer;
  $("#note").addEventListener("input", (e) => {
    clearTimeout(noteTimer);
    noteTimer = setTimeout(() => post("/api/mark", { id: s.id, note: e.target.value }).catch(() => {}), 600);
  });
  $("#detail").querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
    tab = b.dataset.tab;
    if (tab === "stream") loadDetail(); else renderDetail();  // messages are not refreshed while another tab is shown
  }));
  $("#detail").querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => copy(b.dataset.copy, b)));
  $("#resend-btn")?.addEventListener("click", openResend);
  if (tab === "wire") fillWire(s.id);
  $("#rule-btn")?.addEventListener("click", () => openRules(current));
  if (s.state === "held") wireHold(s);
  $("#close-detail").addEventListener("click", closeDetail);
  $("#detail").querySelectorAll(".body-out").forEach(fillBody);
  $("#detail").querySelectorAll(".view-pick").forEach((sel) => sel.addEventListener("change", () => {
    bodyView = sel.value;
    fillBody(sel.closest("h3").parentElement.querySelector(`.body-out[data-part="${sel.dataset.part}"]`));
  }));
  $("#detail").querySelectorAll(".html-preview").forEach((b) => b.addEventListener("click", () => {
    // sandbox="" blocks scripts; the server's CSP also blocks every external load.
    b.outerHTML = `<iframe class="preview" sandbox="" src="${b.dataset.src}" title="Page preview"></iframe>`;
  }));
}

// --- copy as ---
const skipHeader = (k) => /^(content-length|host|connection|accept-encoding)$/i.test(k) || k.startsWith(":");
const sq = (v) => "'" + String(v).replace(/'/g, "'\\''") + "'";
const psq = (v) => "'" + String(v).replace(/'/g, "''") + "'";
const pyq = (v) => JSON.stringify(String(v));

const COPY = {
  url: (s) => s.url,
  curl: (s, r) => ["curl", "-X", s.method, sq(s.url),
    ...r.headers.filter(([k]) => !skipHeader(k)).flatMap(([k, v]) => ["-H", sq(`${k}: ${v}`)]),
    ...(r.body ? ["--data-raw", sq(r.body)] : [])].join(" "),
  ps: (s, r) => {
    const hs = r.headers.filter(([k]) => !skipHeader(k) && k.toLowerCase() !== "content-type");
    const ct = header(r, "content-type");
    return [`Invoke-WebRequest -UseBasicParsing -Method ${s.method} -Uri ${psq(s.url)}`,
      hs.length ? ` -Headers @{\n${hs.map(([k, v]) => `  ${psq(k)} = ${psq(v)}`).join("\n")}\n}` : "",
      ct ? ` -ContentType ${psq(ct)}` : "", r.body ? ` -Body ${psq(r.body)}` : ""].join("");
  },
  py: (s, r) => {
    const hs = r.headers.filter(([k]) => !skipHeader(k));
    return `import requests\n\nresponse = requests.request(\n    ${pyq(s.method)},\n    ${pyq(s.url)},\n` +
      (hs.length ? `    headers={\n${hs.map(([k, v]) => `        ${pyq(k)}: ${pyq(v)},`).join("\n")}\n    },\n` : "") +
      (r.body ? `    data=${pyq(r.body)},\n` : "") + `)\nprint(response.status_code, response.text)\n`;
  },
};

async function copy(kind, btn) {
  await navigator.clipboard.writeText(COPY[kind](S.current.summary, S.current.request));
  const old = btn.textContent; btn.textContent = "Copied";
  setTimeout(() => { btn.textContent = old; btn.closest("details")?.removeAttribute("open"); }, 900);
}

// --- edit and resend ---
function openResend() {
  const s = S.current.summary, r = S.current.request;
  $("#rs-method").value = s.method;
  $("#rs-url").value = s.url;
  $("#rs-headers").value = headerLines(r);
  $("#rs-body").value = r.body;
  $("#resend-error").textContent = "";
  $("#resend").showModal();
}
$("#rs-cancel").addEventListener("click", () => $("#resend").close());
$("#rs-send").addEventListener("click", async () => {
  try {
    const { id } = await post("/api/resend", { id: S.current.summary.id, method: $("#rs-method").value.trim(),
      url: $("#rs-url").value.trim(), headers: parseHeaders($("#rs-headers").value), body: $("#rs-body").value });
    $("#resend").close();
    showAllStatuses();
    select(id);
  } catch (err) { $("#resend-error").textContent = err.message; }
});

// Esc closes the panel; arrow keys move through the shown requests.
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && (S.selected != null || S.panel) && !document.querySelector("dialog[open]")) {
    closeDetail();
    return;
  }
  if (["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName) || S.selected == null || !["ArrowUp", "ArrowDown"].includes(e.key)) return;
  const list = visible(), i = list.findIndex((f) => f.id === S.selected);
  const next = list[i + (e.key === "ArrowDown" ? 1 : -1)];
  if (next) { e.preventDefault(); select(next.id); document.querySelector("tr.sel")?.scrollIntoView({ block: "nearest" }); }
});
