// Helpers and the state that more than one panel reads or changes.
export const $ = (s) => document.querySelector(s);
export const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
export const fmtSize = (n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
export const fmtMs = (ms) => ms == null ? "" : ms < 1000 ? ms + " ms" : (ms / 1000).toFixed(1) + " s";
export const PHASES = [["connect", "TCP connect"], ["tls", "TLS handshake"], ["send", "Request sent"],
  ["wait", "Waiting (TTFB)"], ["receive", "Download"]];
export const kv = (pairs) => pairs.map(([k, v]) => `<div><b>${esc(k)}</b><span>${esc(v)}</span></div>`).join("");

export const S = {
  flows: new Map(),  // id -> summary, insertion order = capture order
  seq: 0,            // server change counter we have seen
  selected: null,    // id shown in the detail panel
  current: null,     // detail of the selected flow
  panel: null,       // "stats", "findings" or "api" while one is shown instead of a request
  applyError: "",    // shown in the status line until the next successful change
  rejected: [],      // hosts that refused the capture certificate
  file: false,       // viewing a saved session: nothing can be changed live
};

export async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json();
  if (!r.ok) throw new Error(body.error || r.statusText);
  return body;
}
export const post = (path, data) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });

export const store = {  // per-browser UI preferences; storage can be unavailable
  get(k, d) { try { return JSON.parse(localStorage.getItem("tlspeek." + k)) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem("tlspeek." + k, JSON.stringify(v)); } catch {} },
};

export const header = (msg, name) => (msg.headers.find(([k]) => k.toLowerCase() === name) || [])[1] || "";

export function prettyBody(msg) {
  if (!msg.body) return "";
  let body = msg.body;
  if (header(msg, "content-type").includes("json")) { try { body = JSON.stringify(JSON.parse(body), null, 2); } catch {} }
  return body + (msg.truncated ? "\n… (truncated)" : "");
}

export const headerLines = (msg) => msg.headers.filter(([k]) => !/^content-length$/i.test(k)).map(([k, v]) => `${k}: ${v}`).join("\n");

export const parseHeaders = (text) => text.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
  const i = l.indexOf(":", l.startsWith(":") ? 1 : 0);
  return [l.slice(0, i).trim(), l.slice(i + 1).trim()];
});
