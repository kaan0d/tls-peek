// Request list: filters, search, columns (sort, resize, auto-hide), selection, timeline.
import { $, PHASES, S, api, esc, fmtMs, fmtSize, post, store } from "./core.js";
import { phaseBar, select } from "./detail.js";
import { renderApiMap } from "./apimap.js";
import { renderFindings } from "./findings.js";
import { renderStats } from "./stats.js";

let clearedBefore = 0;  // ids below this are hidden by "Clear"
let bodyHits = null;    // Set of ids matching a body search, or null
export const filter = { status: "all", type: "all", host: "", marked: false };
export const picked = new Set();  // ids ticked for compare / export
let lastPicked = null;

// --- filters ---
// Arrays, not objects: object keys like "2" would sort before "all".
const STATUS = [["all", "All"], ["2", "2xx"], ["3", "3xx"], ["4", "4xx"], ["5", "5xx"], ["pending", "Pending"], ["held", "Held"], ["error", "Error"]];
export const TYPES = [["all", "All"], ["json", "JSON"], ["html", "HTML"], ["js", "JS"], ["css", "CSS"], ["image", "Image"], ["ws", "WS"], ["raw", "TCP/UDP/DNS"], ["other", "Other"]];

export function typeOf(f) {
  if (f.kind !== "http") return "raw";
  if (f.ws != null) return "ws";
  const t = f.type;
  if (t.includes("json")) return "json";
  if (t.includes("html")) return "html";
  if (t.includes("javascript")) return "js";
  if (t.includes("css")) return "css";
  if (t.startsWith("image/")) return "image";
  return "other";
}

function chips(el, options, key) {
  el.innerHTML = options.map(([v, label]) =>
    `<button type="button" data-v="${v}" aria-pressed="${filter[key] === v}">${label}</button>`).join("");
  el.onclick = (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    filter[key] = b.dataset.v;
    chips(el, options, key);
    render();
  };
}
chips($("#status-chips"), STATUS, "status");
chips($("#type-chips"), TYPES, "type");
export function showAllStatuses() {
  filter.status = "all";
  chips($("#status-chips"), STATUS, "status");
}
$("#host-pick").addEventListener("change", (e) => { filter.host = e.target.value; render(); });
$("#marked-only").addEventListener("click", (e) => {
  filter.marked = !filter.marked;
  e.currentTarget.setAttribute("aria-pressed", filter.marked);
  render();
});

function matches(f) {
  if (f.id < clearedBefore) return false;
  if (filter.marked && !f.marked) return false;
  if (filter.host && f.host !== filter.host) return false;
  if (filter.type !== "all" && typeOf(f) !== filter.type) return false;
  if (filter.status === "pending" && f.state !== "pending") return false;
  if (filter.status === "error" && f.state !== "error") return false;
  if (filter.status === "held" && f.state !== "held") return false;
  if (/^\d$/.test(filter.status) && String(f.status)[0] !== filter.status) return false;
  const q = $("#search").value.trim().toLowerCase();
  if (!q) return true;
  if (bodyHits) return bodyHits.has(f.id);
  return `${f.method} ${f.status ?? ""} ${f.url} ${f.type}`.toLowerCase().includes(q);
}

let searchTimer;
async function runSearch() {
  const q = $("#search").value.trim();
  bodyHits = null;
  if (q && $("#in-bodies").checked) {
    try { bodyHits = new Set(await api("/api/search?q=" + encodeURIComponent(q))); } catch {}
  }
  render();
}
$("#search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(runSearch, 250); });
$("#in-bodies").addEventListener("change", runSearch);

// --- columns ---
const pathOf = (f) => f.info ?? (f.url.replace(/^\w+:\/\/[^/]+/, "") || "/");
const COLUMNS = [
  { key: "pick", label: "", width: 30 },
  { key: "star", label: "", width: 28 },
  { key: "method", label: "Method", width: 70, sort: (f) => f.method },
  { key: "status", label: "Status", width: 76, sort: (f) => f.state === "error" ? 1000 : f.status ?? 0 },
  { key: "host", label: "Host", width: 160, sort: (f) => f.host },
  { key: "path", label: "Path", width: null, sort: pathOf },
  { key: "type", label: "Type", width: 120, sort: (f) => f.type },
  { key: "size", label: "Size", width: 76, sort: (f) => f.size, num: true },
  { key: "ms", label: "Time", width: 72, sort: (f) => f.ms ?? -1, num: true },
  { key: "timeline", label: "Timeline", width: 150, sort: (f) => f.time },
];
const widths = store.get("widths", {});
delete widths.path;  // Path always takes the remaining width
const PATH_MIN = 140;  // Path never gets narrower than this; columns hide first
const DROP_ORDER = ["timeline", "type", "size", "ms"];  // hidden in this order when space runs out
let hiddenCols = new Set();
const shownCols = () => COLUMNS.filter((c) => !hiddenCols.has(c.key));
let sortBy = store.get("sort", null);  // { key, dir: 1 | -1 } or null = capture order

function fitColumns() {
  const room = $("#list").clientWidth;
  const fixed = (c) => widths[c.key] ?? c.width ?? 0;
  const next = new Set();
  let need = COLUMNS.reduce((n, c) => n + fixed(c), 0) + PATH_MIN;
  for (const key of DROP_ORDER) {
    if (need <= room) break;
    next.add(key);
    need -= fixed(COLUMNS.find((c) => c.key === key));
  }
  if ([...next].join() !== [...hiddenCols].join()) {
    hiddenCols = next;
    renderHead();
    render();
  }
}
new ResizeObserver(fitColumns).observe($("#list"));

function renderHead() {
  $("#cols").innerHTML = shownCols().map((c) => {
    const w = widths[c.key] ?? c.width;
    return `<col${w ? ` style="width:${w}px"` : ""}>`;
  }).join("");
  $("#head").innerHTML = shownCols().map((c) => {
    if (c.key === "pick") return `<th class="c-pick"><input type="checkbox" id="pick-all" aria-label="Select all shown"></th>`;
    if (!c.sort) return `<th aria-label="Bookmark"></th>`;
    const dir = sortBy?.key === c.key ? sortBy.dir : 0;
    return `<th data-key="${c.key}" aria-sort="${dir === 1 ? "ascending" : dir === -1 ? "descending" : "none"}" class="${c.num ? "num" : ""}">
      <button type="button" class="sort">${c.label}<span aria-hidden="true">${dir === 1 ? " ▲" : dir === -1 ? " ▼" : ""}</span></button>
      ${c.width ? `<span class="grip" data-key="${c.key}" aria-hidden="true"></span>` : ""}</th>`;
  }).join("");
}

$("#head").addEventListener("click", (e) => {
  if (e.target.id === "pick-all") {
    const list = visible();
    if (e.target.checked) list.forEach((f) => picked.add(f.id)); else picked.clear();
    render();
    return;
  }
  const th = e.target.closest(".sort")?.closest("th");
  if (!th) return;
  const key = th.dataset.key;
  // asc -> desc -> capture order
  sortBy = sortBy?.key !== key ? { key, dir: 1 } : sortBy.dir === 1 ? { key, dir: -1 } : null;
  store.set("sort", sortBy);
  renderHead();
  render();
});

$("#head").addEventListener("pointerdown", (e) => {
  const grip = e.target.closest(".grip");
  if (!grip) return;
  e.preventDefault();
  const key = grip.dataset.key, th = grip.closest("th"), startX = e.clientX, startW = th.offsetWidth;
  const col = $("#cols").children[shownCols().findIndex((c) => c.key === key)];
  const move = (ev) => { widths[key] = Math.max(40, startW + ev.clientX - startX); col.style.width = widths[key] + "px"; };
  const up = () => { removeEventListener("pointermove", move); removeEventListener("pointerup", up); store.set("widths", widths); fitColumns(); };
  addEventListener("pointermove", move);
  addEventListener("pointerup", up);
});

export function visible() {
  const list = [...S.flows.values()].filter(matches);
  if (sortBy) {
    const c = COLUMNS.find((c) => c.key === sortBy.key);
    list.sort((a, b) => {
      const x = c.sort(a), y = c.sort(b);
      return (typeof x === "number" ? x - y : String(x).localeCompare(String(y))) * sortBy.dir;
    });
  }
  return list;
}

// --- rows ---
function statusCell(f) {
  if (f.state === "held") return `<span class="held" title="Held: the program is waiting">⏸ ${f.held === "response" ? f.status : "held"}</span>`;
  if (f.state === "error") return `<span class="err" title="${esc(f.error)}">ERR</span>`;
  if (f.kind !== "http") return `<span class="${f.label === "NOERROR" || f.label === "closed" ? "muted" : f.label === "open" ? "s2" : "err"}">${esc(f.label ?? "···")}</span>`;
  if (f.state === "pending") return `<span class="pending" title="Waiting for response">···</span>`;
  return `<span class="s${String(f.status)[0]}">${f.status}</span>`;
}

function timelineCell(f, t0, span) {
  const end = f.ms != null ? f.time + f.ms / 1000 : Date.now() / 1000;
  const left = ((f.time - t0) / span) * 100, width = Math.max(((end - f.time) / span) * 100, 0.6);
  const tip = `starts +${(f.time - t0).toFixed(2)} s, ${f.ms != null ? fmtMs(f.ms) : "still waiting"}`
    + (f.phases ? PHASES.filter(([k]) => f.phases[k]).map(([k, label]) => `
${label}: ${fmtMs(f.phases[k])}`).join("") : "");
  return `<div class="bar-track" title="${esc(tip)}"><div class="tl-bar ${f.state}" style="left:${left}%;width:${Math.min(width, 100 - left)}%">${f.phases ? phaseBar(f.phases, "tl-phases") : ""}</div></div>`;
}

export function render() {
  $("main").classList.toggle("has-detail", S.selected != null || S.panel);
  const hosts = [...new Set([...S.flows.values()].map((f) => f.host))].sort();
  const pick = $("#host-pick");
  if (pick.options.length - 1 !== hosts.length) {
    pick.innerHTML = `<option value="">All hosts</option>` + hosts.map((h) => `<option${h === filter.host ? " selected" : ""}>${esc(h)}</option>`).join("");
  }
  const list = visible();
  $("#empty").style.display = list.length ? "none" : "block";
  $("#empty").innerHTML = S.flows.size ? "No request matches the filters." : "No requests yet.<br>Pick a program, then close and reopen it and do the action.";
  const box = $("#list");
  const atBottom = !sortBy && box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  // Timeline scale: from the first shown request's start to the last one's end.
  let t0 = Infinity, tEnd = -Infinity;
  for (const f of list) {
    t0 = Math.min(t0, f.time);
    tEnd = Math.max(tEnd, f.ms != null ? f.time + f.ms / 1000 : Date.now() / 1000);
  }
  const span = Math.max(tEnd - t0, 0.001);
  const cells = {
    pick: (f) => `<td class="c-pick"><input type="checkbox" class="pick" ${picked.has(f.id) ? "checked" : ""} aria-label="Select request"></td>`,
    star: (f) => `<td class="c-star"><button type="button" class="star" aria-pressed="${f.marked}" aria-label="Bookmark">${f.marked ? "★" : "☆"}</button></td>`,
    method: (f) => `<td class="c-method">${esc(f.method)}</td>`,
    status: (f) => `<td class="c-status">${statusCell(f)}</td>`,
    host: (f) => `<td title="${esc(f.host)}">${esc(f.host)}</td>`,
    path: (f) => {
      const tags = (f.replay ? `<span class="tag">resent</span>` : "") + (f.ws != null ? `<span class="tag">WS ${f.ws}</span>` : "")
        + (f.note ? `<span class="tag" title="${esc(f.note)}">note</span>` : "")
        + (f.edited.length ? `<span class="tag" title="Edited while held: ${f.edited.join(", ")}">edited</span>` : "")
        + (f.rules ? `<span class="tag" title="Changed by ${f.rules === 1 ? "a rewrite rule" : f.rules + " rewrite rules"}">rule</span>` : "");
      return `<td title="${esc(f.url)}">${tags}${esc(pathOf(f))}</td>`;
    },
    type: (f) => `<td class="muted">${esc(f.type)}</td>`,
    size: (f) => `<td class="num muted">${f.state === "done" ? fmtSize(f.size) : ""}</td>`,
    ms: (f) => `<td class="num muted">${fmtMs(f.ms)}</td>`,
    timeline: (f) => `<td>${timelineCell(f, t0, span)}</td>`,
  };
  const cols = shownCols();
  $("#rows").innerHTML = list.map((f) =>
    `<tr data-id="${f.id}" class="${f.id === S.selected ? "sel" : ""}${picked.has(f.id) ? " picked" : ""}${f.state === "held" ? " is-held" : ""}">${cols.map((c) => cells[c.key](f)).join("")}</tr>`
  ).join("");
  if (atBottom) box.scrollTop = box.scrollHeight;
  if ($("#pick-all")) $("#pick-all").checked = list.length > 0 && list.every((f) => picked.has(f.id));
  $("#selection").hidden = picked.size === 0;
  $("#sel-count").textContent = `${picked.size} selected`;
  $("#compare-btn").disabled = picked.size !== 2;
  if (S.panel === "stats") renderStats();
  if (S.panel === "findings") renderFindings();
  if (S.panel === "api") renderApiMap();
}

$("#rows").addEventListener("click", (e) => {
  const tr = e.target.closest("tr");
  if (!tr) return;
  const id = Number(tr.dataset.id);
  const star = e.target.closest(".star");
  if (star) {
    post("/api/mark", { id, marked: star.getAttribute("aria-pressed") !== "true" }).catch(() => {});
    return;
  }
  if (e.target.classList.contains("pick") || e.ctrlKey || e.metaKey || e.shiftKey) {
    if (e.shiftKey && lastPicked != null) {  // range, in the order shown
      const ids = visible().map((f) => f.id);
      const [a, b] = [ids.indexOf(lastPicked), ids.indexOf(id)].sort((x, y) => x - y);
      ids.slice(a, b + 1).forEach((x) => picked.add(x));
    } else if (picked.has(id)) picked.delete(id); else picked.add(id);
    lastPicked = id;
    render();
    return;
  }
  select(id);
});
$("#sel-clear").addEventListener("click", () => { picked.clear(); render(); });
$("#clear").addEventListener("click", () => { clearedBefore = Math.max(0, ...S.flows.keys()) + 1; picked.clear(); render(); });
renderHead();
