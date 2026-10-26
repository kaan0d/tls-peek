// Command palette (Ctrl K): jump to a panel, run a toolbar action, filter to a host, or open a request, from the keyboard.
import { $, S, store } from "./core.js";
import { select } from "./detail.js";

const dlg = $("#palette"), input = $("#palette-input"), list = $("#palette-list");
let items = [], shown = [], at = 0;

const click = (sel) => () => $(sel).click();
const chip = (text) => () => [...document.querySelectorAll("#status-chips button")].find((b) => b.textContent.trim() === text)?.click();

function theme() {
  const now = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  const next = now === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  store.set("theme", next);
}

function build() {
  const base = [
    ["Go", "Findings", "security checks", click("#findings-btn")], ["Go", "Stats", "counts, timing, who received data", click("#stats-btn")],
    ["Go", "API map", "endpoints and OpenAPI", click("#api-btn")], ["Go", "Export…", "HAR or Postman", click("#export")],
    ["Go", "Requests…", "write or paste a request", click("#compose-btn")],
    ["Do", "Clear the list", "", click("#clear")], ["Do", "Focus search", "/", () => $("#search").focus()],
    ["Do", "Show only errors", "", chip("Error")], ["Do", "Show only 5xx", "", chip("5xx")], ["Do", "Show all statuses", "", chip("All")],
    ["Do", "Switch light or dark theme", "", theme],
  ];
  if (!S.file) base.push(["Do", "Pause or resume the capture", "", click("#pause")], ["Do", "Intercept…", "hold requests", click("#icpt-btn")],
    ["Do", "Rewrite rules…", "", click("#rules-btn")], ["Do", "Pick the program…", "", click("#program-btn")]);
  const hosts = [...new Set([...S.flows.values()].map((f) => f.host))].sort();
  return [...base, ...hosts.map((h) => ["Host", `Only ${h}`, "", () => { $("#host-pick").value = h; $("#host-pick").dispatchEvent(new Event("change")); }])];
}

function paint() {
  const words = input.value.toLowerCase().split(/\s+/).filter(Boolean);
  const hit = (s) => words.every((w) => s.toLowerCase().includes(w));
  shown = items.filter(([k, label, hint]) => hit(`${k} ${label} ${hint}`));
  if (input.value.trim().length >= 2) {
    const rows = [...S.flows.values()].filter((f) => hit(`${f.method} ${f.status ?? ""} ${f.url}`)).slice(-8).reverse();
    shown = [...shown, ...rows.map((f) => ["Request", `${f.method} ${f.url.replace(/^\w+:\/\//, "")}`, f.status ?? "", () => select(f.id)])];
  }
  at = Math.min(at, Math.max(shown.length - 1, 0));
  list.innerHTML = shown.length ? shown.map(([k, label, hint], i) => `<li role="option" data-i="${i}" aria-selected="${i === at}"><span class="kind">${k}</span>
    <span class="label"></span><span class="hint2"></span></li>`).join("") : `<li class="none">Nothing matches.</li>`;
  list.querySelectorAll("li[data-i]").forEach((li) => {  // text goes in as text: URLs and host names are data, not markup
    const [, label, hint] = shown[li.dataset.i];
    li.querySelector(".label").textContent = label;
    li.querySelector(".hint2").textContent = hint;
  });
  list.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
}

function open() {
  if (dlg.open) return;
  items = build();
  input.value = ""; at = 0;
  paint();
  dlg.showModal();
  input.focus();
}
function run(i) {
  const pick = shown[i];
  if (!pick) return;
  dlg.close();
  pick[3]();
}

input.addEventListener("input", () => { at = 0; paint(); });
input.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    at = (at + (e.key === "ArrowDown" ? 1 : -1) + shown.length) % Math.max(shown.length, 1);
    paint();
  } else if (e.key === "Enter") { e.preventDefault(); run(at); }
});
list.addEventListener("click", (e) => { const li = e.target.closest("li[data-i]"); if (li) run(Number(li.dataset.i)); });
$("#palette-btn").addEventListener("click", open);
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); open(); }
  else if (e.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName) && !document.querySelector("dialog[open]")) { e.preventDefault(); $("#search").focus(); }
});
