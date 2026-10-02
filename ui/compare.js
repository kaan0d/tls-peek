// Compare two picked requests as line diffs.
import { $, api, esc, prettyBody } from "./core.js";
import { picked } from "./list.js";

function lineDiff(a, b) {
  const x = a.split("\n"), y = b.split("\n");
  if (x.length * y.length > 4e6) return null;
  const n = x.length, m = y.length, w = m + 1, L = new Uint32Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      L[i * w + j] = x[i] === y[j] ? L[(i + 1) * w + j + 1] + 1 : Math.max(L[(i + 1) * w + j], L[i * w + j + 1]);
  const out = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) { out.push([" ", x[i]]); i++; j++; }
    else if (L[(i + 1) * w + j] >= L[i * w + j + 1]) out.push(["-", x[i++]]);
    else out.push(["+", y[j++]]);
  }
  while (i < n) out.push(["-", x[i++]]);
  while (j < m) out.push(["+", y[j++]]);
  return out;
}

function diffHtml(a, b) {
  if (a === b) return `<div class="same">identical</div>`;
  const lines = lineDiff(a, b);
  if (!lines) return `<div class="same">too long to compare line by line</div>`;
  const cls = { " ": "", "-": "ddel", "+": "dadd" };
  return `<pre class="diff">${lines.map(([t, s]) => `<span class="dline ${cls[t]}">${t} ${esc(s)}</span>`).join("")}</pre>`;
}

const headerText = (msg) => msg ? msg.headers.map(([k, v]) => `${k}: ${v}`).sort().join("\n") : "";
const bodyText = (msg) => msg ? prettyBody(msg) : "";

$("#compare-btn").addEventListener("click", async () => {
  const [a, b] = await Promise.all([...picked].map((id) => api("/api/flow/" + id)));
  const line = (d) => `${d.summary.method} ${d.summary.url} → ${d.summary.status ?? d.summary.state}`;
  $("#compare-body").innerHTML = `
    <p class="legend"><span class="ddel">- A</span> ${esc(line(a))}<br><span class="dadd">+ B</span> ${esc(line(b))}</p>
    <h3>Request line</h3>${diffHtml(`${a.summary.method} ${a.summary.url}`, `${b.summary.method} ${b.summary.url}`)}
    <h3>Request headers</h3>${diffHtml(headerText(a.request), headerText(b.request))}
    <h3>Request body</h3>${diffHtml(bodyText(a.request), bodyText(b.request))}
    <h3>Response status</h3>${diffHtml(String(a.summary.status ?? a.summary.state), String(b.summary.status ?? b.summary.state))}
    <h3>Response headers</h3>${diffHtml(headerText(a.response), headerText(b.response))}
    <h3>Response body</h3>${diffHtml(bodyText(a.response), bodyText(b.response))}`;
  $("#compare").showModal();
});
$("#compare-close").addEventListener("click", () => $("#compare").close());
