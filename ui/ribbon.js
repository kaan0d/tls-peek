// The ribbon: requests over the last minute (or the whole session when a file is open) as a row of bars,
// mint for normal traffic and red where something failed. A glance tells whether the program is talking.
import { $, S } from "./core.js";

const canvas = $("#ribbon"), N = 40;
const ctx = canvas.getContext("2d");
const color = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

function draw() {
  if (!canvas.offsetParent) return;
  const dpr = devicePixelRatio || 1, w = canvas.clientWidth, h = canvas.clientHeight;
  if (canvas.width !== Math.round(w * dpr)) { canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr); }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const rows = [...S.flows.values()];
  const times = rows.map((f) => f.time);
  const t1 = S.file ? Math.max(...times, 0) : Date.now() / 1000;
  const t0 = S.file ? Math.min(...times, t1) : t1 - 60;
  const span = Math.max(t1 - t0, S.file ? 30 : 1), count = new Array(N).fill(0), bad = new Array(N).fill(false);
  for (const f of rows) {
    const i = Math.floor(((f.time - t0) / span) * N);
    if (i < 0 || i >= N) continue;
    count[Math.min(i, N - 1)]++;
    if (f.state === "error" || f.status >= 400) bad[Math.min(i, N - 1)] = true;
  }
  const max = Math.max(...count, 1), gap = 2, bw = (w - 8 - gap * (N - 1)) / N, base = h - 5;
  count.forEach((n, i) => {
    const x = 4 + i * (bw + gap), bh = n ? 3 + (base - 6) * Math.sqrt(n / max) : 2;
    ctx.fillStyle = n ? color(bad[i] ? "--bad" : "--accent") : color("--muted");
    ctx.globalAlpha = n ? (i > N - 4 && !S.file ? 1 : .8) : .28;
    ctx.shadowColor = n && i > N - 4 && !S.file ? ctx.fillStyle : "transparent";
    ctx.shadowBlur = 8;
    ctx.beginPath();
    ctx.roundRect(x, base - bh + 1, Math.max(bw, 1.5), bh, 1.5);
    ctx.fill();
  });
  ctx.globalAlpha = 1;
  canvas.title = rows.length ? `${rows.length} requests ${S.file ? "in this session" : "in the last minute: " + count.reduce((a, b) => a + b, 0)}` : "No traffic yet";
}
setInterval(draw, 1000);
addEventListener("resize", draw);
setTimeout(draw, 300);
