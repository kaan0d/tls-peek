// Opens the UI of a running session in a real browser, clicks every row and every tab of its detail,
// and fails on any script error. Usage: node app/test_ui.mjs PORT
import { chromium } from "playwright-core";

const browser = await chromium.launch({ channel: "chrome" });
const page = await browser.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
page.on("console", (m) => m.type() === "error" && errors.push(m.text()));

await page.goto(`http://127.0.0.1:${process.argv[2]}/`);
await page.waitForSelector("tr[data-id]");
if (await page.isVisible("dialog#picker[open]")) await page.keyboard.press("Escape");  // a live capture asks for a program
const ids = await page.$$eval("tr[data-id]", (rows) => rows.map((r) => r.dataset.id));
if (ids.length < 10) throw new Error(`only ${ids.length} rows listed`);

let tabs = 0;
for (const id of ids) {
  const loaded = page.waitForResponse((r) => r.url().endsWith(`/api/flow/${id}`));  // tabs depend on the flow kind
  await page.click(`tr[data-id="${id}"]`);
  await loaded;
  await page.waitForSelector("#detail .tab");
  for (const key of await page.$$eval("#detail .tab", (t) => t.map((b) => b.dataset.tab))) {
    await page.click(`#detail .tab[data-tab="${key}"]`);
    await page.waitForSelector(`#detail .tab[data-tab="${key}"][aria-selected="true"]`);
    tabs++;
  }
}
await page.keyboard.press("Escape");  // keyboard only: focus a row, Enter opens it, the arrow keys move on
await page.focus(`tr[data-id="${ids[0]}"]`);
await page.keyboard.press("Enter");
await page.waitForSelector(`tr.sel[data-id="${ids[0]}"]`);
await page.keyboard.press("ArrowDown");
await page.waitForFunction((id) => document.querySelector("tr.sel")?.dataset.id !== id, ids[0]);
for (const panel of ["stats", "api", "findings"]) {  // the three panels render over the same session
  await page.click(`#${panel}-btn`);
  await page.waitForTimeout(400);
}
await page.waitForSelector(".finding");
const before = await page.$$eval(".finding.dismissed", (x) => x.length);
await page.click(".finding .dismiss");  // dismiss moves a finding to the greyed-out list, restore brings it back
await page.waitForFunction((n) => document.querySelectorAll(".finding.dismissed").length === n + 1, before);
await page.click(".finding.dismissed .dismiss");
await page.waitForFunction((n) => document.querySelectorAll(".finding.dismissed").length === n, before);
await page.waitForSelector("#findings-badge:not([hidden])");  // the button says there is something before the panel is opened
await page.click(`.finding .f-ids button[data-id]`);  // from a finding to its request: the request lists the finding as a chip
await page.waitForSelector("#detail .fchip");
await page.click("#findings-btn");
await page.click(".tile[data-sev=high]");  // a severity tile filters the list
await page.waitForFunction(() => [...document.querySelectorAll(".finding:not(.dismissed) .sev")].every((e) => e.textContent === "high"));
await page.click(".tile[data-sev=high]");
await page.click("#stats-btn");  // the host table scrolls inside its box instead of running off the panel
await page.waitForSelector(".scroll-x");
await page.waitForSelector("h3:has-text('Who received data')");
if (await page.$eval("#detail", (d) => d.scrollWidth > d.clientWidth + 1)) throw new Error("stats panel overflows sideways");
await page.click("#export");  // the export says what it masked
await page.click("#ex-go");
await page.waitForSelector('.toast:has-text("masked")');
await page.keyboard.press("Escape");  // the command palette: Ctrl K, type, Enter runs the first match
await page.keyboard.press("Control+k");
await page.waitForSelector("dialog#palette[open]");
await page.keyboard.type("theme");
await page.keyboard.press("Enter");
await page.waitForFunction(() => ["light", "dark"].includes(document.documentElement.dataset.theme));
await page.keyboard.press("Control+k");
await page.keyboard.type("api map");
await page.keyboard.press("Enter");
await page.waitForSelector("#ep-host");
if (!(await page.$eval("#ribbon", (c) => c.width > 0))) throw new Error("the ribbon was not drawn");
await page.waitForTimeout(500);  // late fetches (Raw tab) finish
await browser.close();
if (errors.length) throw new Error(`script errors:\n${errors.join("\n")}`);
console.log(`ui ok (${ids.length} rows, ${tabs} tabs)`);
