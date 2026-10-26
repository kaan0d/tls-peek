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
await page.waitForTimeout(500);  // late fetches (Raw tab) finish
await browser.close();
if (errors.length) throw new Error(`script errors:\n${errors.join("\n")}`);
console.log(`ui ok (${ids.length} rows, ${tabs} tabs)`);
