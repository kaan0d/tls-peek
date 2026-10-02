// Export dialog: HAR or Postman, for all, shown or picked requests.
import { $, S } from "./core.js";
import { picked, visible } from "./list.js";

$("#export").addEventListener("click", () => {
  const counts = { all: S.flows.size, shown: visible().length, selected: picked.size };
  document.querySelectorAll("input[name=ex-scope]").forEach((r) => {
    r.disabled = counts[r.value] === 0;
    r.closest("label").querySelector("small").textContent = `(${counts[r.value]})`;
  });
  const scope = document.querySelector(`input[name=ex-scope][value=${picked.size ? "selected" : "shown"}]`);
  if (!scope.disabled) scope.checked = true;
  $("#ex-error").textContent = "";
  $("#export-dlg").showModal();
});
$("#ex-cancel").addEventListener("click", () => $("#export-dlg").close());
$("#ex-go").addEventListener("click", async () => {
  const scope = document.querySelector("input[name=ex-scope]:checked").value;
  const ids = scope === "all" ? null : scope === "selected" ? [...picked] : visible().map((f) => f.id);
  const format = document.querySelector("input[name=ex-format]:checked").value;
  const r = await fetch("/api/export", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ format, ids, mask: $("#ex-mask").checked }) });
  if (!r.ok) { $("#ex-error").textContent = "Export failed."; return; }
  const name = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "")?.[1] || "tlspeek-export.json";
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(await r.blob()), download: name });
  a.click();
  URL.revokeObjectURL(a.href);
  $("#export-dlg").close();
});
