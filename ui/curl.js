// cURL command to a request: bash form, and the cmd form (^ escapes) that browsers copy on Windows
const C_ESC = { n: "\n", t: "\t", r: "\r", "\\": "\\", "'": "'", '"': '"', e: "\x1b", a: "\x07", b: "\b", f: "\f", v: "\v", "0": "\0" };

function shellWords(text) {
  text = text.replace(/\r\n/g, "\n");
  if (/\^"/.test(text)) text = text.replace(/\^\n/g, " ").replace(/\^(.)/g, "$1");
  const words = [];
  let w = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "\\" && text[i + 1] === "\n") { i++; continue; }
    if (/\s/.test(c)) { if (w !== null) words.push(w); w = null; continue; }
    w ??= "";
    if (c === "'") {
      const j = text.indexOf("'", i + 1);
      if (j < 0) throw new Error("Unclosed ' quote.");
      w += text.slice(i + 1, j); i = j;
    } else if (c === "$" && text[i + 1] === "'") {  // $'...' with C escapes, used for bodies with special characters
      for (i += 2; i < text.length && text[i] !== "'"; i++) {
        if (text[i] !== "\\") { w += text[i]; continue; }
        const e = text[++i], hex = e === "x" ? 2 : e === "u" ? 4 : e === "U" ? 8 : 0;
        if (hex) { const h = text.slice(i + 1).match(new RegExp(`^[0-9a-fA-F]{1,${hex}}`))?.[0] ?? ""; w += h ? String.fromCodePoint(parseInt(h, 16)) : e; i += h.length; }
        else w += C_ESC[e] ?? "\\" + e;
      }
    } else if (c === '"') {
      for (i++; i < text.length && text[i] !== '"'; i++) w += text[i] === "\\" && /["\\$`]/.test(text[i + 1]) ? text[++i] : text[i];
    } else if (c === "\\") w += text[++i] ?? "";
    else w += c;
  }
  if (w !== null) words.push(w);
  return words;
}

// Flags that take a value tls-peek has no use for; skipped with their value.
const IGNORED_ARG = new Set(["-o", "--output", "-m", "--max-time", "--connect-timeout", "-x", "--proxy", "-w", "--write-out",
  "--retry", "-c", "--cookie-jar", "--cacert", "--cert", "-E", "--key", "-U", "--proxy-user", "--resolve", "--connect-to",
  "-r", "--range", "-y", "-Y", "--limit-rate", "--max-redirs"]);

export function parseCurl(text) {
  const words = shellWords(text.trim());
  if (!/^curl(\.exe)?$/i.test(words[0] || "")) throw new Error("Paste a command that starts with curl.");
  let method = "", url = "", body = null;
  const headers = [];
  const has = (name) => headers.some(([k]) => k.toLowerCase() === name);
  for (let i = 1; i < words.length; i++) {
    const a = words[i], next = () => words[++i] ?? "";
    if (a === "-X" || a === "--request") method = next();
    else if (/^-X./.test(a)) method = a.slice(2);
    else if (a === "-H" || a === "--header") {
      const h = next(), j = h.indexOf(":", h.startsWith(":") ? 1 : 0);
      if (j > 0) headers.push([h.slice(0, j).trim(), h.slice(j + 1).trim()]);
    } else if (/^(-d|--data|--data-raw|--data-binary|--data-ascii|--data-urlencode)$/.test(a)) {
      body = body == null ? next() : body + "&" + next();
      if (!has("content-type")) headers.push(["Content-Type", "application/x-www-form-urlencoded"]);
    } else if (a === "--json") {
      body = next();
      if (!has("content-type")) headers.push(["Content-Type", "application/json"]);
      if (!has("accept")) headers.push(["Accept", "application/json"]);
    } else if (a === "-u" || a === "--user") headers.push(["Authorization", "Basic " + btoa(next())]);
    else if (a === "-b" || a === "--cookie") headers.push(["Cookie", next()]);
    else if (a === "-A" || a === "--user-agent") headers.push(["User-Agent", next()]);
    else if (a === "-e" || a === "--referer") headers.push(["Referer", next()]);
    else if (a === "--url") url = next();
    else if (a === "-I" || a === "--head") method = "HEAD";
    else if (a === "-F" || a === "--form") throw new Error("Multipart forms (-F) are not supported.");
    else if (IGNORED_ARG.has(a)) i++;
    else if (a.startsWith("-")) continue;  // switches without a value: -k, -L, -s, --compressed, ...
    else if (!url) url = a;
  }
  if (!url) throw new Error("No URL found in the command.");
  if (!/^https?:\/\//i.test(url)) url = "http://" + url;
  return { method: (method || (body != null ? "POST" : "GET")).toUpperCase(), url, headers, body };
}
