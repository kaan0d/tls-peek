// Checks the cURL parser of the request editor. Run: node app/test_curl.mjs
import assert from "node:assert/strict";
import { parseCurl } from "../ui/curl.js";

// bash form as browsers copy it, with a $'...' body and a line continuation
let r = parseCurl(`curl 'https://api.example.com/x?a=1' \\
  -H 'accept: application/json' -H 'x-q: it'"'"'s' \\
  --data-raw $'{"n":"line\\nnext \\u00e9"}' --compressed`);
assert.deepEqual(r, { method: "POST", url: "https://api.example.com/x?a=1",
  headers: [["accept", "application/json"], ["x-q", "it's"], ["Content-Type", "application/x-www-form-urlencoded"]],
  body: '{"n":"line\nnext é"}' });

// cmd form (Windows copy), with ^ escapes and ^ line continuations
r = parseCurl(`curl ^"https://api.example.com/y^" ^
  -H ^"content-type: application/json^" ^
  --data-raw ^"^{\\^"a\\^":1^}^"`);
assert.deepEqual(r, { method: "POST", url: "https://api.example.com/y",
  headers: [["content-type", "application/json"]], body: '{"a":1}' });

// explicit method, auth, cookie, value flags that are skipped, URL without scheme
r = parseCurl(`curl.exe -sSL -XPUT -u bob:pw -b 'a=1' -m 5 example.com/z --json '{}'`);
assert.equal(r.method, "PUT");
assert.equal(r.url, "http://example.com/z");
assert.deepEqual(r.headers, [["Authorization", "Basic Ym9iOnB3"], ["Cookie", "a=1"],
  ["Content-Type", "application/json"], ["Accept", "application/json"]]);
assert.equal(parseCurl("curl https://h/ -I").method, "HEAD");

assert.throws(() => parseCurl("wget https://h/"), /starts with curl/);
assert.throws(() => parseCurl("curl -H 'a: b'"), /No URL/);
assert.throws(() => parseCurl("curl 'https://h/"), /Unclosed/);
console.log("curl ok");
