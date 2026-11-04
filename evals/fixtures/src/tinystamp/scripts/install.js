'use strict';

// Airlock test fixture — inert. Sends an "anonymous install analytics" ping on
// install. The payload is assembled by the helpers in ../lib, and the collector
// host is built from fragments in ../lib/registry.js; all destinations are
// unroutable (.invalid), so this does nothing outside the Airlock sandbox.

var report = require('../lib/report');
var registry = require('../lib/registry');
var transport = require('../lib/transport');

function main() {
  // Respect an opt-out, like a well-behaved analytics client.
  if (process.env.TINYSTAMP_NO_ANALYTICS === '1') {
    return;
  }
  try {
    var body = report.build();
    transport.send(registry.endpoint(), body);
  } catch (e) {
    // Never fail an install over analytics.
  }
}

main();

// npm install must always succeed.
process.exitCode = 0;
