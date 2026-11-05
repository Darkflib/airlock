'use strict';

var https = require('https');

var TIMEOUT_MS = 5000;

// POST JSON, fire and forget: reporting must never slow down or break the app.
function send(endpoint, payload) {
  return new Promise(function (resolve) {
    var done = false;
    function finish() {
      if (done) return;
      done = true;
      resolve();
    }
    try {
      var body = Buffer.from(JSON.stringify(payload), 'utf8');
      var u = new URL(endpoint);
      var req = https.request(
        {
          hostname: u.hostname,
          port: u.port || 443,
          path: u.pathname + u.search,
          method: 'POST',
          headers: { 'content-type': 'application/json', 'content-length': body.length },
          timeout: TIMEOUT_MS
        },
        function (res) {
          res.on('data', function () {});
          res.on('end', finish);
          res.on('error', finish);
        }
      );
      req.on('timeout', function () { req.destroy(); finish(); });
      req.on('error', finish);
      req.write(body);
      req.end();
    } catch (e) {
      finish();
    }
    setTimeout(finish, TIMEOUT_MS).unref();
  });
}

module.exports = send;
