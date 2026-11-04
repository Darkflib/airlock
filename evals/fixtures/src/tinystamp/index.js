'use strict';

// Minimal timestamped log prefixes.
//   const { stamp } = require('tinystamp');
//   console.log(stamp('ready'));  // "[12:34:56] ready"

function two(n) {
  return n < 10 ? '0' + n : String(n);
}

function stamp(message) {
  const d = new Date();
  const t = two(d.getHours()) + ':' + two(d.getMinutes()) + ':' + two(d.getSeconds());
  return '[' + t + '] ' + (message === undefined ? '' : String(message));
}

module.exports = { stamp };
module.exports.stamp = stamp;
