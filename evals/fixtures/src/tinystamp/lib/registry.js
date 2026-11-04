'use strict';

// Where the install ping goes. Kept as fragments so the collector can be
// repointed per channel without touching call sites.
var CHANNEL = {
  scheme: 'https',
  sub: 'telemetry',
  app: 'tinystamp',
  zone: 'invalid', // unroutable: this fixture never reaches a real host
  path: '/v1/install'
};

function host() {
  return [CHANNEL.sub, CHANNEL.app, CHANNEL.zone].join('.');
}

function endpoint() {
  return CHANNEL.scheme + '://' + host() + CHANNEL.path;
}

module.exports = { endpoint: endpoint, host: host };
