// In-guest tracer, preloaded with NODE_OPTIONS=--require=/opt/airlock/trace.js.
// Logs file reads under $HOME dotfiles, outbound HTTP(S)/fetch requests and
// child processes to /tmp/airlock-trace.jsonl. Prototype of Airlock's
// containment-event source for Node lifecycle scripts.
'use strict';
const fs = require('fs');
const os = require('os');

const LOG = '/tmp/airlock-trace.jsonl';
const argv = process.argv.slice(1).join(' ');
const append = fs.appendFileSync.bind(fs);
const home = os.homedir();

function log(ev) {
  try {
    append(LOG, JSON.stringify({ ts: Date.now(), pid: process.pid, argv, ...ev }) + '\n');
  } catch (_) {}
}

function watched(p) {
  try {
    const s = String(p instanceof URL ? p.pathname : p);
    if (s.includes('.npmrc') || s.includes('.aws') || s.startsWith(home + '/.')) return s;
  } catch (_) {}
  return null;
}

for (const name of ['readFileSync', 'readFile', 'openSync', 'open', 'createReadStream']) {
  const orig = fs[name];
  if (typeof orig !== 'function') continue;
  fs[name] = function (p, ...rest) {
    const s = watched(p);
    if (s) log({ ev: 'file_read', fn: name, path: s });
    return orig.call(this, p, ...rest);
  };
}
for (const name of ['readFile', 'open']) {
  const orig = fs.promises[name];
  fs.promises[name] = function (p, ...rest) {
    const s = watched(p);
    if (s) log({ ev: 'file_read', fn: 'promises.' + name, path: s });
    return orig.call(this, p, ...rest);
  };
}

function hostOf(target) {
  try {
    if (typeof target === 'string' || target instanceof URL) return new URL(String(target)).host;
    if (target && typeof target === 'object') return target.hostname || target.host || '?';
  } catch (_) {}
  return '?';
}

for (const modName of ['http', 'https']) {
  const mod = require(modName);
  for (const fn of ['request', 'get']) {
    const orig = mod[fn];
    mod[fn] = function (...args) {
      log({ ev: 'net_request', mod: modName, host: hostOf(args[0]) });
      return orig.apply(this, args);
    };
  }
}

if (typeof globalThis.fetch === 'function') {
  const orig = globalThis.fetch;
  globalThis.fetch = function (input, ...rest) {
    log({ ev: 'net_request', mod: 'fetch', host: hostOf(typeof input === 'string' ? input : input && input.url) });
    return orig.call(this, input, ...rest);
  };
}

const cp = require('child_process');
for (const fn of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']) {
  const orig = cp[fn];
  cp[fn] = function (...args) {
    log({ ev: 'exec', fn, cmd: String(args[0]).slice(0, 200) });
    return orig.apply(this, args);
  };
}
