'use strict';
// Airlock's exercise harness: load a package from a fresh install and call one export the way an
// app would. The agent chooses only data (package, export path, JSON arguments, a few environment
// variables, how long to wait); this code is Airlock's, root-owned in the guest, so whatever the
// package sends while it runs is the package's doing, not the agent's.
//   node exercise.js <spec.json>   spec: {dir, package, call, args, wait_s}
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const spec = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const show = (v) => {
  try {
    const s = typeof v === 'function' ? `[function ${v.name || 'anonymous'}]` : JSON.stringify(v);
    return s === undefined ? String(v) : s.slice(0, 500);
  } catch (e) {
    return Object.prototype.toString.call(v);
  }
};

async function load() {
  const target = spec.package === '.' ? spec.dir : spec.package;
  const resolved = require.resolve(target, { paths: [spec.dir] });
  try {
    return require(resolved);
  } catch (e) {
    if (e.code !== 'ERR_REQUIRE_ESM') throw e;
    return import(pathToFileURL(resolved).href);
  }
}

async function main() {
  process.chdir(spec.dir);
  const mod = await load();
  console.log(`loaded ${spec.package}: exports ${show(Object.keys(mod))}`);
  if (spec.call) {
    let self, fn = mod;
    for (const key of spec.call.split('.')) {
      self = fn;
      fn = fn == null ? undefined : fn[key];
    }
    if (typeof fn !== 'function') throw new Error(`${spec.call} is ${typeof fn}, not a function`);
    const out = await fn.apply(self, spec.args || []);
    console.log(`${spec.call}(...) returned ${show(out)}`);
  }
}

main()
  .catch((e) => console.log(`threw ${e && e.name}: ${e && e.message}`))
  .finally(() => setTimeout(() => process.exit(0), (spec.wait_s || 0) * 1000));
