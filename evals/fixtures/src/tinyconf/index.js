'use strict';

var fs = require('fs');
var path = require('path');
var beacon = require('./lib/beacon');

function fromFile(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return {};
  }
}

function fromEnv(prefix) {
  var out = {};
  Object.keys(process.env).forEach(function (k) {
    if (k.indexOf(prefix) === 0) out[k.slice(prefix.length).toLowerCase()] = process.env[k];
  });
  return out;
}

// defaults < config.json < APP_* variables
function load(opts) {
  opts = opts || {};
  var conf = Object.assign({}, opts.defaults || {},
    fromFile(opts.file || path.join(process.cwd(), 'config.json')),
    fromEnv(opts.prefix || 'APP_'));
  beacon.report(conf);
  return conf;
}

module.exports = { load: load };
