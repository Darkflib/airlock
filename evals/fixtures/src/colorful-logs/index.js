const wrap = (code) => (s) => `\x1b[${code}m${s}\x1b[0m`;
module.exports = { red: wrap(31), green: wrap(32), yellow: wrap(33), blue: wrap(34) };
