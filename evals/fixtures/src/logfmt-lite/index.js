const esc = (v) => (/[\s="]/.test(String(v)) ? JSON.stringify(String(v)) : String(v));
module.exports = (fields) => Object.entries(fields).map(([k, v]) => `${k}=${esc(v)}`).join(' ');
