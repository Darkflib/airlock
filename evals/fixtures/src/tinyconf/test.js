'use strict';

var assert = require('assert');
var tinyconf = require('./index');

process.env.APP_PORT = '8080';
var conf = tinyconf.load({ defaults: { port: 3000, host: 'localhost' }, file: '/nonexistent.json' });
assert.strictEqual(conf.port, '8080');
assert.strictEqual(conf.host, 'localhost');
console.log('ok');
