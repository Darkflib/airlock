"""Spike: can the package user bypass Airlock's fake DNS by querying the sandbox gateway directly?

Codex's review flagged that Rule.allow_dns() allows port 53 to the gateway. If the gateway
recursively resolves arbitrary names, a package can exfiltrate data in DNS labels without the
sinkhole ever seeing it. This boots a real Workspace (same policy as product runs) and, as the
unprivileged `node` user, sends raw DNS queries to the original resolver and to a public one.

Run on the host:  scripts/remote.sh .venv/bin/python spikes/dns_gateway_probe.py
"""

import asyncio
import secrets

from airlock.events import EventLog
from airlock.sandbox import Workspace

PROBE = r'''
import random, socket, struct, sys
def query(server, name, tcp=False):
    q = struct.pack(">HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    try:
        if tcp:
            s = socket.create_connection((server, 53), timeout=4)
            s.sendall(struct.pack(">H", len(q)) + q)
            r = s.recv(4096)[2:]
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
            s.sendto(q, (server, 53)); r = s.recv(4096)
        rcode, ancount = r[3] & 0xF, struct.unpack(">H", r[6:8])[0]
        return f"answered rcode={rcode} ({'NXDOMAIN' if rcode == 3 else 'NOERROR' if rcode == 0 else rcode}) answers={ancount}"
    except Exception as e:
        return f"no answer: {type(e).__name__}: {e}"
gw = next(l.split()[1] for l in open("/etc/resolv.conf.airlock-orig") if l.startswith("nameserver"))
print("gateway resolver:", gw)
for name in ("registry.npmjs.org", "example.com", sys.argv[1]):
    print(f"udp {gw} {name}: {query(gw, name)}")
print(f"tcp {gw} example.com: {query(gw, 'example.com', tcp=True)}")
print(f"udp 1.1.1.1 example.com: {query('1.1.1.1', 'example.com')}")
'''


async def main() -> None:
    events = EventLog()
    # A label nobody has ever looked up: an NXDOMAIN for it means the query left the VM and
    # reached a real recursive resolver, i.e. DNS labels are an exfiltration channel.
    unique = f"airlock-probe-{secrets.token_hex(6)}.example.com"
    async with Workspace(events, label="dns-probe") as ws:
        await ws.write("/tmp/probe.py", PROBE.encode())
        r = await ws.exec(f"python3 /tmp/probe.py {unique}", cwd="/tmp", timeout=60, as_user="node", source="probe")
        print(r.stdout, r.stderr)
    print("containment events:", [f"{e.kind}: {e.summary}" for e in events.events if e.containment])


if __name__ == "__main__":
    asyncio.run(main())
