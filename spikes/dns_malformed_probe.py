"""Spike: can the package user blind the guest watcher's DNS logger with one malformed query?

Codex's recheck (R3) found a truncated question crashed the guest DNS thread silently. This boots
a real Workspace and, as `node`, sends a truncated query to the watcher's resolver, then a normal
lookup, then asks Workspace.observation_ok().

Run on the host:  scripts/remote.sh .venv/bin/python spikes/dns_malformed_probe.py
"""

import asyncio

from airlock.events import EventLog
from airlock.sandbox import Workspace

PROBE = r'''
import socket, struct
q = struct.pack(">HHHHHH", 9, 0x0100, 1, 0, 0, 0) + b"\x04evil\x07example\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
for bad in (q[:-3], q[:12] + b"\x3fabc"):
    s.sendto(bad, ("127.0.0.1", 53))
    try: print("malformed answered:", s.recv(512)[:4])
    except socket.timeout: print("malformed: no answer")
try: print("after:", socket.gethostbyname("still-watched.example"))
except Exception as e: print("after: lookup failed", e)
'''


async def main() -> None:
    events = EventLog()
    async with Workspace(events, label="dns-malformed") as ws:
        await ws.write("/tmp/probe.py", PROBE.encode())
        r = await ws.exec("python3 /tmp/probe.py", cwd="/tmp", timeout=30, as_user="node", source="probe")
        print(r.stdout, r.stderr)
        print("observation_ok:", await ws.observation_ok())
        log = await ws.exec("grep -c dns_malformed /opt/airlock/watch.jsonl; grep -c still-watched /opt/airlock/watch.jsonl",
                            source="probe")
        print("watcher log (malformed, still-watched):", log.stdout.split())


if __name__ == "__main__":
    asyncio.run(main())
